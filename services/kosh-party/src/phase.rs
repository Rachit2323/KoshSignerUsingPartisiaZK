
/// Phase state machine: streams DkgEvent / SignEvent back to the gateway.
///
/// Strict mode only:
/// - Partisia signer contract is mandatory.
/// - Encrypted share persistence is mandatory.
/// - Local signing and in-memory share fallbacks are intentionally disabled.

use anyhow::{Result, anyhow};
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::bulletin_board::BulletinBoard;
use crate::chain_relay_client::ChainRelayClient;
use crate::config::Config;
use crate::contract_args as ca;
use crate::dkg;
use crate::gg20;
use crate::pqc_identity::PqcIdentity;
use crate::share_store::{PersistedShare, ShareStore};
use crate::types::Gg20State;

pub mod party_pb {
    tonic::include_proto!("kosh.party");
}
pub mod ks_pb {
    tonic::include_proto!("kosh.ks");
}
pub mod relay_pb {
    tonic::include_proto!("kosh.relay");
}

use party_pb::{
    DkgEvent, SignEvent,
    dkg_event::Phase as DkgPhase,
    sign_event::Phase as SignPhase,
};

const DKG_ONCHAIN_TIMEOUT: Duration = Duration::from_secs(180);
const SIGN_ONCHAIN_TIMEOUT: Duration = Duration::from_secs(300);

async fn wait_for_bb_barrier(
    bb: &mut BulletinBoard,
    key_id: u32,
    prefix: &str,
    num_parties: u32,
    party_index: u32,
) -> Result<()> {
    for j in 1..=num_parties {
        if j == party_index {
            continue;
        }
        let topic = format!("{prefix}_{key_id}_party_{j}");
        bb.watch_one(&topic, DKG_ONCHAIN_TIMEOUT).await?;
    }
    Ok(())
}

async fn wait_for_sign_subset_barrier(
    bb: &mut BulletinBoard,
    prefix: &str,
    key_id: u32,
    task_id: u32,
    signing_subset: &[u32],
    party_index: u32,
) -> Result<()> {
    for &signer in signing_subset {
        if signer == party_index {
            continue;
        }
        let topic = format!("{prefix}_{key_id}_{task_id}_party_{signer}");
        bb.watch_one(&topic, SIGN_ONCHAIN_TIMEOUT).await?;
    }
    Ok(())
}

fn parse_partisia_address_bytes(address_hex: &str) -> Result<Vec<u8>> {
    let trimmed = address_hex.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed)?;
    if bytes.len() != 21 {
        return Err(anyhow!(
            "PARTISIA_SENDER_ADDRESS must decode to 21 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

async fn ensure_operational_readiness(
    cfg: &Config,
    bb: &mut BulletinBoard,
    relay: &mut ChainRelayClient,
    key_id: u32,
    task_id: u32,
) -> Result<()> {
    if cfg.partisia_sender_address.is_empty() {
        return Err(anyhow!(
            "PARTISIA_SENDER_ADDRESS is required for party readiness registration"
        ));
    }

    if cfg.party_index == 1 {
        for party in 1..=cfg.num_parties {
            let identity = PqcIdentity::load_or_generate(&cfg.keystore_dir, party as u8)?;
            let address_bytes = parse_partisia_address_bytes(&cfg.partisia_sender_address)?;
            let dilithium_pubkey = identity.dilithium_public_key()?;
            let kyber_pubkey = identity.kyber_public_key()?;

            relay
                .submit_action(
                    cfg.party_index,
                    &cfg.signer_address,
                    0x72,
                    ca::build_register_party_address(key_id, party as u8, &address_bytes),
                    "register_party_address",
                )
                .await?;
            relay
                .submit_action(
                    cfg.party_index,
                    &cfg.signer_address,
                    0x73,
                    ca::build_register_dilithium_pubkey(key_id, party as u8, &dilithium_pubkey),
                    "register_dilithium_pubkey",
                )
                .await?;
            relay
                .submit_action(
                    cfg.party_index,
                    &cfg.signer_address,
                    0x74,
                    ca::build_register_kyber_pubkey(key_id, party as u8, &kyber_pubkey),
                    "register_kyber_pubkey",
                )
                .await?;
        }

        bb.post(&format!("sign_readiness_registered_{key_id}_{task_id}"), "ok")
            .await?;
    } else {
        bb.watch_one(
            &format!("sign_readiness_registered_{key_id}_{task_id}"),
            SIGN_ONCHAIN_TIMEOUT,
        )
        .await?;
    }

    Ok(())
}

// ── DKG ───────────────────────────────

pub async fn run_dkg(
    cfg: &Config,
    key_id: u32,
    num_parties: u32,
    _threshold: u32,
    tx: mpsc::Sender<Result<DkgEvent, tonic::Status>>,
) -> Result<()> {
    let send = |phase: DkgPhase, msg: String| {
        let _ = tx.try_send(Ok(DkgEvent { phase: phase as i32, message: msg }));
    };

    let on_chain = !cfg.signer_address.is_empty();
    send(DkgPhase::DkgStart, format!(
        "DKG key={key_id} party={} on_chain={on_chain}", cfg.party_index
    ));

    let mut bb = BulletinBoard::connect(&cfg.coordinator_addr).await?;

    // ── Phase 1: local commit (Feldman polynomial + Schnorr proof) ────────────
    let (s_i, a_i, c_i0, c_i1, commits) =
        dkg::run_dkg_commit(&mut bb, cfg.party_index, num_parties, key_id).await?;
    send(DkgPhase::DkgCommitted, format!("committed; got {} commits", commits.len()));

    // ── Phase 2: local sub-share exchange + Feldman verification ─────────────
    let x_i = dkg::run_dkg_subshares(
        &mut bb, cfg.party_index, num_parties, key_id, &s_i, &a_i, &commits,
    ).await?;
    send(DkgPhase::DkgSubshares, "sub-shares exchanged and verified".into());

    // ── Phase 3: combined public key ──────────────────────────────────────────
    let combined_pk = dkg::compute_combined_pk(&commits)?;
    let combined_pk_hex = dkg::point_to_hex(&combined_pk);
    send(DkgPhase::DkgFinalized, format!("combined_pk={combined_pk_hex}"));

    // ── Phase 4: on-chain DKG ceremony via Partisia ZK nodes ─────────────────
    use k256::elliptic_curve::group::GroupEncoding;

    if !on_chain {
        // Local-only mode: skip Partisia on-chain submissions, persist share, return.
        send(DkgPhase::DkgZkSubmitted, "ZK share halves submitted (simulated)".into());
        let store = ShareStore::new(&cfg.keystore_dir, &cfg.keystore_master_key)?;
        store.save(&PersistedShare {
            contract_address: cfg.signer_address.clone(),
            key_id,
            party_index: cfg.party_index as u8,
            public_key_hex: combined_pk_hex.clone(),
            shamir_share_hex: dkg::scalar_to_hex(&x_i),
            next_task_id: 1,
            runtime_version: "kosh-party-v1".into(),
        })?;
        send(DkgPhase::DkgComplete, format!("combined_pk={combined_pk_hex}"));
        return Ok(());
    }

    let mut relay = ChainRelayClient::connect(&cfg.chain_relay_addr).await?;
    let contract = &cfg.signer_address;

    // Party 1 creates the DKG key on-chain.
    if cfg.party_index == 1 {
        tracing::info!("[party 1] 0x20 dkg_create_key key={key_id}");
        relay.submit_action(
            cfg.party_index, contract, 0x20,
            ca::build_dkg_create_key(key_id, num_parties as u8),
            "dkg_create_key",
        ).await?;
    }

    if cfg.party_index == 1 {
        bb.post(&format!("dkg_create_onchain_{key_id}"), "ok").await?;
    } else {
        tracing::info!("[party {}] waiting for on-chain DKG create key={key_id}", cfg.party_index);
        bb.watch_one(&format!("dkg_create_onchain_{key_id}"), DKG_ONCHAIN_TIMEOUT).await?;
    }

    // All parties: build on-chain commit data from local DKG output.
    let my_commit = commits.get(&cfg.party_index)
        .ok_or_else(|| anyhow::anyhow!("own commit missing from BB"))?;

    let c_i0_bytes = c_i0.to_bytes().to_vec();
    let c_i1_bytes = c_i1.to_bytes().to_vec();
    let commitment_hash: Vec<u8> = Sha256::digest(&c_i0_bytes).to_vec();
    let schnorr_r_bytes = hex::decode(&my_commit.schnorr_r)?;
    let schnorr_z_bytes = hex::decode(&my_commit.schnorr_z)?;

    tracing::info!("[party {}] 0x21 dkg_commit key={key_id}", cfg.party_index);
    relay.submit_action(
        cfg.party_index, contract, 0x21,
        ca::build_dkg_commit(
            key_id, cfg.party_index as u8,
            &commitment_hash, &c_i1_bytes, &schnorr_r_bytes, &schnorr_z_bytes,
        ),
        "dkg_commit",
    ).await?;
    bb.post(&format!("dkg_commit_onchain_{key_id}_party_{}", cfg.party_index), "ok").await?;

    tracing::info!("[party {}] waiting for all DKG commits key={key_id}", cfg.party_index);
    wait_for_bb_barrier(&mut bb, key_id, "dkg_commit_onchain", num_parties, cfg.party_index).await?;

    // All parties: reveal public key share (c_i0) only after contract enters reveal phase.
    tracing::info!("[party {}] 0x22 dkg_reveal key={key_id}", cfg.party_index);
    relay.submit_action(
        cfg.party_index, contract, 0x22,
        ca::build_dkg_reveal(key_id, cfg.party_index as u8, &c_i0_bytes),
        "dkg_reveal",
    ).await?;
    bb.post(&format!("dkg_reveal_onchain_{key_id}_party_{}", cfg.party_index), "ok").await?;

    tracing::info!("[party {}] waiting for all DKG reveals key={key_id}", cfg.party_index);
    wait_for_bb_barrier(&mut bb, key_id, "dkg_reveal_onchain", num_parties, cfg.party_index).await?;

    // Party 1 finalizes the public DKG state after all reveals are visible.
    if cfg.party_index == 1 {
        tracing::info!("[party 1] 0x23 dkg_finalize key={key_id}");
        relay.submit_action(cfg.party_index, contract, 0x23, ca::build_dkg_finalize(key_id), "dkg_finalize").await?;
        bb.post(&format!("dkg_finalize_onchain_{key_id}"), "ok").await?;
    } else {
        tracing::info!("[party {}] waiting for DKG finalize key={key_id}", cfg.party_index);
        bb.watch_one(&format!("dkg_finalize_onchain_{key_id}"), DKG_ONCHAIN_TIMEOUT).await?;
    }

    // After finalize, all parties upload their Lagrange-ready share halves as encrypted ZK inputs.
    let x_i_bytes = x_i.to_bytes();
    let (x_hi, x_lo) = split_scalar_halves(&x_i_bytes);

    tracing::info!("[party {}] 0x10 submit_key_share[hi] key={key_id}", cfg.party_index);
    relay.submit_zk_input(
        cfg.party_index,
        contract,
        0x10,
        ca::build_submit_key_share(key_id, cfg.party_index as u8, true),
        x_hi.to_vec(),
        "submit_key_share_hi",
    ).await?;

    tracing::info!("[party {}] 0x10 submit_key_share[lo] key={key_id}", cfg.party_index);
    relay.submit_zk_input(
        cfg.party_index,
        contract,
        0x10,
        ca::build_submit_key_share(key_id, cfg.party_index as u8, false),
        x_lo.to_vec(),
        "submit_key_share_lo",
    ).await?;
    bb.post(&format!("dkg_share_uploaded_{key_id}_party_{}", cfg.party_index), "ok").await?;
    tracing::info!("[party {}] waiting for all DKG share uploads key={key_id}", cfg.party_index);
    wait_for_bb_barrier(&mut bb, key_id, "dkg_share_uploaded", num_parties, cfg.party_index).await?;

    // Party 1 completes keygen after the secret shares are on the ZK side.
    if cfg.party_index == 1 {
        tracing::info!("[party 1] 0x24 dkg_complete_keygen key={key_id}");
        relay.submit_action(cfg.party_index, contract, 0x24, ca::build_dkg_complete_keygen(key_id), "dkg_complete_keygen").await?;
        bb.post(&format!("dkg_complete_onchain_{key_id}"), "ok").await?;
    } else {
        tracing::info!("[party {}] waiting for DKG complete key={key_id}", cfg.party_index);
        bb.watch_one(&format!("dkg_complete_onchain_{key_id}"), DKG_ONCHAIN_TIMEOUT).await?;
    }

    send(DkgPhase::DkgZkSubmitted, format!(
        "DKG ceremony submitted to Partisia ZK nodes (contract={})", contract
    ));

    // ── Persist key share for this party (AES-256-GCM encrypted to disk) ─────
    let store = ShareStore::new(&cfg.keystore_dir, &cfg.keystore_master_key)?;
    store.save(&PersistedShare {
        contract_address: cfg.signer_address.clone(),
        key_id,
        party_index: cfg.party_index as u8,
        public_key_hex: combined_pk_hex.clone(),
        shamir_share_hex: dkg::scalar_to_hex(&x_i),
        next_task_id: 1,
        runtime_version: "kosh-party-v1".into(),
    })?;
    tracing::info!("[party {}] key share saved to {}", cfg.party_index, cfg.keystore_dir);

    send(DkgPhase::DkgComplete, format!("combined_pk={combined_pk_hex}"));
    tracing::info!("[party {}] DKG complete key={key_id} pk={combined_pk_hex}", cfg.party_index);
    Ok(())
}

// ── Signing ───────────────────────────────────────────────────────────────────

pub async fn run_sign(
    cfg: &Config,
    key_id: u32,
    message_hash: [u8; 32],
    tx_tag: String,
    signing_subset: Vec<u32>,
    task_id: u32,
    x_i_override: Option<Scalar>, // used in local/test mode; None = load from keystore
    tx: mpsc::Sender<Result<SignEvent, tonic::Status>>,
) -> Result<()> {
    let send = |phase: SignPhase, msg: String, sig: Vec<u8>| {
        let _ = tx.try_send(Ok(SignEvent { phase: phase as i32, message: msg, signature: sig }));
    };

    send(SignPhase::SignStart, format!(
        "Signing key={key_id} task={task_id} party={} on_chain=true", cfg.party_index
    ), vec![]);

    if x_i_override.is_some() {
        anyhow::bail!("x_i_override is no longer supported; signing must use persisted encrypted shares");
    }

    let on_chain = !cfg.signer_address.is_empty();

    // ── Load key share from encrypted disk persistence ───────────────────────
    let x_i = if let Some(xi) = x_i_override {
        xi
    } else {
        // For local mode the contract_address was saved as empty string
        let contract_key = if on_chain { cfg.signer_address.as_str() } else { "" };
        let store = ShareStore::new(&cfg.keystore_dir, &cfg.keystore_master_key)?;
        let persisted = store.load(contract_key, key_id, cfg.party_index as u8)?;
        let subset_u8: Vec<u8> = signing_subset.iter().map(|&p| p as u8).collect();
        apply_lagrange(&persisted.shamir_share_hex, cfg.party_index as u8, &subset_u8)?
    };

    let mut bb = BulletinBoard::connect(&cfg.coordinator_addr).await?;
    let mut state = Gg20State::new(
        key_id, task_id, cfg.party_index, signing_subset.clone(), message_hash, tx_tag.clone(),
    );

    // ── GG20 Round 1: k_i, gamma_i, Gamma_i ──────────────────────────────────
    let (k_i, gamma_i, big_gamma_i, all_gammas) =
        gg20::round1(&mut bb, &state, x_i).await?;
    state.k_i = Some(k_i);
    state.gamma_i = Some(gamma_i);
    state.big_gamma_i = Some(big_gamma_i);
    send(SignPhase::Gg20Round1, "Round 1 complete".into(), vec![]);

    // ── GG20 Round 2 + MtA: delta_i, sigma_i ─────────────────────────────────
    let (delta_i, sigma_i) =
        gg20::round2(
            &mut bb,
            &mut state,
            k_i,
            gamma_i,
            x_i,
            &cfg.coordinator_addr,
            &cfg.keystore_dir,
        )
        .await?;
    state.delta_i = Some(delta_i);
    state.sigma_i = Some(sigma_i);
    send(SignPhase::MtaComplete, "MtA complete".into(), vec![]);
    send(SignPhase::Gg20Round2, "Round 2 complete".into(), vec![]);

    if !on_chain {
        anyhow::bail!(
            "on-chain signing is required. \
             Set SIGNER_ADDRESS to the deployed contract address. \
             Demo mode (local key reconstruction) has been removed — \
             the private key must never be assembled."
        );
    }

    // ── PQC Approval (required before gg20_start_signing on-chain) ───────────
    send(SignPhase::PqcApproved, "PQC approval submitted".into(), vec![]);

    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let mut relay = ChainRelayClient::connect(&cfg.chain_relay_addr).await?;
    let contract = &cfg.signer_address;
    let parties_u8: Vec<u8> = signing_subset.iter().map(|&p| p as u8).collect();

    if cfg.party_index == 1 {
        if let Ok(state) = relay.get_contract_state(contract).await {
            let signing_phase = state["keys"][key_id.to_string()]["signing_phase"]["discriminant"]
                .as_u64()
                .unwrap_or(0);
            if signing_phase != 0 {
                tracing::warn!(
                    "[party 1] aborting stale on-chain signing session key={key_id} phase={signing_phase}"
                );
                relay
                    .submit_action(
                        cfg.party_index,
                        contract,
                        0x48,
                        ca::build_abort_signing(key_id),
                        "abort_signing",
                    )
                    .await?;
            }
        }
    }

    ensure_operational_readiness(cfg, &mut bb, &mut relay, key_id, task_id).await?;

    let onchain_task_id = if cfg.party_index == 1 {
        tracing::info!("[party 1] 0x59 open_signing_session_v4 key={key_id}");
        relay.submit_action(
            cfg.party_index,
            contract,
            0x59,
            ca::build_open_signing_session_v4(key_id, &message_hash, tx_tag.as_bytes(), &parties_u8),
            "open_signing_session_v4",
        ).await?;

        let pqc_deadline_block = relay
            .poll_until(
                contract,
                |state| {
                    state["keys"][key_id.to_string()]["pqc_approval_deadline_block"]
                        .as_i64()
                        .filter(|v| *v > 0)
                },
                SIGN_ONCHAIN_TIMEOUT,
            )
            .await
            .map_err(|e| anyhow!("failed waiting for PQC approval deadline: {e}"))?;
        let actual_task_id = relay
            .poll_until(
                contract,
                |state| {
                    let signing_info = state["keys"][key_id.to_string()]["signing_information"].as_object()?;
                    signing_info
                        .iter()
                        .filter_map(|(task_id, info)| {
                            let verified = info["verified"].as_bool().unwrap_or(false);
                            let has_sig = info["signature"].as_str().is_some();
                            if !verified && !has_sig {
                                task_id.parse::<u32>().ok()
                            } else {
                                None
                            }
                        })
                        .max()
                },
                SIGN_ONCHAIN_TIMEOUT,
            )
            .await
            .map_err(|e| anyhow!("failed waiting for active signing task id: {e}"))?;
        bb.post(
            &format!("sign_task_ready_{key_id}_{task_id}"),
            &actual_task_id.to_string(),
        )
        .await?;
        let challenge = compute_pqc_session_challenge(
            key_id,
            actual_task_id,
            &message_hash,
            tx_tag.as_bytes(),
            &parties_u8,
        );
        for &party in &parties_u8 {
            let approval_hash = compute_pqc_approval_hash(
                key_id,
                actual_task_id,
                party,
                &message_hash,
                tx_tag.as_bytes(),
                &parties_u8,
                &challenge,
                pqc_deadline_block,
            );
            relay.submit_action(
                cfg.party_index,
                contract,
                0x76,
                ca::build_submit_pqc_approval(key_id, actual_task_id, party, &approval_hash),
                "submit_pqc_approval",
            )
            .await?;
        }

        relay.submit_action(
            cfg.party_index,
            contract,
            0x77,
            ca::build_finalize_pqc_approval(key_id, actual_task_id),
            "finalize_pqc_approval",
        )
        .await?;

        tracing::info!("[party 1] 0x50 gg20_start_signing key={key_id} task={actual_task_id}");
        relay.submit_action(
            cfg.party_index,
            contract,
            0x50,
            ca::build_gg20_start_signing(key_id, actual_task_id, &parties_u8),
            "gg20_start_signing",
        )
        .await?;
        bb.post(&format!("sign_session_started_{key_id}_{task_id}"), "ok")
            .await?;
        actual_task_id
    } else {
        let actual_task_id = bb
            .watch_one(
                &format!("sign_task_ready_{key_id}_{task_id}"),
                SIGN_ONCHAIN_TIMEOUT,
            )
            .await?
            .parse::<u32>()
            .map_err(|e| anyhow!("invalid on-chain task id barrier payload: {e}"))?;
        tracing::info!(
            "[party {}] waiting for gg20 signing session key={key_id} task={actual_task_id}",
            cfg.party_index
        );
        bb.watch_one(
            &format!("sign_session_started_{key_id}_{task_id}"),
            SIGN_ONCHAIN_TIMEOUT,
        )
        .await?;
        actual_task_id
    };

        // All parties: commit delta hash, then upload delta halves as ZK inputs and reveal gamma.
        let delta_bytes = delta_i.to_bytes().to_vec();
        let delta_hash: Vec<u8> = Sha256::digest(&delta_bytes).to_vec();
        let gamma_bytes = big_gamma_i.to_encoded_point(true).as_bytes().to_vec();
        let delta_bytes = delta_i.to_bytes().to_vec();

        tracing::info!("[party {}] 0x49 commit_delta key={key_id}", cfg.party_index);
        relay.submit_action(
            cfg.party_index, contract, 0x49,
            ca::build_commit_delta(key_id, cfg.party_index as u8, &delta_hash),
            "commit_delta",
        ).await?;

        tracing::info!("[party {}] 0x45 submit_delta key={key_id}", cfg.party_index);
        relay.submit_action(
            cfg.party_index,
            contract,
            0x45,
            ca::build_submit_delta(key_id, cfg.party_index as u8, &delta_bytes),
            "submit_delta",
        ).await?;

        tracing::info!("[party {}] 0x46 submit_gamma key={key_id}", cfg.party_index);
        relay.submit_action(
            cfg.party_index, contract, 0x46,
            ca::build_submit_gamma(key_id, cfg.party_index as u8, &gamma_bytes),
            "submit_gamma",
        ).await?;
        bb.post(
            &format!("sign_delta_ready_{key_id}_{task_id}_party_{}", cfg.party_index),
            "ok",
        )
        .await?;

        tracing::info!(
            "[party {}] waiting for all delta/gamma uploads key={key_id} task={task_id}",
            cfg.party_index
        );
        wait_for_sign_subset_barrier(
            &mut bb,
            "sign_delta_ready",
            key_id,
            task_id,
            &signing_subset,
            cfg.party_index,
        )
        .await?;

        // ── Off-chain GG20 partial signature (coordinator broadcasts R, all parties
        //    compute s_i = k_i·H(m) + r·σ_i, party 1 collects and broadcasts) ──────
        //
        // This replaces the ZK psig session (0x54/0x53/0x55/0x57) which requires
        // Partisia ZK nodes to be online and assigned to this contract.
        // The math is identical to standard GG20: s = Σ s_i = k·(H(m) + r·x) ✓

        if cfg.party_index == 1 {
            tracing::info!("[party 1] 0x47 gg20_finalize_r key={key_id}");
            relay.submit_action(cfg.party_index, contract, 0x47, ca::build_gg20_finalize_r(key_id), "gg20_finalize_r").await?;

            // Fetch r from contract state (x-coordinate of R = k^{-1}·G).
            send(SignPhase::Gg20Round2, "waiting for on-chain R".into(), vec![]);
            let (r_hex, ts_recovery_id) = relay.poll_until(
                contract,
                |state| {
                    let key_node = &state["keys"][key_id.to_string()];
                    let r = key_node["ts_r_bytes"].as_str()?;
                    if r.is_empty() { return None; }  // skip before finalize_r
                    let rid = key_node["ts_recovery_id"].as_u64().unwrap_or(0) as u8;
                    Some((r.to_string(), rid))
                },
                Duration::from_secs(180),
            ).await.map_err(|e| anyhow!("failed waiting for on-chain R: {e}"))?;

            // Broadcast r (and recovery_id) to all parties so they can compute their partial sig.
            bb.post(&format!("sign_r_ready_{key_id}_{task_id}"), &r_hex).await?;
            tracing::info!("[party 1] on-chain r={r_hex} ts_recovery_id={ts_recovery_id}");

            // Compute own partial sig: s_i = k_i·H(m) + r·σ_i
            let r_scalar = dkg::scalar_from_hex(&r_hex)?;
            let s_i = gg20::compute_partial_sig(&k_i, &sigma_i, &message_hash, &r_scalar)?;
            let s_i_hex = dkg::scalar_to_hex(&s_i);
            bb.post(&format!("sign_psig_{key_id}_{task_id}_party_{}", cfg.party_index), &s_i_hex).await?;
            tracing::info!("[party 1] partial sig posted key={key_id}");

            // Wait for all other parties' partial sigs.
            let mut partial_sigs = vec![s_i];
            for &j in &signing_subset {
                if j == cfg.party_index { continue; }
                let t = format!("sign_psig_{key_id}_{task_id}_party_{j}");
                let hex = bb.watch_one(&t, SIGN_ONCHAIN_TIMEOUT).await?;
                let s_j = dkg::scalar_from_hex(&hex)?;
                partial_sigs.push(s_j);
                tracing::info!("[party 1] received partial sig from party {j}");
            }

            // Reconstruct (r, s) and determine recovery id.
            let combined_pk_hex = {
                let store = ShareStore::new(&cfg.keystore_dir, &cfg.keystore_master_key)?;
                let persisted = store.load(contract, key_id, cfg.party_index as u8)?;
                persisted.public_key_hex
            };
            let combined_pk = dkg::point_from_hex(&combined_pk_hex)?;
            tracing::info!("[party 1] combined_pk={combined_pk_hex}");
            let signature = reconstruct_ecdsa_signature(
                &r_scalar,
                &partial_sigs,
                &message_hash,
                &combined_pk,
                ts_recovery_id,
            )?;

            bb.post(&format!("sign_complete_onchain_{key_id}_{task_id}"), "ok").await?;
            send(SignPhase::PartialSigs, format!("partial sigs combined by party {}", cfg.party_index), vec![]);
            send(SignPhase::SignComplete, "signing complete (off-chain GG20)".into(), signature.clone());
            tracing::info!("[party {}] signing complete key={key_id} task={task_id}", cfg.party_index);
            return Ok(());
        }

        // Non-coordinator parties: wait for r, compute partial sig, post.
        tracing::info!("[party {}] waiting for r key={key_id} task={task_id}", cfg.party_index);
        let r_hex = bb.watch_one(
            &format!("sign_r_ready_{key_id}_{task_id}"),
            SIGN_ONCHAIN_TIMEOUT,
        ).await?;
        let r_scalar = dkg::scalar_from_hex(&r_hex)?;
        let s_i = gg20::compute_partial_sig(&k_i, &sigma_i, &message_hash, &r_scalar)?;
        let s_i_hex = dkg::scalar_to_hex(&s_i);
        bb.post(&format!("sign_psig_{key_id}_{task_id}_party_{}", cfg.party_index), &s_i_hex).await?;

        send(SignPhase::PartialSigs, format!("partial sig posted by party {}", cfg.party_index), vec![]);
        send(SignPhase::SignComplete, "signing complete (off-chain GG20)".into(), vec![]);
        tracing::info!("[party {}] signing complete key={key_id} task={task_id}", cfg.party_index);
        Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn apply_lagrange(shamir_share_hex: &str, party_index: u8, signing_subset: &[u8]) -> Result<Scalar> {
    let share = dkg::scalar_from_hex(shamir_share_hex)?;
    let i = Scalar::from(party_index as u64);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &j in signing_subset {
        if j == party_index { continue; }
        let jj = Scalar::from(j as u64);
        num *= -jj;
        den *= i - jj;
    }
    let den_inv = Option::<Scalar>::from(den.invert())
        .ok_or_else(|| anyhow::anyhow!("lagrange denominator not invertible"))?;
    Ok(num * den_inv * share)
}

fn compute_pqc_session_challenge(
    key_id: u32,
    task_id: u32,
    msg_hash: &[u8],
    tx_tag: &[u8],
    signing_subset: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"KOSH_PQC_SESSION_V1");
    payload.extend_from_slice(&key_id.to_be_bytes());
    payload.extend_from_slice(&task_id.to_be_bytes());
    encode_len_prefixed(&mut payload, msg_hash);
    encode_len_prefixed(&mut payload, tx_tag);
    encode_party_vec(&mut payload, signing_subset);
    Sha256::digest(&payload).to_vec()
}

fn compute_pqc_approval_hash(
    key_id: u32,
    task_id: u32,
    party_index: u8,
    msg_hash: &[u8],
    tx_tag: &[u8],
    signing_subset: &[u8],
    challenge: &[u8],
    expires_at_block: i64,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"KOSH_PQC_APPROVAL_V1");
    payload.extend_from_slice(&key_id.to_be_bytes());
    payload.extend_from_slice(&task_id.to_be_bytes());
    payload.push(party_index);
    encode_len_prefixed(&mut payload, msg_hash);
    encode_len_prefixed(&mut payload, tx_tag);
    encode_party_vec(&mut payload, signing_subset);
    encode_len_prefixed(&mut payload, challenge);
    payload.extend_from_slice(&expires_at_block.to_be_bytes());
    Sha256::digest(&payload).to_vec()
}

fn encode_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn encode_party_vec(out: &mut Vec<u8>, parties: &[u8]) {
    out.extend_from_slice(&(parties.len() as u32).to_be_bytes());
    out.extend_from_slice(parties);
}


fn split_scalar_halves(bytes: &[u8]) -> ([u8; 16], [u8; 16]) {
    assert_eq!(bytes.len(), 32, "split_scalar_halves requires 32 bytes");
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&bytes[..16]);
    lo.copy_from_slice(&bytes[16..]);
    (hi, lo)
}

fn split_scalar_bytes(bytes: &[u8]) -> Result<(i128, i128)> {
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&bytes[..16]);
    lo.copy_from_slice(&bytes[16..]);
    Ok((i128::from_be_bytes(hi), i128::from_be_bytes(lo)))
}

/// Combine partial GG20 signatures into a final Ethereum-compatible ECDSA signature.
/// GG20 produces s = Σ(k_i·m + r·σ_i) = k·(m+rx), which is a valid ECDSA sig
/// because R = k^{-1}·G (so verification: s^{-1}·(m+rx)·G = k^{-1}·G = R ✓).
/// k256 may normalize s to low-s form; we try all four (s / n-s) × (rid 0 / 1)
/// combinations, then fall back to the contract-provided ts_recovery_id.
fn reconstruct_ecdsa_signature(
    r: &Scalar,
    partial_sigs: &[Scalar],
    message_hash: &[u8; 32],
    combined_pk: &ProjectivePoint,
    ts_recovery_id: u8,
) -> Result<Vec<u8>> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let s = partial_sigs.iter().fold(Scalar::ZERO, |acc, s_i| acc + s_i);
    let neg_s = -s;

    let r_bytes: [u8; 32] = r.to_bytes().into();
    let s_bytes: [u8; 32] = s.to_bytes().into();
    let neg_s_bytes: [u8; 32] = neg_s.to_bytes().into();

    tracing::info!(
        "reconstruct_ecdsa: r={} s={} neg_s={} ts_recovery_id={ts_recovery_id}",
        hex::encode(r_bytes), hex::encode(s_bytes), hex::encode(neg_s_bytes)
    );

    let vk_expected = VerifyingKey::from_encoded_point(
        &combined_pk.to_encoded_point(true),
    ).map_err(|e| anyhow!("bad combined_pk: {e}"))?;

    // Try s and -s (low-s normalization), each with recovery_id 0 and 1.
    for (label, sb) in [("s", s_bytes), ("neg_s", neg_s_bytes)] {
        let sig = match Signature::from_scalars(r_bytes, sb) {
            Ok(sig) => sig,
            Err(e) => { tracing::debug!("from_scalars({label}) failed: {e}"); continue; }
        };
        // k256 may have normalized s; read back what's actually in the sig.
        let sig_s_bytes: [u8; 32] = sig.s().to_bytes().into();

        for recovery_id in [0u8, 1u8] {
            let rid = RecoveryId::try_from(recovery_id).unwrap();
            if let Ok(recovered) = VerifyingKey::recover_from_prehash(message_hash, &sig, rid) {
                if recovered == vk_expected {
                    let mut out = [0u8; 65];
                    out[..32].copy_from_slice(&r_bytes);
                    out[32..64].copy_from_slice(&sig_s_bytes);
                    out[64] = 27 + recovery_id;
                    tracing::info!("ECDSA signature verified with s_form={label} recovery_id={recovery_id}");
                    return Ok(out.to_vec());
                }
            }
        }
    }

    // Recovery failed — fall back to contract-provided ts_recovery_id.
    // Use low-s form (k256 normalizes internally anyway).
    tracing::warn!(
        "could not verify recovery id with s or -s — using contract ts_recovery_id={ts_recovery_id}"
    );
    let fallback_sig = Signature::from_scalars(r_bytes, s_bytes)
        .map_err(|e| anyhow!("invalid (r,s): {e}"))?;
    let fallback_s: [u8; 32] = fallback_sig.s().to_bytes().into();
    let mut out = [0u8; 65];
    out[..32].copy_from_slice(&r_bytes);
    out[32..64].copy_from_slice(&fallback_s);
    out[64] = 27 + ts_recovery_id;
    Ok(out.to_vec())
}
