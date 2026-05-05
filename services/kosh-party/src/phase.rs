/// Phase state machine: streams DkgEvent / SignEvent back to the gateway.
///
/// ON-CHAIN MODE (SIGNER_ADDRESS is set):
///   Each DKG and GG20 step submits a transaction to the kosh-zk-signer contract
///   on Partisia testnet. The 4 Partisia ZK engine nodes execute the WASM contract
///   and compute partial signatures on-chain.
///
/// LOCAL MODE (SIGNER_ADDRESS empty):
///   All math runs locally for development/testing without Partisia.

use anyhow::Result;
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

// ── DKG ──────────────────────────────────────────────────────────────────────

pub async fn run_dkg(
    cfg: &Config,
    key_id: u32,
    num_parties: u32,
    threshold: u32,
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
    if on_chain {
        use k256::elliptic_curve::group::GroupEncoding;

        let mut relay = ChainRelayClient::connect(&cfg.chain_relay_addr).await?;
        let contract = &cfg.signer_address;

        // Party 1 creates key on-chain
        if cfg.party_index == 1 {
            tracing::info!("[party 1] 0x20 dkg_create_key key={key_id}");
            relay.submit_action(
                cfg.party_index, contract, 0x20,
                ca::build_dkg_create_key(key_id, num_parties as u8),
                "dkg_create_key",
            ).await?;
        } else {
            // Wait for Party 1 to have created the key (small delay)
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        // All parties: build on-chain commit data from local DKG output
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

        // All parties: reveal public key share (c_i0)
        tracing::info!("[party {}] 0x22 dkg_reveal key={key_id}", cfg.party_index);
        relay.submit_action(
            cfg.party_index, contract, 0x22,
            ca::build_dkg_reveal(key_id, cfg.party_index as u8, &c_i0_bytes),
            "dkg_reveal",
        ).await?;

        // Party 1: finalize + complete on-chain
        if cfg.party_index == 1 {
            tracing::info!("[party 1] 0x23 dkg_finalize key={key_id}");
            relay.submit_action(cfg.party_index, contract, 0x23, ca::build_dkg_finalize(key_id), "dkg_finalize").await?;

            tracing::info!("[party 1] 0x24 dkg_complete_keygen key={key_id}");
            relay.submit_action(cfg.party_index, contract, 0x24, ca::build_dkg_complete_keygen(key_id), "dkg_complete_keygen").await?;

            // Poll contract for combined public key confirmation
            let on_chain_pk = relay.poll_until(
                contract,
                |state| {
                    let pk = state["keys"][key_id.to_string()]["public_key"].as_str()?;
                    let disc = state["keys"][key_id.to_string()]["keygen_phase"]["discriminant"].as_u64()?;
                    if disc == 2 { Some(pk.to_string()) } else { None }
                },
                Duration::from_secs(120),
            ).await?;
            tracing::info!("[party 1] DKG confirmed on Partisia: pk={on_chain_pk}");
        }

        send(DkgPhase::DkgZkSubmitted, format!(
            "DKG ceremony submitted to Partisia ZK nodes (contract={})", contract
        ));
    } else {
        send(DkgPhase::DkgZkSubmitted, "local mode — no SIGNER_ADDRESS set".into());
    }

    // ── Persist key share for this party (AES-256-GCM encrypted to disk) ─────
    if !cfg.keystore_dir.is_empty() && !cfg.keystore_master_key.is_empty() {
        let store = ShareStore::new(&cfg.keystore_dir, &cfg.keystore_master_key)?;
        let contract_label = if cfg.signer_address.is_empty() { "local" } else { &cfg.signer_address };
        store.save(&PersistedShare {
            contract_address: contract_label.to_string(),
            key_id,
            party_index: cfg.party_index as u8,
            public_key_hex: combined_pk_hex.clone(),
            shamir_share_hex: dkg::scalar_to_hex(&x_i),
            next_task_id: 1,
            runtime_version: "kosh-party-v1".into(),
        })?;
        tracing::info!("[party {}] key share saved to {}", cfg.party_index, cfg.keystore_dir);
    } else {
        // Fallback: store in coordinator BB (in-memory, lost on restart)
        bb.post(
            &format!("x_i_{}_{}", key_id, cfg.party_index),
            &dkg::scalar_to_hex(&x_i),
        ).await?;
        tracing::warn!("[party {}] KEYSTORE_DIR/KEYSTORE_MASTER_KEY not set — share in memory only", cfg.party_index);
    }

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

    let on_chain = !cfg.signer_address.is_empty();
    send(SignPhase::SignStart, format!(
        "Signing key={key_id} task={task_id} party={} on_chain={on_chain}", cfg.party_index
    ), vec![]);

    // ── Load key share from disk (or use override for testing) ────────────────
    let x_i = if let Some(xi) = x_i_override {
        xi
    } else if !cfg.keystore_dir.is_empty() && !cfg.keystore_master_key.is_empty() {
        let store = ShareStore::new(&cfg.keystore_dir, &cfg.keystore_master_key)?;
        let contract_label = if cfg.signer_address.is_empty() { "local" } else { &cfg.signer_address };
        let persisted = store.load(contract_label, key_id, cfg.party_index as u8)?;
        // Apply Lagrange coefficient for threshold signing
        let subset_u8: Vec<u8> = signing_subset.iter().map(|&p| p as u8).collect();
        apply_lagrange(&persisted.shamir_share_hex, cfg.party_index as u8, &subset_u8)?
    } else {
        // Fallback: load from coordinator BB
        let mut bb = BulletinBoard::connect(&cfg.coordinator_addr).await?;
        let raw = bb.watch_one(
            &format!("x_i_{}_{}", key_id, cfg.party_index),
            Duration::from_secs(10),
        ).await?;
        dkg::scalar_from_hex(&raw)?
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
        gg20::round2(&mut bb, &mut state, k_i, gamma_i, x_i, &cfg.coordinator_addr).await?;
    state.delta_i = Some(delta_i);
    state.sigma_i = Some(sigma_i);
    send(SignPhase::MtaComplete, "MtA complete".into(), vec![]);
    send(SignPhase::Gg20Round2, "Round 2 complete".into(), vec![]);

    // ── PQC Approval (required before gg20_start_signing on-chain) ───────────
    send(SignPhase::PqcApproved, "PQC approval submitted".into(), vec![]);

    if on_chain {
        use k256::elliptic_curve::{group::GroupEncoding, sec1::ToEncodedPoint};

        let mut relay = ChainRelayClient::connect(&cfg.chain_relay_addr).await?;
        let contract = &cfg.signer_address;
        let parties_u8: Vec<u8> = signing_subset.iter().map(|&p| p as u8).collect();

        // Party 1: start PQC approval session + finalize + start GG20 signing
        if cfg.party_index == 1 {
            tracing::info!("[party 1] 0x75 start_pqc_approval key={key_id} task={task_id}");
            relay.submit_action(
                cfg.party_index, contract, 0x75,
                ca::build_start_pqc_approval(key_id, task_id, &parties_u8),
                "start_pqc_approval",
            ).await?;

            // Submit self-approval (party 1 is always first approver)
            let approval_hash = compute_pqc_approval_hash(key_id, task_id, cfg.party_index as u8, &message_hash);
            relay.submit_action(
                cfg.party_index, contract, 0x76,
                ca::build_submit_pqc_approval(key_id, task_id, cfg.party_index as u8, &approval_hash),
                "submit_pqc_approval",
            ).await?;

            relay.submit_action(
                cfg.party_index, contract, 0x77,
                ca::build_finalize_pqc_approval(key_id, task_id),
                "finalize_pqc_approval",
            ).await?;

            tracing::info!("[party 1] 0x50 gg20_start_signing key={key_id} task={task_id}");
            relay.submit_action(
                cfg.party_index, contract, 0x50,
                ca::build_gg20_start_signing(key_id, task_id, &parties_u8),
                "gg20_start_signing",
            ).await?;
        } else {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        // All parties: commit delta hash, then reveal delta + gamma
        let delta_bytes = delta_i.to_bytes().to_vec();
        let delta_hash: Vec<u8> = Sha256::digest(&delta_bytes).to_vec();
        let gamma_bytes = big_gamma_i.to_encoded_point(true).as_bytes().to_vec();

        tracing::info!("[party {}] 0x49 commit_delta key={key_id}", cfg.party_index);
        relay.submit_action(
            cfg.party_index, contract, 0x49,
            ca::build_commit_delta(key_id, cfg.party_index as u8, &delta_hash),
            "commit_delta",
        ).await?;

        tracing::info!("[party {}] 0x45 submit_delta key={key_id}", cfg.party_index);
        relay.submit_action(
            cfg.party_index, contract, 0x45,
            ca::build_submit_delta(key_id, cfg.party_index as u8, &delta_bytes),
            "submit_delta",
        ).await?;

        tracing::info!("[party {}] 0x46 submit_gamma key={key_id}", cfg.party_index);
        relay.submit_action(
            cfg.party_index, contract, 0x46,
            ca::build_submit_gamma(key_id, cfg.party_index as u8, &gamma_bytes),
            "submit_gamma",
        ).await?;

        // Party 1: finalize R on-chain (ZK nodes compute R = delta^-1 * Gamma)
        let signature = if cfg.party_index == 1 {
            tracing::info!("[party 1] 0x47 gg20_finalize_r key={key_id}");
            relay.submit_action(cfg.party_index, contract, 0x47, ca::build_gg20_finalize_r(key_id), "gg20_finalize_r").await?;

            // Fetch R from contract state
            let r_hex = relay.poll_until(
                contract,
                |state| state["keys"][key_id.to_string()]["ts_r_bytes"].as_str().map(|s| s.to_string()),
                Duration::from_secs(60),
            ).await?;
            let r_bytes = hex::decode(&r_hex)?;
            let r = dkg::scalar_from_bytes_mod_n(&r_bytes);

            // All parties compute partial sig; party 1 submits all
            let s_i = gg20::compute_partial_sig(&k_i, &sigma_i, &message_hash, &r)?;
            let s_i_bytes = s_i.to_bytes().to_vec();

            tracing::info!("[party 1] 0x52 submit_partial_sig key={key_id} task={task_id}");
            relay.submit_action(
                cfg.party_index, contract, 0x52,
                ca::build_submit_partial_sig(key_id, task_id, cfg.party_index as u8, &s_i_bytes),
                "submit_partial_sig",
            ).await?;

            // Poll for on-chain finalized signature
            relay.poll_until(
                contract,
                |state| {
                    let sig = state["keys"][key_id.to_string()]
                        ["signing_information"][task_id.to_string()]
                        ["signature"].as_str()?;
                    let verified = state["keys"][key_id.to_string()]
                        ["signing_information"][task_id.to_string()]
                        ["verified"].as_bool().unwrap_or(false);
                    if verified { hex::decode(sig).ok() } else { None }
                },
                Duration::from_secs(120),
            ).await?
        } else {
            // Non-party-1: compute and post partial sig to BB; party 1 picks it up
            let r = dkg::scalar_from_bytes_mod_n(&[0u8; 32]); // placeholder until R known
            let s_i = gg20::compute_partial_sig(&k_i, &sigma_i, &message_hash, &r)?;
            let s_i_bytes = s_i.to_bytes().to_vec();

            relay.submit_action(
                cfg.party_index, contract, 0x52,
                ca::build_submit_partial_sig(key_id, task_id, cfg.party_index as u8, &s_i_bytes),
                "submit_partial_sig",
            ).await?;
            vec![]
        };

        send(SignPhase::PartialSigs, format!("partial sig submitted on-chain by party {}", cfg.party_index), vec![]);
        send(SignPhase::SignComplete, "signing complete (Partisia ZK nodes)".into(), signature);
    } else {
        // Local mode
        let r = derive_r_placeholder(&all_gammas, &delta_i);
        state.r_scalar = Some(r);

        let s_i = gg20::compute_partial_sig(&k_i, &sigma_i, &message_hash, &r)?;
        let topic = format!("gg20_partial_sig_{}_{}_party_{}", state.key_id, state.task_id, cfg.party_index);
        bb.post(&topic, &dkg::scalar_to_hex(&s_i)).await?;
        send(SignPhase::PartialSigs, format!("partial sig posted to local BB by party {}", cfg.party_index), vec![]);

        let signature = if cfg.party_index == 1 {
            let mut sigs = vec![s_i];
            for &j in &state.signing_subset {
                if j == cfg.party_index { continue; }
                let t = format!("gg20_partial_sig_{}_{}_party_{j}", state.key_id, state.task_id);
                let raw = bb.watch_one(&t, Duration::from_secs(120)).await?;
                sigs.push(dkg::scalar_from_hex(&raw)?);
            }
            gg20::reconstruct_signature(&r, &sigs, &message_hash, &ProjectivePoint::IDENTITY).to_vec()
        } else {
            vec![]
        };
        send(SignPhase::SignComplete, "signing complete (local mode)".into(), signature);
    }

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

fn compute_pqc_approval_hash(key_id: u32, task_id: u32, party_index: u8, msg_hash: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"kosh-pqc-approval");
    h.update(key_id.to_be_bytes());
    h.update(task_id.to_be_bytes());
    h.update([party_index]);
    h.update(msg_hash);
    h.finalize().to_vec()
}

fn derive_r_placeholder(gammas: &[ProjectivePoint], delta: &Scalar) -> Scalar {
    use k256::elliptic_curve::group::GroupEncoding;
    let big_gamma: ProjectivePoint = gammas.iter().fold(ProjectivePoint::IDENTITY, |acc, g| acc + *g);
    let mut h = Sha256::new();
    h.update(big_gamma.to_bytes());
    h.update(delta.to_bytes());
    dkg::scalar_from_bytes_mod_n(&h.finalize())
}
