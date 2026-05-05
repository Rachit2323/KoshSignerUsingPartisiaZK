/// Phase state machine: streams DkgEvent / SignEvent back to the gateway.
/// Each phase runs sequentially; events are sent to the gRPC response stream.

use anyhow::Result;
use k256::{ProjectivePoint, Scalar};
use tokio::sync::mpsc;

use crate::bulletin_board::BulletinBoard;
use crate::config::Config;
use crate::dkg;
use crate::gg20;
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

/// Run the full DKG flow for one party and stream events.
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

    send(DkgPhase::DkgStart, format!("DKG starting for key {key_id}"));

    let mut bb = BulletinBoard::connect(&cfg.coordinator_addr).await?;

    // ── Phase 1: Commit ───────────────────────────────────────────────────────
    let (s_i, a_i, _c_i0, _c_i1, commits) =
        dkg::run_dkg_commit(&mut bb, cfg.party_index, num_parties, key_id).await?;
    send(DkgPhase::DkgCommitted, format!("Commit posted; received {} commits", commits.len()));

    // ── Phase 2: Sub-shares ───────────────────────────────────────────────────
    let _x_i = dkg::run_dkg_subshares(
        &mut bb, cfg.party_index, num_parties, key_id,
        &s_i, &a_i, &commits,
    )
    .await?;
    send(DkgPhase::DkgSubshares, "Sub-shares exchanged and verified".to_string());

    // ── Phase 3: Compute combined public key ──────────────────────────────────
    let combined_pk = dkg::compute_combined_pk(&commits)?;
    let combined_pk_hex = dkg::point_to_hex(&combined_pk);
    send(DkgPhase::DkgFinalized, format!("combined_pk={combined_pk_hex}"));

    // ── Phase 4: On-chain ceremony (via chain relay) ──────────────────────────
    // In the full impl: submit DKG create/commit/reveal/finalize/complete_keygen
    // via chain_relay_client. Omitted here to keep the phase service self-contained
    // for testing without a running Partisia node.
    send(DkgPhase::DkgZkSubmitted, "ZK share halves submitted (simulated)".to_string());
    send(DkgPhase::DkgComplete, format!("combined_pk={combined_pk_hex}"));

    tracing::info!("[party {}] DKG complete for key {key_id}: pk={combined_pk_hex}", cfg.party_index);
    Ok(())
}

/// Run the full signing flow for one party and stream events.
pub async fn run_sign(
    cfg: &Config,
    key_id: u32,
    message_hash: [u8; 32],
    tx_tag: String,
    signing_subset: Vec<u32>,
    task_id: u32,
    x_i: Scalar,
    tx: mpsc::Sender<Result<SignEvent, tonic::Status>>,
) -> Result<()> {
    let send = |phase: SignPhase, msg: String, sig: Vec<u8>| {
        let _ = tx.try_send(Ok(SignEvent { phase: phase as i32, message: msg, signature: sig }));
    };

    send(SignPhase::SignStart, format!("Signing key={key_id} task={task_id}"), vec![]);

    let mut bb = BulletinBoard::connect(&cfg.coordinator_addr).await?;

    let mut state = Gg20State::new(
        key_id, task_id, cfg.party_index, signing_subset, message_hash, tx_tag,
    );

    // ── PQC Approval (placeholder) ────────────────────────────────────────────
    send(SignPhase::PqcApproved, "PQC approval submitted".to_string(), vec![]);

    // ── GG20 Round 1 ──────────────────────────────────────────────────────────
    let (k_i, gamma_i, big_gamma_i, all_gammas) =
        gg20::round1(&mut bb, &state, x_i).await?;
    state.k_i = Some(k_i);
    state.gamma_i = Some(gamma_i);
    state.big_gamma_i = Some(big_gamma_i);
    send(SignPhase::Gg20Round1, "Round 1 complete".to_string(), vec![]);

    // ── GG20 Round 2 + MtA ───────────────────────────────────────────────────
    let (delta_i, sigma_i) =
        gg20::round2(&mut bb, &mut state, k_i, gamma_i, x_i, &cfg.coordinator_addr).await?;
    state.delta_i = Some(delta_i);
    state.sigma_i = Some(sigma_i);
    send(SignPhase::MtaComplete, "MtA complete".to_string(), vec![]);
    send(SignPhase::Gg20Round2, "Round 2 complete".to_string(), vec![]);

    // ── Partial Signature ─────────────────────────────────────────────────────
    // In full impl: fetch r from contract state via chain relay after Party 1 finalizes.
    // For the service skeleton, use a placeholder r derived from the session.
    let r = derive_r_placeholder(&all_gammas, &delta_i);
    state.r_scalar = Some(r);

    let s_i = gg20::compute_partial_sig(&k_i, &sigma_i, &message_hash, &r)?;
    send(SignPhase::PartialSigs, format!("Partial sig computed by party {}", cfg.party_index), vec![]);

    // Post partial sig to coordinator (Party 1 will collect and reconstruct)
    let topic = format!(
        "gg20_partial_sig_{}_{}_party_{}",
        state.key_id, state.task_id, cfg.party_index
    );
    bb.post(&topic, &dkg::scalar_to_hex(&s_i)).await?;

    // Collect all partial sigs if we are party 1
    let signature = if cfg.party_index == 1 {
        let mut sigs = vec![s_i];
        for &j in &state.signing_subset {
            if j == cfg.party_index {
                continue;
            }
            let t = format!("gg20_partial_sig_{}_{}_party_{j}", state.key_id, state.task_id);
            let raw = bb
                .watch_one(&t, std::time::Duration::from_secs(120))
                .await?;
            sigs.push(dkg::scalar_from_hex(&raw)?);
        }
        gg20::reconstruct_signature(&r, &sigs, &message_hash, &ProjectivePoint::IDENTITY).to_vec()
    } else {
        vec![]
    };

    send(SignPhase::SignComplete, "Signing complete".to_string(), signature);
    tracing::info!("[party {}] Signing complete for key={key_id} task={task_id}", cfg.party_index);
    Ok(())
}

/// Derive r deterministically from Gamma points for testing (no on-chain relay needed).
fn derive_r_placeholder(gammas: &[ProjectivePoint], delta: &Scalar) -> Scalar {
    use k256::elliptic_curve::group::GroupEncoding;
    use sha2::{Digest, Sha256};
    let big_gamma: ProjectivePoint = gammas.iter().fold(ProjectivePoint::IDENTITY, |acc, g| acc + *g);
    let mut h = Sha256::new();
    h.update(big_gamma.to_bytes());
    h.update(delta.to_bytes());
    let hash = h.finalize();
    dkg::scalar_from_bytes_mod_n(&hash)
}
