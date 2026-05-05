/// GG20 signing rounds: Round 1 (nonce generation + commit/reveal),
/// Round 2 (delta/sigma aggregation), and partial signature computation.

use anyhow::Result;
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::bulletin_board::BulletinBoard;
use crate::dkg::{point_from_hex, point_to_hex, scalar_from_hex, scalar_from_bytes_mod_n, scalar_to_hex};
use crate::mta::run_all_mta;
use crate::types::{Gg20State, MtAOutput};

const PHASE_TIMEOUT: Duration = Duration::from_secs(300);

/// Generate k_i using HMAC-DRBG seeded from (x_i, message_hash, session_id).
/// Deterministic: same inputs always produce the same k_i.
pub fn generate_k_i(x_i: &Scalar, message_hash: &[u8; 32], session_id: &str) -> Scalar {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut key_material = x_i.to_bytes().to_vec();
    key_material.extend_from_slice(message_hash);
    key_material.extend_from_slice(session_id.as_bytes());

    let mut mac = HmacSha256::new_from_slice(&key_material).unwrap();
    mac.update(b"gg20-nonce-k_i");
    let result = mac.finalize().into_bytes();
    scalar_from_bytes_mod_n(&result)
}

/// GG20 Round 1: generate (k_i, gamma_i), commit-reveal Gamma_i = gamma_i · G.
/// Returns (k_i, gamma_i, Gamma_i) after all parties have revealed.
pub async fn round1(
    bb: &mut BulletinBoard,
    state: &Gg20State,
    x_i: Scalar,
) -> Result<(Scalar, Scalar, ProjectivePoint, Vec<ProjectivePoint>)> {
    use k256::elliptic_curve::Field;
    let session_id = format!("{}_{}", state.key_id, state.task_id);

    let k_i = generate_k_i(&x_i, &state.message_hash, &session_id);
    let gamma_i = Scalar::generate_vartime(&mut rand::rngs::OsRng);
    let big_gamma_i = ProjectivePoint::GENERATOR * gamma_i;

    // Commit: hash(Gamma_i || nonce)
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let commit = {
        let mut h = Sha256::new();
        use k256::elliptic_curve::group::GroupEncoding;
        h.update(big_gamma_i.to_bytes());
        h.update(&nonce);
        hex::encode(h.finalize())
    };

    let commit_topic = format!(
        "gg20_gamma_commit_{}_{}_party_{}",
        state.key_id, state.task_id, state.party_index
    );
    bb.post(&commit_topic, &commit).await?;
    tracing::info!("[party {}] GG20 round1: Gamma commit posted", state.party_index);

    // Wait for all other parties' commits
    let mut other_commits = Vec::new();
    for &j in &state.signing_subset {
        if j == state.party_index {
            continue;
        }
        let t = format!("gg20_gamma_commit_{}_{}_party_{j}", state.key_id, state.task_id);
        let c = bb.watch_one(&t, PHASE_TIMEOUT).await?;
        other_commits.push((j, c));
    }

    // Now reveal Gamma_i + nonce
    let reveal_payload = serde_json::json!({
        "gamma": point_to_hex(&big_gamma_i),
        "nonce": hex::encode(nonce),
    });
    let reveal_topic = format!(
        "gg20_gamma_reveal_{}_{}_party_{}",
        state.key_id, state.task_id, state.party_index
    );
    bb.post(&reveal_topic, &reveal_payload.to_string()).await?;

    // Verify other parties' reveals
    let mut all_gammas = vec![big_gamma_i];
    for (j, commit_j) in &other_commits {
        let t = format!("gg20_gamma_reveal_{}_{}_party_{j}", state.key_id, state.task_id);
        let raw = bb.watch_one(&t, PHASE_TIMEOUT).await?;
        let v: serde_json::Value = serde_json::from_str(&raw)?;

        let gamma_j = point_from_hex(v["gamma"].as_str().unwrap_or(""))?;
        let nonce_j = hex::decode(v["nonce"].as_str().unwrap_or(""))?;

        // Verify commit: SHA256(Gamma_j || nonce_j) == commit_j
        use k256::elliptic_curve::group::GroupEncoding;
        let mut h = Sha256::new();
        h.update(gamma_j.to_bytes());
        h.update(&nonce_j);
        let expected = hex::encode(h.finalize());
        if expected != *commit_j {
            anyhow::bail!("GG20 gamma commit mismatch for party {j}");
        }
        all_gammas.push(gamma_j);
        tracing::info!("[party {}] verified gamma reveal from party {j}", state.party_index);
    }

    tracing::info!("[party {}] GG20 round1 complete", state.party_index);
    Ok((k_i, gamma_i, big_gamma_i, all_gammas))
}

/// GG20 Round 2: run MtA, compute delta_i and sigma_i, commit-reveal delta_i.
/// Returns (delta_i, sigma_i, r_scalar after finalize).
pub async fn round2(
    bb: &mut BulletinBoard,
    state: &mut Gg20State,
    k_i: Scalar,
    gamma_i: Scalar,
    x_i: Scalar,
    bb_addr: &str,
) -> Result<(Scalar, Scalar)> {
    // Run MtA for all counterparty pairs concurrently
    let mta_outputs = run_all_mta(
        state.party_index,
        &state.signing_subset,
        k_i,
        gamma_i,
        x_i,
        bb_addr,
        state.key_id,
        state.task_id,
    )
    .await?;

    // Compute delta_i = k_i·gamma_i + Σ (alpha_kgamma_ij + beta_kgamma_ji)
    let mut delta_i = k_i * gamma_i;
    for out in &mta_outputs {
        delta_i = delta_i + out.alpha_kgamma + out.beta_kgamma;
    }

    // Compute sigma_i = k_i·x_i + Σ (alpha_kx_ij + beta_kx_ji)
    let mut sigma_i = k_i * x_i;
    for out in &mta_outputs {
        sigma_i = sigma_i + out.alpha_kx + out.beta_kx;
    }

    state.mta_outputs = mta_outputs;

    // Commit-reveal delta_i
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let delta_commit = {
        let mut h = Sha256::new();
        h.update(delta_i.to_bytes());
        h.update(&nonce);
        hex::encode(h.finalize())
    };

    let commit_topic = format!(
        "gg20_delta_commit_{}_{}_party_{}",
        state.key_id, state.task_id, state.party_index
    );
    bb.post(&commit_topic, &delta_commit).await?;

    // Wait for all delta commits
    let mut other_delta_commits = Vec::new();
    for &j in &state.signing_subset {
        if j == state.party_index {
            continue;
        }
        let t = format!("gg20_delta_commit_{}_{}_party_{j}", state.key_id, state.task_id);
        let c = bb.watch_one(&t, PHASE_TIMEOUT).await?;
        other_delta_commits.push((j, c));
    }

    // Reveal delta_i
    let reveal = serde_json::json!({
        "delta": scalar_to_hex(&delta_i),
        "nonce": hex::encode(nonce),
    });
    let reveal_topic = format!(
        "gg20_delta_reveal_{}_{}_party_{}",
        state.key_id, state.task_id, state.party_index
    );
    bb.post(&reveal_topic, &reveal.to_string()).await?;

    // Verify other reveals
    for (j, commit_j) in &other_delta_commits {
        let t = format!("gg20_delta_reveal_{}_{}_party_{j}", state.key_id, state.task_id);
        let raw = bb.watch_one(&t, PHASE_TIMEOUT).await?;
        let v: serde_json::Value = serde_json::from_str(&raw)?;

        let delta_j = scalar_from_hex(v["delta"].as_str().unwrap_or(""))?;
        let nonce_j = hex::decode(v["nonce"].as_str().unwrap_or(""))?;
        let mut h = Sha256::new();
        h.update(delta_j.to_bytes());
        h.update(&nonce_j);
        let expected = hex::encode(h.finalize());
        if expected != *commit_j {
            anyhow::bail!("GG20 delta commit mismatch for party {j}");
        }
    }

    tracing::info!("[party {}] GG20 round2 complete: delta_i, sigma_i computed", state.party_index);
    Ok((delta_i, sigma_i))
}

/// Compute partial signature s_i = k_i^{-1} · (m + r · sigma_i) mod N.
pub fn compute_partial_sig(
    k_i: &Scalar,
    sigma_i: &Scalar,
    message_hash: &[u8; 32],
    r: &Scalar,
) -> Result<Scalar> {
    let m = hash_to_scalar(message_hash);
    let k_inv = Option::<Scalar>::from(k_i.invert())
        .ok_or_else(|| anyhow::anyhow!("k_i is zero — cannot invert"))?;
    Ok(k_inv * (m + r * sigma_i))
}

fn hash_to_scalar(hash: &[u8; 32]) -> Scalar {
    scalar_from_bytes_mod_n(hash)
}

/// Parse r from the contract state JSON (returned by chain relay GetContractState).
pub fn parse_r_from_state(state_json: &str) -> Result<Scalar> {
    let v: serde_json::Value = serde_json::from_str(state_json)?;
    let r_hex = v["gg20_r"]
        .as_str()
        .or_else(|| v["r"].as_str())
        .ok_or_else(|| anyhow::anyhow!("r not found in contract state"))?;
    scalar_from_hex(r_hex)
}

/// Reconstruct the final ECDSA signature (r, s, v) from partial signatures.
/// Contract does this on-chain; this is the off-chain reconstruction for testing.
pub fn reconstruct_signature(
    r: &Scalar,
    partial_sigs: &[Scalar],
    _message_hash: &[u8; 32],
    _combined_pk: &ProjectivePoint,
) -> [u8; 65] {
    let s = partial_sigs.iter().fold(Scalar::ZERO, |acc, s_i| acc + s_i);
    let mut sig = [0u8; 65];
    sig[..32].copy_from_slice(r.to_bytes().as_slice());
    sig[32..64].copy_from_slice(s.to_bytes().as_slice());
    sig[64] = 27; // recovery id (simplified — real impl computes from R.y)
    sig
}
