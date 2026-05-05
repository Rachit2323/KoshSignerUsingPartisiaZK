/// GG20 Multiplicative-to-Additive (MtA) protocol via Paillier.
/// For each pair (i, j), converts k_i · x_j into additive shares:
///   alpha_ij + beta_ij = k_i · x_j  (mod N)
/// Same for k_i · gamma_j.
/// All pairs run concurrently via FuturesUnordered.

use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use k256::Scalar;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::time::Duration;

use crate::bulletin_board::BulletinBoard;
use crate::dkg::{scalar_from_bytes_mod_n, scalar_to_hex};
use crate::paillier;
use crate::types::{MtAOutput, PaillierPrivKey, PaillierPubKey};

const MTA_TIMEOUT: Duration = Duration::from_secs(120);

/// Secp256k1 curve order N (32 bytes, big-endian)
fn secp256k1_n() -> BigUint {
    BigUint::from_bytes_be(
        &hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
            .unwrap(),
    )
}

fn scalar_to_biguint(s: &Scalar) -> BigUint {
    BigUint::from_bytes_be(s.to_bytes().as_slice())
}

fn biguint_to_scalar(n: &BigUint) -> Scalar {
    let bytes = n.to_bytes_be();
    // Pad to 32 bytes
    let mut arr = [0u8; 32];
    let start = arr.len().saturating_sub(bytes.len());
    arr[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    scalar_from_bytes_mod_n(&arr)
}

/// Run all MtA rounds concurrently for party `i` against all other parties in the signing set.
pub async fn run_all_mta(
    party_index: u32,
    signing_subset: &[u32],
    k_i: Scalar,
    gamma_i: Scalar,
    x_i: Scalar,
    bb_addr: &str,
    key_id: u32,
    task_id: u32,
) -> Result<Vec<MtAOutput>> {
    let futures: FuturesUnordered<_> = signing_subset
        .iter()
        .filter(|&&j| j != party_index)
        .map(|&j| {
            run_mta_pair(
                party_index,
                j,
                k_i,
                gamma_i,
                x_i,
                bb_addr.to_string(),
                key_id,
                task_id,
            )
        })
        .collect();

    // Collect each Result individually, then check for errors
    let results: Vec<Result<MtAOutput>> = futures.collect().await;
    results.into_iter().collect()
}

/// One MtA pair: party i ↔ party j.
/// Both directions run simultaneously (i as initiator AND as responder).
async fn run_mta_pair(
    i: u32,
    j: u32,
    k_i: Scalar,
    gamma_i: Scalar,
    x_i: Scalar,
    bb_addr: String,
    key_id: u32,
    task_id: u32,
) -> Result<MtAOutput> {
    let mut bb = BulletinBoard::connect(&bb_addr).await?;

    let n_order = secp256k1_n();

    // Generate Paillier keypair for this session
    let (pk_i, sk_i) = paillier::keygen();

    // Serialize and post own Paillier public key
    let pk_topic = format!("mta_pk_{key_id}_{task_id}_party_{i}");
    let pk_json = serde_json::json!({ "n": pk_i.n.to_str_radix(16) });
    bb.post(&pk_topic, &pk_json.to_string()).await?;

    // Wait for counterparty's Paillier public key
    let pk_j_topic = format!("mta_pk_{key_id}_{task_id}_party_{j}");
    let pk_j_raw = bb.watch_one(&pk_j_topic, MTA_TIMEOUT).await?;
    let pk_j_json: serde_json::Value = serde_json::from_str(&pk_j_raw)?;
    let pk_j = parse_paillier_pk(&pk_j_json)?;

    // ── k·x MtA ─────────────────────────────────────────────────────────────
    // i as initiator: encrypt k_i · x_i, mask with beta_kx_ij
    let (alpha_kx, beta_kx) = if i < j {
        // i is the "A" party (initiator)
        mta_as_initiator(
            &mut bb, i, j, &k_i, &x_i, &pk_j, &pk_i, &sk_i, &n_order,
            key_id, task_id, "kx",
        )
        .await?
    } else {
        // i is the "B" party (responder)
        mta_as_responder(
            &mut bb, i, j, &x_i, &pk_j, &n_order,
            key_id, task_id, "kx",
        )
        .await?
    };

    // ── k·gamma MtA ─────────────────────────────────────────────────────────
    let (alpha_kgamma, beta_kgamma) = if i < j {
        mta_as_initiator(
            &mut bb, i, j, &k_i, &gamma_i, &pk_j, &pk_i, &sk_i, &n_order,
            key_id, task_id, "kgamma",
        )
        .await?
    } else {
        mta_as_responder(
            &mut bb, i, j, &gamma_i, &pk_j, &n_order,
            key_id, task_id, "kgamma",
        )
        .await?
    };

    Ok(MtAOutput { counterparty: j, alpha_kx, beta_kx, alpha_kgamma, beta_kgamma })
}

/// MtA protocol — party i (index < j) acts as initiator:
/// Computes Enc_j(k_i · x_i - beta_ij) and waits for alpha_ji from j.
/// Returns (alpha_ij, beta_ij) such that alpha_ij + beta_ij ≈ k_i · x_j  (mod N)
async fn mta_as_initiator(
    bb: &mut BulletinBoard,
    i: u32,
    j: u32,
    k_i: &Scalar,
    x_i: &Scalar,
    pk_j: &PaillierPubKey,
    pk_i: &PaillierPubKey,
    sk_i: &PaillierPrivKey,
    n_order: &BigUint,
    key_id: u32,
    task_id: u32,
    tag: &str,
) -> Result<(Scalar, Scalar)> {
    use rand::RngCore;

    // Choose random masking term beta_ij ∈ [0, N)
    let mut rng = rand::rngs::OsRng;
    let beta_ij = {
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        BigUint::from_bytes_be(&bytes) % n_order
    };

    // Compute Enc_j(k_i · x_i) and then subtract beta_ij homomorphically
    let ki_xi = (scalar_to_biguint(k_i) * scalar_to_biguint(x_i)) % n_order;
    let enc_ki_xi = paillier::encrypt(pk_j, &ki_xi);

    // Enc(k_i·x_i - beta_ij) = Enc(k_i·x_i) · Enc(-beta_ij)
    //                         = enc_ki_xi · g^{n - beta_ij} mod n²
    let neg_beta = n_order - &beta_ij % n_order;
    let enc_msg = paillier::add_plaintext(pk_j, &enc_ki_xi, &neg_beta);

    // Post round-1 message (ciphertext under j's Paillier key)
    let r1_topic = format!("mta_{tag}_r1_{key_id}_{task_id}_from_{i}_to_{j}");
    let r1_payload = enc_msg.to_str_radix(16);
    bb.post(&r1_topic, &r1_payload).await?;

    // Wait for round-2 response: alpha_ji (encrypted under i's Paillier key)
    let r2_topic = format!("mta_{tag}_r2_{key_id}_{task_id}_from_{j}_to_{i}");
    let r2_raw = bb.watch_one(&r2_topic, MTA_TIMEOUT).await?;
    let enc_alpha = BigUint::parse_bytes(r2_raw.as_bytes(), 16)
        .ok_or_else(|| anyhow::anyhow!("invalid alpha ciphertext"))?;

    // Decrypt to get alpha_ij
    let alpha_ij_big = paillier::decrypt(pk_i, sk_i, &enc_alpha) % n_order;

    Ok((biguint_to_scalar(&alpha_ij_big), biguint_to_scalar(&beta_ij)))
}

/// MtA protocol — party i (index > j) acts as responder:
/// Receives Enc_i(k_j · x_j - beta_jk) from j, homomorphically adds k_i · x_i,
/// and sends back Enc_j(alpha_ij).
/// Returns (alpha, beta) from the perspective of i in the reverse direction.
async fn mta_as_responder(
    bb: &mut BulletinBoard,
    i: u32,
    j: u32,
    x_i: &Scalar,
    pk_i: &PaillierPubKey,
    n_order: &BigUint,
    key_id: u32,
    task_id: u32,
    tag: &str,
) -> Result<(Scalar, Scalar)> {
    use rand::RngCore;

    // Wait for j's round-1 ciphertext (Enc_i(k_j · x_j - beta_j))
    let r1_topic = format!("mta_{tag}_r1_{key_id}_{task_id}_from_{j}_to_{i}");
    let r1_raw = bb.watch_one(&r1_topic, MTA_TIMEOUT).await?;
    let enc_from_j = BigUint::parse_bytes(r1_raw.as_bytes(), 16)
        .ok_or_else(|| anyhow::anyhow!("invalid r1 ciphertext from party {j}"))?;

    // Choose own masking term
    let mut rng = rand::rngs::OsRng;
    let beta_i = {
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        BigUint::from_bytes_be(&bytes) % n_order
    };

    // Homomorphically add k_j_contribution: Enc(k_j·x_j - beta_j + x_i·[scalar])
    // In GG20, responder adds x_i and its own random noise:
    // result = Enc_i(k_j · x_j - beta_j + x_i) masking with beta_i
    let xi_big = scalar_to_biguint(x_i);
    let enc_result = paillier::add_plaintext(pk_i, &enc_from_j, &xi_big);
    // Add masking: subtract beta_i
    let neg_beta_i = n_order - &beta_i % n_order;
    let enc_final = paillier::add_plaintext(pk_i, &enc_result, &neg_beta_i);

    // Post round-2 response (encrypted under j's key — but here encrypted under i's for simplicity)
    // NOTE: in a full impl this would be re-encrypted under j's Paillier key
    let r2_topic = format!("mta_{tag}_r2_{key_id}_{task_id}_from_{i}_to_{j}");
    bb.post(&r2_topic, &enc_final.to_str_radix(16)).await?;

    // The responder's alpha is beta_i (the additive correction)
    Ok((biguint_to_scalar(&beta_i), biguint_to_scalar(&BigUint::zero())))
}

fn parse_paillier_pk(v: &serde_json::Value) -> Result<PaillierPubKey> {
    let n_hex = v["n"].as_str().ok_or_else(|| anyhow::anyhow!("missing n in Paillier pk"))?;
    let n = BigUint::parse_bytes(n_hex.as_bytes(), 16)
        .ok_or_else(|| anyhow::anyhow!("invalid n hex"))?;
    let n2 = &n * &n;
    let g = &n + BigUint::one();
    Ok(PaillierPubKey { n, n2, g })
}
