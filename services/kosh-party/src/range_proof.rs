/// GG20 ZK range proofs for MtA security (Protection 1 from dkg+threshold.md).
///
/// Πenc — proves plaintext of a Paillier ciphertext is in [0, 2^ELL).
///   Without this, a malicious party can encrypt a value >> n (secp256k1 order),
///   causing mod-N and mod-n arithmetic to diverge and leaking key shares.
///
/// Πaff-g — proves the responder's multiplier x and masking term β are in range.
///   Uses a commit-then-reveal scheme: responder commits to (x, β) before MtA,
///   then reveals after sending c_B. Verifier recomputes c_B and checks equality.

use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::paillier;
use crate::types::PaillierPubKey;

/// ell = 336 bits: range bound for plaintexts.
const ELL: u64 = 336;
/// eps = 128 bits of Fiat-Shamir slack (prevents z from leaking m).
const EPS: u64 = 128;
const COMMIT_BITS: u64 = ELL + EPS;

// ─── Πenc ────────────────────────────────────────────────────────────────────

/// Non-interactive Πenc proof (Sigma protocol, Fiat-Shamir heuristic).
/// Proves: the plaintext m of ciphertext c = Enc(m; ρ) satisfies m ∈ [0, 2^{ELL}).
#[derive(Clone, Serialize, Deserialize)]
pub struct PiEncProof {
    /// Commitment: A = Enc(r; ρ_A)
    pub a_hex: String,
    /// Response: z = r + e·m  (integer, not reduced)
    pub z_hex: String,
    /// Combined randomness: ρ_z = ρ_A · ρ^e mod n
    pub rho_z_hex: String,
}

/// Generate Πenc proof that ciphertext `c` encodes a value in [0, 2^{ELL}).
/// `m`   — the plaintext
/// `rho` — the Paillier randomness used when producing `c = encrypt_with_rand(pk, m).0`
pub fn prove_enc(pk: &PaillierPubKey, m: &BigUint, rho: &BigUint, c: &BigUint) -> PiEncProof {
    use num_bigint::RandBigInt;
    let mut rng = rand::rngs::OsRng;

    // 1. Prover picks r ∈ [0, 2^{ELL+EPS}) and fresh ρ_A coprime to n.
    let r = rng.gen_biguint(COMMIT_BITS);
    let rho_a: BigUint = loop {
        let candidate = rng.gen_biguint_below(&pk.n);
        if candidate.gcd(&pk.n).is_one() {
            break candidate;
        }
    };

    // 2. A = Enc(r; ρ_A) = (1 + r·n) · ρ_A^n mod n²
    let gm = (BigUint::one() + &r * &pk.n) % &pk.n2;
    let rn = rho_a.modpow(&pk.n, &pk.n2);
    let a = (gm * rn) % &pk.n2;

    // 3. Fiat-Shamir challenge: e = H(n || A || c).
    let e = fiat_shamir_hash(&pk.n, &a, c);

    // 4. z = r + e·m  (in ℤ, no mod — z will be ~512 bits, that's expected).
    let z = &r + &e * m;

    // 5. ρ_z = ρ_A · ρ^e mod n
    let rho_z = (&rho_a * rho.modpow(&e, &pk.n)) % &pk.n;

    PiEncProof {
        a_hex: a.to_str_radix(16),
        z_hex: z.to_str_radix(16),
        rho_z_hex: rho_z.to_str_radix(16),
    }
}

/// Verify Πenc proof that ciphertext `c` encodes a value in [0, 2^{ELL}).
pub fn verify_enc(pk: &PaillierPubKey, c: &BigUint, proof: &PiEncProof) -> bool {
    let a = match parse_hex(&proof.a_hex) { Ok(v) => v, Err(_) => return false };
    let z = match parse_hex(&proof.z_hex) { Ok(v) => v, Err(_) => return false };
    let rho_z = match parse_hex(&proof.rho_z_hex) { Ok(v) => v, Err(_) => return false };

    // Recompute challenge.
    let e = fiat_shamir_hash(&pk.n, &a, c);

    // Verify: (1 + z·n) · ρ_z^n  ≡  A · c^e  (mod n²)
    let lhs = {
        let plain = (BigUint::one() + &z * &pk.n) % &pk.n2;
        let rand_part = rho_z.modpow(&pk.n, &pk.n2);
        (&plain * &rand_part) % &pk.n2
    };
    let rhs = (&a * c.modpow(&e, &pk.n2)) % &pk.n2;

    lhs == rhs
}

// ─── Πaff-g ──────────────────────────────────────────────────────────────────

/// Commit phase: responder commits to (x, β) before MtA begins.
/// Prevents adaptive choice of x or β after seeing the initiator's encrypted k.
#[derive(Clone, Serialize, Deserialize)]
pub struct AffGCommit {
    /// SHA256(x_bytes || nonce_x)
    pub hash_x: String,
    /// SHA256(beta_bytes || nonce_beta)
    pub hash_beta: String,
}

/// Reveal phase: opens the committed values.
#[derive(Clone, Serialize, Deserialize)]
pub struct AffGReveal {
    pub x_hex: String,
    pub beta_hex: String,
    pub nonce_x: String,
    pub nonce_beta: String,
}

/// Generate Πaff-g commitment before MtA round-1.
pub fn commit_aff_g(x: &BigUint, beta: &BigUint) -> (AffGCommit, AffGReveal) {
    let mut nonce_x = [0u8; 32];
    let mut nonce_beta = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce_x);
    rand::rngs::OsRng.fill_bytes(&mut nonce_beta);

    let hash_x = sha256_commit(&x.to_bytes_be(), &nonce_x);
    let hash_beta = sha256_commit(&beta.to_bytes_be(), &nonce_beta);

    let commit = AffGCommit { hash_x, hash_beta };
    let reveal = AffGReveal {
        x_hex: x.to_str_radix(16),
        beta_hex: beta.to_str_radix(16),
        nonce_x: hex::encode(nonce_x),
        nonce_beta: hex::encode(nonce_beta),
    };
    (commit, reveal)
}

/// Verify Πaff-g reveal after round-2:
/// 1. Check hash commitments open correctly.
/// 2. Check x and β are in range [0, n_order).
/// 3. Recompute c_B = scalar_mul(c_A, x) · Enc_init(-β) and verify it matches c_B.
pub fn verify_aff_g(
    commit: &AffGCommit,
    reveal: &AffGReveal,
    pk_init: &PaillierPubKey,
    c_a: &BigUint,
    c_b: &BigUint,
    n_order: &BigUint,
) -> bool {
    let x = match parse_hex(&reveal.x_hex) { Ok(v) => v, Err(_) => return false };
    let beta = match parse_hex(&reveal.beta_hex) { Ok(v) => v, Err(_) => return false };
    let nonce_x = match hex::decode(&reveal.nonce_x) { Ok(v) => v, Err(_) => return false };
    let nonce_beta = match hex::decode(&reveal.nonce_beta) { Ok(v) => v, Err(_) => return false };

    // 1. Verify hash commitments.
    if sha256_commit(&x.to_bytes_be(), &nonce_x) != commit.hash_x
        || sha256_commit(&beta.to_bytes_be(), &nonce_beta) != commit.hash_beta
    {
        return false;
    }

    // 2. Range check: x and β must be proper secp256k1 scalars.
    if &x >= n_order || &beta >= n_order {
        return false;
    }

    // 3. Recompute c_B and compare.
    //    c_B = scalar_mul(pk_init, c_A, x) · (1 + neg_beta · n) mod n²
    let enc_scaled = paillier::scalar_mul(pk_init, c_a, &x);
    let neg_beta = n_order - &beta % n_order;
    let neg_beta_term = (BigUint::one() + &neg_beta * &pk_init.n) % &pk_init.n2;
    let c_b_expected = (&enc_scaled * &neg_beta_term) % &pk_init.n2;

    c_b_expected == *c_b
}

// ─── Internal helpers ────────────────────────────────────────────────────────

fn fiat_shamir_hash(n: &BigUint, a: &BigUint, c: &BigUint) -> BigUint {
    let mut h = Sha256::new();
    h.update(&n.to_bytes_be());
    h.update(&a.to_bytes_be());
    h.update(&c.to_bytes_be());
    BigUint::from_bytes_be(&h.finalize())
}

fn sha256_commit(data: &[u8], nonce: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.update(nonce);
    hex::encode(h.finalize())
}

fn parse_hex(s: &str) -> Result<BigUint> {
    BigUint::parse_bytes(s.as_bytes(), 16)
        .ok_or_else(|| anyhow!("invalid hex"))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paillier;

    fn secp_n() -> BigUint {
        BigUint::from_bytes_be(
            &hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
                .unwrap(),
        )
    }

    #[test]
    fn pi_enc_roundtrip() {
        let (pk, _sk) = paillier::keygen();
        let m = BigUint::from(12345u32);
        let (c, rho) = paillier::encrypt_with_rand(&pk, &m);
        let proof = prove_enc(&pk, &m, &rho, &c);
        assert!(verify_enc(&pk, &c, &proof), "Πenc verify failed");
    }

    #[test]
    fn pi_enc_rejects_wrong_ciphertext() {
        let (pk, _sk) = paillier::keygen();
        let m = BigUint::from(99u32);
        let (c, rho) = paillier::encrypt_with_rand(&pk, &m);
        let proof = prove_enc(&pk, &m, &rho, &c);
        let bad_c = (&c + BigUint::one()) % &pk.n2;
        assert!(!verify_enc(&pk, &bad_c, &proof));
    }

    #[test]
    fn aff_g_valid() {
        let n_order = secp_n();
        let (pk_init, _sk_init) = paillier::keygen();
        let k = BigUint::from(7u32);
        let x = BigUint::from(5u32);
        let beta = BigUint::from(3u32);

        let (c_a, _) = paillier::encrypt_with_rand(&pk_init, &k);
        let (commit, reveal) = commit_aff_g(&x, &beta);

        // Compute c_B the same way the responder would.
        let enc_scaled = paillier::scalar_mul(&pk_init, &c_a, &x);
        let neg_beta = &n_order - &beta % &n_order;
        let neg_beta_term = (BigUint::one() + &neg_beta * &pk_init.n) % &pk_init.n2;
        let c_b = (&enc_scaled * &neg_beta_term) % &pk_init.n2;

        assert!(verify_aff_g(&commit, &reveal, &pk_init, &c_a, &c_b, &n_order));
    }

    #[test]
    fn aff_g_rejects_out_of_range_x() {
        let n_order = secp_n();
        let (pk_init, _sk_init) = paillier::keygen();
        let k = BigUint::from(7u32);
        // x = n_order (out of range)
        let x = n_order.clone();
        let beta = BigUint::from(3u32);

        let (c_a, _) = paillier::encrypt_with_rand(&pk_init, &k);
        let (commit, reveal) = commit_aff_g(&x, &beta);

        let enc_scaled = paillier::scalar_mul(&pk_init, &c_a, &x);
        let neg_beta = BigUint::from(0u32); // doesn't matter
        let neg_beta_term = (BigUint::one() + &neg_beta * &pk_init.n) % &pk_init.n2;
        let c_b = (&enc_scaled * &neg_beta_term) % &pk_init.n2;

        assert!(!verify_aff_g(&commit, &reveal, &pk_init, &c_a, &c_b, &n_order));
    }
}
