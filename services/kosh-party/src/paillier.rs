/// 2048-bit Paillier homomorphic encryption with persisted per-party keypairs.
/// Keys are generated once per party and then reused across sign sessions.

use anyhow::{Context, Result};
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

use crate::types::{PaillierPrivKey, PaillierPubKey};

const PRIME_BITS: usize = 1024; // p, q are 1024-bit -> n is 2048-bit

#[derive(Serialize, Deserialize)]
struct StoredKeyPair {
    n_hex: String,
    n2_hex: String,
    g_hex: String,
    lambda_hex: String,
    mu_hex: String,
}

pub fn keygen() -> (PaillierPubKey, PaillierPrivKey) {
    let p = generate_prime(PRIME_BITS);
    let q = loop {
        let q = generate_prime(PRIME_BITS);
        if q != p {
            break q;
        }
    };

    let n = &p * &q;
    let n2 = &n * &n;
    let g = &n + BigUint::one(); // g = n+1 (simplified Paillier)

    let lambda = lcm(&(p - BigUint::one()), &(q - BigUint::one()));
    // mu = lambda^{-1} mod n
    let mu = mod_inverse(&lambda, &n).expect("lambda must be invertible mod n");

    let pk = PaillierPubKey { n: n.clone(), n2: n2.clone(), g };
    let sk = PaillierPrivKey { lambda, mu };
    (pk, sk)
}

pub fn load_or_generate(root: &str, party_index: u32) -> Result<(PaillierPubKey, PaillierPrivKey)> {
    let root = PathBuf::from(root);
    fs::create_dir_all(&root)
        .with_context(|| format!("create paillier dir {}", root.display()))?;
    let path = root.join(format!("paillier-party-{party_index}.json"));
    if path.exists() {
        let bytes = fs::read(&path)
            .with_context(|| format!("read paillier keypair {}", path.display()))?;
        let stored: StoredKeyPair =
            serde_json::from_slice(&bytes).context("decode stored paillier keypair")?;
        let public_key = PaillierPubKey {
            n: parse_biguint_hex(&stored.n_hex)?,
            n2: parse_biguint_hex(&stored.n2_hex)?,
            g: parse_biguint_hex(&stored.g_hex)?,
        };
        let private_key = PaillierPrivKey {
            lambda: parse_biguint_hex(&stored.lambda_hex)?,
            mu: parse_biguint_hex(&stored.mu_hex)?,
        };
        return Ok((public_key, private_key));
    }

    let (public_key, private_key) = keygen();
    let stored = StoredKeyPair {
        n_hex: public_key.n.to_str_radix(16),
        n2_hex: public_key.n2.to_str_radix(16),
        g_hex: public_key.g.to_str_radix(16),
        lambda_hex: private_key.lambda.to_str_radix(16),
        mu_hex: private_key.mu.to_str_radix(16),
    };
    fs::write(&path, serde_json::to_vec_pretty(&stored)?)
        .with_context(|| format!("write paillier keypair {}", path.display()))?;
    Ok((public_key, private_key))
}

fn parse_biguint_hex(input: &str) -> Result<BigUint> {
    BigUint::parse_bytes(input.as_bytes(), 16)
        .ok_or_else(|| anyhow::anyhow!("invalid BigUint hex"))
}

pub fn encrypt(pk: &PaillierPubKey, m: &BigUint) -> BigUint {
    let mut rng = OsRng;
    let r = loop {
        let r = rng.gen_biguint_below(&pk.n);
        if r.gcd(&pk.n).is_one() {
            break r;
        }
    };
    // c = g^m · r^n mod n²  =  (1 + m·n) · r^n mod n²
    let gm = (BigUint::one() + m * &pk.n) % &pk.n2;
    let rn = r.modpow(&pk.n, &pk.n2);
    (gm * rn) % &pk.n2
}

pub fn decrypt(pk: &PaillierPubKey, sk: &PaillierPrivKey, c: &BigUint) -> BigUint {
    // L(c^lambda mod n²) · mu mod n
    let u = c.modpow(&sk.lambda, &pk.n2);
    let l = l_function(&u, &pk.n);
    (l * &sk.mu) % &pk.n
}

/// Homomorphic addition: Enc(a) · Enc(b) mod n² = Enc(a+b)
pub fn add_ciphertexts(pk: &PaillierPubKey, c1: &BigUint, c2: &BigUint) -> BigUint {
    (c1 * c2) % &pk.n2
}

/// Homomorphic scalar mul: c^k mod n² = Enc(k·m)
pub fn scalar_mul(pk: &PaillierPubKey, c: &BigUint, k: &BigUint) -> BigUint {
    c.modpow(k, &pk.n2)
}

/// Enc(m + k) = Enc(m) · g^k mod n² = c · (1 + k·n) mod n²
pub fn add_plaintext(pk: &PaillierPubKey, c: &BigUint, k: &BigUint) -> BigUint {
    let gk = (BigUint::one() + k * &pk.n) % &pk.n2;
    (c * gk) % &pk.n2
}

// ─── Internal helpers ───────────────────────────────────────────────────────

fn l_function(u: &BigUint, n: &BigUint) -> BigUint {
    (u - BigUint::one()) / n
}

fn lcm(a: &BigUint, b: &BigUint) -> BigUint {
    a / a.gcd(b) * b
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    // Extended Euclidean algorithm
    let (mut old_r, mut r) = (a.clone(), m.clone());
    let (mut old_s, mut s) = (BigUint::one(), BigUint::zero());

    while !r.is_zero() {
        let quotient = &old_r / &r;
        let tmp_r = old_r.clone() - &quotient * &r;
        old_r = r;
        r = tmp_r;
        // Use signed arithmetic via modular subtraction
        let tmp_s = mod_sub(&old_s, &((&quotient * &s) % m), m);
        old_s = s;
        s = tmp_s;
    }
    if old_r != BigUint::one() {
        return None;
    }
    Some(old_s % m)
}

fn mod_sub(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % m
    } else {
        (m - (b - a) % m) % m
    }
}

fn generate_prime(bits: usize) -> BigUint {
    let mut rng = OsRng;
    loop {
        let mut candidate = rng.gen_biguint(bits as u64);
        candidate |= BigUint::one();
        candidate |= BigUint::one() << (bits - 1);
        if is_probably_prime(&candidate, 16) {
            return candidate;
        }
    }
}

fn is_probably_prime(n: &BigUint, rounds: usize) -> bool {
    if n < &BigUint::from(2u32) {
        return false;
    }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Write n-1 as 2^r * d
    let n_minus_1 = n - BigUint::one();
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    let mut rng = OsRng;
    'outer: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - BigUint::one()));
        let mut x = a.modpow(&d, n);
        if x == BigUint::one() || x == n_minus_1 {
            continue;
        }
        for _ in 0..r - 1 {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n_minus_1 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::ToPrimitive;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let (pk, sk) = keygen();
        let m = BigUint::from(42u32);
        let c = encrypt(&pk, &m);
        let m2 = decrypt(&pk, &sk, &c);
        assert_eq!(m, m2);
    }

    #[test]
    fn homomorphic_add() {
        let (pk, sk) = keygen();
        let m1 = BigUint::from(7u32);
        let m2 = BigUint::from(13u32);
        let c1 = encrypt(&pk, &m1);
        let c2 = encrypt(&pk, &m2);
        let c_sum = add_ciphertexts(&pk, &c1, &c2);
        let result = decrypt(&pk, &sk, &c_sum);
        assert_eq!(result, BigUint::from(20u32));
    }

    #[test]
    fn homomorphic_scalar_mul() {
        let (pk, sk) = keygen();
        let m = BigUint::from(5u32);
        let k = BigUint::from(4u32);
        let c = encrypt(&pk, &m);
        let c_k = scalar_mul(&pk, &c, &k);
        let result = decrypt(&pk, &sk, &c_k);
        assert_eq!(result.to_u32().unwrap(), 20);
    }
}
