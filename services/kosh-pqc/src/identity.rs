use crate::rng::SystemRng;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ml_dsa::{KeyGen, MlDsa65, SigningKey};
use ml_kem::{
    DecapsulationKey768, Decapsulate, EncapsulationKey768, Encapsulate, KeyExport, MlKem768,
    Seed, kem::Kem,
};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Persisted key material: both keys stored as seeds (32/64 bytes).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentityFile {
    pub kem_seed_b64: String, // 64-byte ML-KEM seed → deterministic dk + ek
    pub dsa_seed_b64: String, // 32-byte ML-DSA seed → deterministic signing key
}

pub struct Identity {
    pub kem_dk: DecapsulationKey768,
    pub kem_ek: EncapsulationKey768,
    pub dsa_sk: SigningKey<MlDsa65>,
}

impl Identity {
    pub fn load_or_generate(path: &str) -> Result<Self> {
        if Path::new(path).exists() {
            Self::load(path).context("failed to load PQC identity")
        } else {
            let id = Self::generate();
            id.save(path)?;
            tracing::info!("generated new PQC identity → {}", path);
            Ok(id)
        }
    }

    fn generate() -> Self {
        use ml_dsa::signature::rand_core::UnwrapErr;
        let (kem_dk, kem_ek) = MlKem768::generate_keypair();
        let mut rng = UnwrapErr(SystemRng);
        let dsa_sk = MlDsa65::key_gen(&mut rng);
        Self { kem_dk, kem_ek, dsa_sk }
    }

    fn save(&self, path: &str) -> Result<()> {
        let kem_seed = self.kem_dk.to_seed().expect("key must have seed");
        let dsa_seed: [u8; 32] = self.dsa_sk.to_seed().into();
        let file = IdentityFile {
            kem_seed_b64: B64.encode(kem_seed.as_slice()),
            dsa_seed_b64: B64.encode(&dsa_seed),
        };
        fs::write(path, serde_json::to_string_pretty(&file)?)?;
        Ok(())
    }

    fn load(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path)?;
        let file: IdentityFile = serde_json::from_str(&raw)?;

        let kem_seed_bytes = B64.decode(&file.kem_seed_b64)?;
        let kem_seed: Seed = kem_seed_bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("KEM seed must be 64 bytes, got {}", kem_seed_bytes.len())
        })?;
        let kem_dk = DecapsulationKey768::from_seed(kem_seed);
        let kem_ek = kem_dk.encapsulation_key().clone();

        let dsa_seed_bytes = B64.decode(&file.dsa_seed_b64)?;
        let dsa_seed_arr: [u8; 32] = dsa_seed_bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("DSA seed must be 32 bytes, got {}", dsa_seed_bytes.len())
        })?;
        let dsa_seed = ml_dsa::Seed::from(dsa_seed_arr);
        let dsa_sk = MlDsa65::from_seed(&dsa_seed);

        Ok(Self { kem_dk, kem_ek, dsa_sk })
    }

    pub fn public_keys(&self) -> (String, String) {
        let kem_pk_bytes: Vec<u8> = self.kem_ek.to_bytes().to_vec();
        let kem_pk = B64.encode(&kem_pk_bytes);
        let dsa_vk = self.dsa_sk.signing_key().verifying_key();
        let dsa_vk_enc = dsa_vk.encode();
        let dsa_pk = B64.encode(dsa_vk_enc.as_ref() as &[u8]);
        (kem_pk, dsa_pk)
    }

    pub fn encapsulate_to(&self, recipient_ek_b64: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let pk_bytes = B64.decode(recipient_ek_b64)?;
        if pk_bytes.len() != 1184 {
            anyhow::bail!("invalid ek: expected 1184 bytes, got {}", pk_bytes.len());
        }
        let pk_key = ml_kem::Key::<EncapsulationKey768>::try_from(pk_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("failed to convert pk bytes to array"))?;
        let ek = EncapsulationKey768::new(&pk_key)
            .map_err(|e| anyhow::anyhow!("invalid encapsulation key: {:?}", e))?;
        let (ct, ss) = ek.encapsulate_with_rng(&mut SystemRng);
        let ct_vec: Vec<u8> = <ml_kem::ml_kem_768::Ciphertext as AsRef<[u8]>>::as_ref(&ct).to_vec();
        let ss_vec: Vec<u8> = <ml_kem::SharedKey as AsRef<[u8]>>::as_ref(&ss).to_vec();
        Ok((ct_vec, ss_vec))
    }

    pub fn decapsulate_ct(&self, ct_bytes: &[u8]) -> Result<Vec<u8>> {
        use ml_kem::ml_kem_768::Ciphertext;
        let arr: [u8; 1088] = ct_bytes.try_into().map_err(|_| {
            anyhow::anyhow!(
                "invalid ciphertext: expected 1088 bytes, got {}",
                ct_bytes.len()
            )
        })?;
        let ct = Ciphertext::from(arr);
        let ss = self.kem_dk.decapsulate(&ct);
        let ss_vec: Vec<u8> = <ml_kem::SharedKey as AsRef<[u8]>>::as_ref(&ss).to_vec();
        Ok(ss_vec)
    }
}
