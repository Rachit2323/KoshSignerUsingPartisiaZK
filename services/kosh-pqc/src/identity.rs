use anyhow::{Context, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ml_dsa::{KeyGen, MlDsa65, SigningKey};
use ml_dsa::signature::{Keypair, rand_core::UnwrapErr};
use ml_kem::{DecapsulationKey768, EncapsulationKey768, Encapsulate, Decapsulate, KeyExport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::rng::{SystemRng, fill};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentityFile {
    pub kem_seed_b64: String,  // 64-byte raw seed
    pub dsa_seed_b64: String,  // 32-byte raw seed
}

#[derive(Serialize, Deserialize)]
struct EncryptedIdentityFile {
    nonce_b64: String,
    ciphertext_b64: String,
}

pub struct Identity {
    kem_seed: [u8; 64],               // kept so save() can serialize it
    pub kem_dk: DecapsulationKey768,
    pub kem_ek: EncapsulationKey768,
    pub dsa_sk: SigningKey<MlDsa65>,
}

impl Identity {
    pub fn load_or_generate(path: &str, encryption_key: Option<&str>) -> Result<Self> {
        if Path::new(path).exists() {
            Self::load(path, encryption_key).context("failed to load PQC identity")
        } else {
            let id = Self::generate();
            id.save(path, encryption_key)?;
            tracing::info!("generated new PQC identity → {}", path);
            Ok(id)
        }
    }

    fn generate() -> Self {
        let mut kem_seed = [0u8; 64];
        fill(&mut kem_seed);
        let kem_dk = DecapsulationKey768::from_seed(kem_seed.into());
        let kem_ek = kem_dk.encapsulation_key().clone();
        let mut rng = UnwrapErr(SystemRng);
        let dsa_sk = MlDsa65::key_gen(&mut rng);
        Self { kem_seed, kem_dk, kem_ek, dsa_sk }
    }

    fn save(&self, path: &str, encryption_key: Option<&str>) -> Result<()> {
        let dsa_seed = self.dsa_sk.to_seed();
        let dsa_seed_bytes: &[u8] = dsa_seed.as_ref();
        let file = IdentityFile {
            kem_seed_b64: B64.encode(&self.kem_seed),
            dsa_seed_b64: B64.encode(dsa_seed_bytes),
        };
        let plaintext = serde_json::to_vec_pretty(&file)?;
        if let Some(key) = encryption_key {
            let key_bytes = decode_master_key(key)?;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
            let nonce_bytes = derive_nonce(path, &plaintext);
            let ciphertext = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
                .map_err(|_| anyhow::anyhow!("encrypt PQC identity"))?;
            let envelope = EncryptedIdentityFile {
                nonce_b64: B64.encode(nonce_bytes),
                ciphertext_b64: B64.encode(ciphertext),
            };
            fs::write(path, serde_json::to_string_pretty(&envelope)?)?;
        } else {
            fs::write(path, plaintext)?;
        }
        Ok(())
    }

    fn load(path: &str, encryption_key: Option<&str>) -> Result<Self> {
        let raw = fs::read_to_string(path)?;
        let file: IdentityFile = if let Some(key) = encryption_key {
            match serde_json::from_str::<EncryptedIdentityFile>(&raw) {
                Ok(envelope) => {
                    let key_bytes = decode_master_key(key)?;
                    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
                    let nonce = B64.decode(&envelope.nonce_b64)?;
                    let ciphertext = B64.decode(&envelope.ciphertext_b64)?;
                    let plaintext = cipher
                        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
                        .map_err(|_| anyhow::anyhow!("decrypt PQC identity"))?;
                    serde_json::from_slice(&plaintext)?
                }
                Err(_) => serde_json::from_str(&raw)?,
            }
        } else {
            serde_json::from_str(&raw)?
        };

        let kem_seed_bytes = B64.decode(&file.kem_seed_b64)?;
        let kem_seed: [u8; 64] = kem_seed_bytes.as_slice().try_into()
            .map_err(|_| anyhow::anyhow!("invalid KEM seed: expected 64 bytes, got {}", kem_seed_bytes.len()))?;
        let kem_dk = DecapsulationKey768::from_seed(kem_seed.into());
        let kem_ek = kem_dk.encapsulation_key().clone();

        let dsa_seed_bytes = B64.decode(&file.dsa_seed_b64)?;
        let dsa_seed: [u8; 32] = dsa_seed_bytes.as_slice().try_into()
            .map_err(|_| anyhow::anyhow!("invalid DSA seed: expected 32 bytes, got {}", dsa_seed_bytes.len()))?;
        let dsa_sk = MlDsa65::from_seed((&dsa_seed).into());

        Ok(Self { kem_seed, kem_dk, kem_ek, dsa_sk })
    }

    pub fn public_keys(&self) -> (String, String) {
        let kem_pk_bytes = self.kem_ek.to_bytes();
        let kem_pk = B64.encode(kem_pk_bytes.as_ref() as &[u8]);
        let dsa_vk = self.dsa_sk.verifying_key();
        let dsa_pk = B64.encode(dsa_vk.encode().as_ref() as &[u8]);
        (kem_pk, dsa_pk)
    }

    pub fn encapsulate_to(&self, recipient_ek_b64: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let pk_bytes = B64.decode(recipient_ek_b64)?;
        let ek = EncapsulationKey768::new(
            pk_bytes.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("invalid EK: expected 1184 bytes, got {}", pk_bytes.len()))?,
        ).map_err(|_| anyhow::anyhow!("invalid encapsulation key"))?;
        let (ct, ss) = ek.encapsulate();
        let ct_bytes: &[u8] = ct.as_ref();
        let ss_bytes: &[u8] = ss.as_ref();
        Ok((ct_bytes.to_vec(), ss_bytes.to_vec()))
    }

    pub fn decapsulate_ct(&self, ct_bytes: &[u8]) -> Result<Vec<u8>> {
        use ml_kem::kem::Ciphertext;
        use ml_kem::MlKem768;
        let ct = Ciphertext::<MlKem768>::from(
            <[u8; 1088]>::try_from(ct_bytes)
                .map_err(|_| anyhow::anyhow!("ciphertext must be 1088 bytes, got {}", ct_bytes.len()))?,
        );
        let ss = self.kem_dk.decapsulate(&ct);
        let ss_bytes: &[u8] = ss.as_ref();
        Ok(ss_bytes.to_vec())
    }
}

fn decode_master_key(input: &str) -> Result<[u8; 32]> {
    let trimmed = input.trim();
    let bytes = if let Some(hex) = trimmed.strip_prefix("0x") {
        hex::decode(hex)?
    } else if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(trimmed)?
    } else {
        B64.decode(trimmed)?
    };
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("PQC_KEY_FILE_KEY must be 32 bytes"))
}

fn derive_nonce(path: &str, plaintext: &[u8]) -> [u8; 12] {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    hasher.update(plaintext);
    let digest = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::Identity;
    use std::time::{SystemTime, UNIX_EPOCH};

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn tmp_file(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("kosh-pqc-{name}-{nanos}.json"))
            .display()
            .to_string()
    }

    #[test]
    fn encrypted_identity_roundtrip_hides_plaintext_fields() {
        let path = tmp_file("enc");
        let identity = Identity::load_or_generate(&path, Some(KEY)).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("ciphertext_b64"));
        assert!(!raw.contains("kem_seed_b64"));

        let loaded = Identity::load_or_generate(&path, Some(KEY)).unwrap();
        assert_eq!(identity.public_keys(), loaded.public_keys());
    }

    #[test]
    fn encrypted_identity_wrong_key_fails() {
        let path = tmp_file("wrong-key");
        Identity::load_or_generate(&path, Some(KEY)).unwrap();
        let wrong_key =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(Identity::load_or_generate(&path, Some(wrong_key)).is_err());
    }
}
