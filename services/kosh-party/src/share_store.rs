/// AES-256-GCM encrypted storage for Shamir key shares.
/// Each party stores its own share: runtime-contract-{addr}-key-{id}-party-{idx}.json
/// Same format as backend/src/keystore/ so shares are cross-compatible.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::{Path, PathBuf}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedShare {
    pub contract_address: String,
    pub key_id: u32,
    pub party_index: u8,
    pub public_key_hex: String,   // combined public key (all parties' shares combined)
    pub shamir_share_hex: String, // x_i — this party's Shamir share scalar
    pub next_task_id: u32,
    pub runtime_version: String,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    nonce_b64: String,
    ciphertext_b64: String,
    meta_party: u8,
    meta_key_id: u32,
    meta_contract: String,
}

pub struct ShareStore {
    root: PathBuf,
    cipher: Aes256Gcm,
}

impl ShareStore {
    pub fn new(root: impl Into<PathBuf>, master_key_hex: &str) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)
            .with_context(|| format!("create share store dir {}", root.display()))?;
        let key_bytes = decode_master_key(master_key_hex)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        Ok(Self { root, cipher })
    }

    fn share_path(&self, contract: &str, key_id: u32, party_index: u8) -> PathBuf {
        self.root.join(format!(
            "runtime-contract-{contract}-key-{key_id}-party-{party_index}.json"
        ))
    }

    pub fn save(&self, share: &PersistedShare) -> Result<PathBuf> {
        let path = self.share_path(&share.contract_address, share.key_id, share.party_index);
        let plaintext = serde_json::to_vec_pretty(share)?;
        let nonce_bytes = derive_nonce(&share.contract_address, share.key_id, share.party_index);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self.cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|_| anyhow!("encrypt share"))?;
        let envelope = Envelope {
            nonce_b64: B64.encode(nonce_bytes),
            ciphertext_b64: B64.encode(ciphertext),
            meta_party: share.party_index,
            meta_key_id: share.key_id,
            meta_contract: share.contract_address.clone(),
        };
        fs::write(&path, serde_json::to_vec_pretty(&envelope)?)?;
        tracing::info!("share saved → {}", path.display());
        Ok(path)
    }

    pub fn load(&self, contract: &str, key_id: u32, party_index: u8) -> Result<PersistedShare> {
        let path = self.share_path(contract, key_id, party_index);
        let bytes = fs::read(&path)
            .with_context(|| format!("read share file {}", path.display()))?;
        let envelope: Envelope = serde_json::from_slice(&bytes)?;
        let nonce_bytes = B64.decode(envelope.nonce_b64)?;
        let ciphertext = B64.decode(envelope.ciphertext_b64)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = self.cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| anyhow!("decrypt share — wrong master key?"))?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    pub fn exists(&self, contract: &str, key_id: u32, party_index: u8) -> bool {
        self.share_path(contract, key_id, party_index).exists()
    }

    pub fn root(&self) -> &Path {
        &self.root
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
    let arr: [u8; 32] = bytes.try_into()
        .map_err(|_| anyhow!("KEYSTORE_MASTER_KEY must be 32 bytes (64 hex chars)"))?;
    Ok(arr)
}

fn derive_nonce(contract: &str, key_id: u32, party_index: u8) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(contract.as_bytes());
    h.update(key_id.to_be_bytes());
    h.update([party_index]);
    let digest = h.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}
