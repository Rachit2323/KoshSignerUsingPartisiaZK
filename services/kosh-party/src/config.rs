use anyhow::{bail, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub party_index: u32,
    pub num_parties: u32,
    pub coordinator_addr: String,
    pub keystore_addr: String,
    pub pqc_addr: String,
    pub chain_relay_addr: String,
    pub signer_address: String,
    /// Directory where AES-256-GCM encrypted key shares are stored on disk.
    pub keystore_dir: String,
    /// 32-byte hex master key for encrypting/decrypting key shares.
    pub keystore_master_key: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let party_index: u32 = std::env::var("PARTY_INDEX")
            .unwrap_or_else(|_| "1".into())
            .parse()?;
        if party_index == 0 {
            bail!("PARTY_INDEX must be >= 1");
        }
        Ok(Self {
            port: std::env::var("PORT").unwrap_or_else(|_| "50060".into()).parse()?,
            party_index,
            num_parties: std::env::var("NUM_PARTIES").unwrap_or_else(|_| "3".into()).parse()?,
            coordinator_addr: std::env::var("COORDINATOR_ADDR")
                .unwrap_or_else(|_| "http://localhost:50051".into()),
            keystore_addr: std::env::var("KEYSTORE_ADDR")
                .unwrap_or_else(|_| "http://localhost:50070".into()),
            pqc_addr: std::env::var("PQC_ADDR")
                .unwrap_or_else(|_| "http://localhost:50080".into()),
            chain_relay_addr: std::env::var("CHAIN_RELAY_ADDR")
                .unwrap_or_else(|_| "http://localhost:50053".into()),
            signer_address: std::env::var("SIGNER_ADDRESS").unwrap_or_default(),
            keystore_dir: std::env::var("KEYSTORE_DIR")
                .unwrap_or_else(|_| ".kosh-shares".into()),
            keystore_master_key: std::env::var("KEYSTORE_MASTER_KEY").unwrap_or_default(),
        })
    }
}
