use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ml_dsa::signature::rand_core::{Infallible, TryCryptoRng, TryRng};
use ml_dsa::{KeyGen, MlDsa65};
use ml_kem::{KeyExport, MlKem768};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PqcIdentityFile {
    kyber_public_key_b64: String,
    dilithium_public_key_b64: String,
}

#[derive(Debug, Clone)]
pub struct PqcIdentity {
    file: PqcIdentityFile,
}

impl PqcIdentity {
    pub fn load_or_generate(root: &str, party_index: u8) -> Result<Self> {
        let root = PathBuf::from(root);
        fs::create_dir_all(&root)
            .with_context(|| format!("create pqc identity dir {}", root.display()))?;
        let path = root.join(format!("pqc-identity-party-{party_index}.json"));
        if path.exists() {
            let bytes = fs::read(&path)
                .with_context(|| format!("read pqc identity {}", path.display()))?;
            let file: PqcIdentityFile =
                serde_json::from_slice(&bytes).context("decode stored PQC identity")?;
            return Ok(Self { file });
        }

        let identity = Self::generate()?;
        fs::write(&path, serde_json::to_vec_pretty(&identity.file)?)
            .with_context(|| format!("write pqc identity {}", path.display()))?;
        Ok(identity)
    }

    pub fn kyber_public_key(&self) -> Result<Vec<u8>> {
        Ok(B64.decode(&self.file.kyber_public_key_b64)?)
    }

    pub fn dilithium_public_key(&self) -> Result<Vec<u8>> {
        Ok(B64.decode(&self.file.dilithium_public_key_b64)?)
    }

    fn generate() -> Result<Self> {
        use ml_dsa::signature::rand_core::UnwrapErr;
        use ml_kem::kem::Kem;

        let (_kem_dk, kem_ek) = MlKem768::generate_keypair();
        let mut rng = UnwrapErr(SystemRng);
        let dsa_sk = MlDsa65::key_gen(&mut rng);
        let kem_ek_bytes = kem_ek.to_bytes();
        let dsa_vk_bytes = dsa_sk.signing_key().verifying_key().encode();
        let file = PqcIdentityFile {
            kyber_public_key_b64: B64.encode(&kem_ek_bytes[..]),
            dilithium_public_key_b64: B64.encode(&dsa_vk_bytes[..]),
        };
        Ok(Self { file })
    }
}

pub struct SystemRng;

impl TryRng for SystemRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut buf = [0u8; 4];
        fill(&mut buf);
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut buf = [0u8; 8];
        fill(&mut buf);
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        fill(dest);
        Ok(())
    }
}

impl TryCryptoRng for SystemRng {}

fn fill(buf: &mut [u8]) {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .expect("cannot open /dev/urandom")
        .read_exact(buf)
        .expect("urandom read failed");
}
