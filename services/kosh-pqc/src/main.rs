mod identity;
mod rng;
mod service;

pub mod pb {
    tonic::include_proto!("kosh.pqc");
}

use identity::Identity;
use pb::pqc_service_server::PqcServiceServer;
use service::PqcServiceImpl;
use std::sync::Arc;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "50080".into());
    let pqc_key_file =
        std::env::var("PQC_KEY_FILE").unwrap_or_else(|_| "/tmp/kosh-pqc-identity.json".into());
    let pqc_key_file_key = std::env::var("PQC_KEY_FILE_KEY")
        .ok()
        .or_else(|| std::env::var("SHARE_FILE_KEY").ok());

    let identity = Identity::load_or_generate(&pqc_key_file, pqc_key_file_key.as_deref())?;
    let (kem_pk, dsa_pk) = identity.public_keys();
    tracing::info!("PQC identity ready");
    tracing::info!("  kyber_pk     = {}...", &kem_pk[..16]);
    tracing::info!("  dilithium_pk = {}...", &dsa_pk[..16]);
    if pqc_key_file_key.is_some() {
        tracing::info!("  storage      = AES-256-GCM encrypted at rest");
    } else {
        tracing::warn!("  storage      = plaintext seed file (set PQC_KEY_FILE_KEY or SHARE_FILE_KEY to encrypt at rest)");
    }

    let addr = format!("0.0.0.0:{}", port).parse()?;
    tracing::info!("kosh-pqc listening on {}", addr);

    Server::builder()
        .add_service(PqcServiceServer::new(PqcServiceImpl {
            identity: Arc::new(identity),
        }))
        .serve(addr)
        .await?;

    Ok(())
}
