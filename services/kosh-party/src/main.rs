mod bulletin_board;
mod config;
mod dkg;
mod gg20;
mod mta;
mod paillier;
mod phase;
mod types;

use anyhow::Result;
use config::Config;
use phase::party_pb::{
    party_service_server::{PartyService, PartyServiceServer},
    DkgEvent, DkgRequest, SignEvent, SignRequest, StatusRequest, StatusResponse,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};
use tracing_subscriber::EnvFilter;

struct PartyServiceImpl {
    cfg: Arc<Config>,
}

#[tonic::async_trait]
impl PartyService for PartyServiceImpl {
    type StartDkgStream = ReceiverStream<Result<DkgEvent, Status>>;
    type StartSignStream = ReceiverStream<Result<SignEvent, Status>>;

    async fn start_dkg(
        &self,
        req: Request<DkgRequest>,
    ) -> Result<Response<Self::StartDkgStream>, Status> {
        let r = req.into_inner();
        let cfg = Arc::clone(&self.cfg);
        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            if let Err(e) = phase::run_dkg(&cfg, r.key_id, r.num_parties, r.threshold, tx.clone()).await {
                let _ = tx
                    .send(Ok(DkgEvent {
                        phase: phase::party_pb::dkg_event::Phase::DkgFailed as i32,
                        message: e.to_string(),
                    }))
                    .await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn start_sign(
        &self,
        req: Request<SignRequest>,
    ) -> Result<Response<Self::StartSignStream>, Status> {
        let r = req.into_inner();
        let cfg = Arc::clone(&self.cfg);
        let (tx, rx) = mpsc::channel(32);

        let message_hash: [u8; 32] = r
            .message_hash
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("message_hash must be 32 bytes"))?;

        // In a full impl, x_i would be fetched from keystore via gRPC.
        // For the service skeleton, use a placeholder derived from party_index + key_id.
        let x_i = derive_x_i_placeholder(cfg.party_index, r.key_id);
        let signing_subset: Vec<u32> = r.signing_subset.iter().map(|&x| x as u32).collect();
        let task_id = r.key_id; // simplified; real impl fetches from keystore

        tokio::spawn(async move {
            if let Err(e) = phase::run_sign(
                &cfg, r.key_id, message_hash, r.tx_tag, signing_subset, task_id, x_i, tx.clone(),
            )
            .await
            {
                let _ = tx
                    .send(Ok(SignEvent {
                        phase: phase::party_pb::sign_event::Phase::SignFailed as i32,
                        message: e.to_string(),
                        signature: vec![],
                    }))
                    .await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_status(
        &self,
        _req: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Ok(Response::new(StatusResponse {
            party_index: self.cfg.party_index,
            current_phase: "Idle".to_string(),
            active_key_ids: vec![],
        }))
    }
}

/// Deterministic x_i placeholder for testing without a running keystore.
fn derive_x_i_placeholder(party_index: u32, key_id: u32) -> k256::Scalar {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"kosh-test-share");
    h.update(party_index.to_le_bytes());
    h.update(key_id.to_le_bytes());
    dkg::scalar_from_bytes_mod_n(&h.finalize())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = Config::from_env()?;
    let addr = format!("0.0.0.0:{}", cfg.port).parse()?;

    tracing::info!(
        "kosh-party {} listening on {} (coordinator={})",
        cfg.party_index, addr, cfg.coordinator_addr
    );

    let svc = PartyServiceImpl { cfg: Arc::new(cfg) };

    Server::builder()
        .add_service(PartyServiceServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
