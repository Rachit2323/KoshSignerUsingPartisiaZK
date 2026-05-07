mod grpc_server;
mod relay;
mod state_decode;

use grpc_server::{
    pb::chain_relay_server::ChainRelayServer,
    ChainRelayService,
};
use relay::ChainRelay;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "50053".to_string());
    let addr = format!("0.0.0.0:{port}").parse()?;

    let relay = ChainRelay::from_env()?;
    let service = ChainRelayService::new(relay);

    tracing::info!("kosh-chain-relay listening on {addr}");

    Server::builder()
        .add_service(ChainRelayServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
