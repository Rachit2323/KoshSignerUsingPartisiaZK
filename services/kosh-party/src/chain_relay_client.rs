/// gRPC client for kosh-chain-relay.
/// Wraps submit() and get_contract_state() with helpers for the DKG/signing ceremony.

use anyhow::{anyhow, Result};
use serde_json::Value;
use tokio_stream::StreamExt;
use tonic::transport::Channel;

mod relay_pb {
    tonic::include_proto!("kosh.relay");
}

use relay_pb::{
    chain_relay_client::ChainRelayClient as RelayGrpc,
    GetContractStateRequest, SubmitRequest, SubmitZkInputRequest,
    tx_event::Status as TxStatus,
};

pub struct ChainRelayClient {
    inner: RelayGrpc<Channel>,
}

impl ChainRelayClient {
    pub async fn connect(addr: &str) -> Result<Self> {
        let inner = RelayGrpc::connect(addr.to_string()).await?;
        Ok(Self { inner })
    }

    /// Submit a contract action and wait for confirmation.
    /// Returns the confirmed tx_hash.
    pub async fn submit_action(
        &mut self,
        party_index: u32,
        contract_addr: &str,
        shortname: u8,
        args: Vec<u8>,
        label: &str,
    ) -> Result<String> {
        let req = SubmitRequest {
            party_index,
            contract_address: contract_addr.to_string(),
            shortname: shortname as u32,
            args,
            label: label.to_string(),
        };

        let mut stream = self.inner.submit(req).await?.into_inner();

        while let Some(event) = stream.next().await {
            let ev = event?;
            match TxStatus::try_from(ev.status).unwrap_or(TxStatus::Queued) {
                TxStatus::Confirmed => {
                    tracing::info!("[relay] tx confirmed: {}", ev.tx_id);
                    return Ok(ev.tx_id);
                }
                TxStatus::Failed => {
                    return Err(anyhow!("tx failed: {}", ev.error));
                }
                _ => {
                    tracing::debug!("[relay] tx status {:?}: {}", ev.status, ev.tx_id);
                }
            }
        }
        Err(anyhow!("relay stream ended without confirmation"))
    }

    pub async fn submit_zk_input(
        &mut self,
        party_index: u32,
        contract_addr: &str,
        shortname: u8,
        public_args: Vec<u8>,
        secret_input: Vec<u8>,
        label: &str,
    ) -> Result<String> {
        let req = SubmitZkInputRequest {
            party_index,
            contract_address: contract_addr.to_string(),
            shortname: shortname as u32,
            public_args,
            secret_input,
            label: label.to_string(),
        };

        let mut stream = self.inner.submit_zk_input(req).await?.into_inner();

        while let Some(event) = stream.next().await {
            let ev = event?;
            match TxStatus::try_from(ev.status).unwrap_or(TxStatus::Queued) {
                TxStatus::Confirmed => {
                    tracing::info!("[relay] zk tx confirmed: {}", ev.tx_id);
                    return Ok(ev.tx_id);
                }
                TxStatus::Failed => {
                    return Err(anyhow!("zk tx failed: {}", ev.error));
                }
                _ => {
                    tracing::debug!("[relay] zk tx status {:?}: {}", ev.status, ev.tx_id);
                }
            }
        }
        Err(anyhow!("relay zk stream ended without confirmation"))
    }

    /// Fetch and parse contract state JSON.
    pub async fn get_contract_state(&mut self, contract_addr: &str) -> Result<Value> {
        let resp = self
            .inner
            .get_contract_state(GetContractStateRequest {
                contract_address: contract_addr.to_string(),
            })
            .await?
            .into_inner();
        let v: Value = serde_json::from_str(&resp.state_json)?;
        Ok(v)
    }

    /// Poll contract state until `pred` returns Some(T), or timeout.
    pub async fn poll_until<T, F>(
        &mut self,
        contract_addr: &str,
        mut pred: F,
        timeout: std::time::Duration,
    ) -> Result<T>
    where
        F: FnMut(&Value) -> Option<T>,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(anyhow!("poll_until timed out after {:?}", timeout));
            }
            match self.get_contract_state(contract_addr).await {
                Ok(state) => {
                    if let Some(result) = pred(&state) {
                        return Ok(result);
                    }
                }
                Err(e) => tracing::warn!("[relay] poll error: {e}"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    }
}
