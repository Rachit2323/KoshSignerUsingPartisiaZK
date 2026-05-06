use crate::relay::ChainRelay;
use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("kosh.relay");
}

use pb::{
    chain_relay_server::ChainRelay as ChainRelayTrait,
    GetContractStateRequest, GetContractStateResponse,
    SubmitRequest, SubmitZkInputRequest, TxEvent,
    tx_event::Status as TxStatus,
};

pub struct ChainRelayService {
    relay: ChainRelay,
}

impl ChainRelayService {
    pub fn new(relay: ChainRelay) -> Self {
        Self { relay }
    }
}

#[tonic::async_trait]
impl ChainRelayTrait for ChainRelayService {
    type SubmitStream = tokio_stream::wrappers::ReceiverStream<Result<TxEvent, Status>>;
    type SubmitZkInputStream = tokio_stream::wrappers::ReceiverStream<Result<TxEvent, Status>>;

    async fn submit(
        &self,
        request: Request<SubmitRequest>,
    ) -> Result<Response<Self::SubmitStream>, Status> {
        let req = request.into_inner();
        let relay = self.relay.clone();

        let (tx, rx) = tokio::sync::mpsc::channel(8);

        // Send QUEUED immediately
        let _ = tx.send(Ok(TxEvent {
            status: TxStatus::Queued as i32,
            tx_id: String::new(),
            error: String::new(),
        })).await;

        tokio::spawn(async move {
            let _ = tx.send(Ok(TxEvent {
                status: TxStatus::Submitted as i32,
                tx_id: String::new(),
                error: String::new(),
            })).await;

            match relay
                .submit(
                    req.party_index,
                    &req.contract_address,
                    req.shortname as u8,
                    &req.args,
                    &req.label,
                )
                .await
            {
                Ok(tx_hash) => {
                    let _ = tx.send(Ok(TxEvent {
                        status: TxStatus::Confirmed as i32,
                        tx_id: tx_hash,
                        error: String::new(),
                    })).await;
                }
                Err(e) => {
                    let _ = tx.send(Ok(TxEvent {
                        status: TxStatus::Failed as i32,
                        tx_id: String::new(),
                        error: e.to_string(),
                    })).await;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn submit_zk_input(
        &self,
        request: Request<SubmitZkInputRequest>,
    ) -> Result<Response<Self::SubmitStream>, Status> {
        let req = request.into_inner();
        let relay = self.relay.clone();

        let (tx, rx) = tokio::sync::mpsc::channel(8);

        let _ = tx.send(Ok(TxEvent {
            status: TxStatus::Queued as i32,
            tx_id: String::new(),
            error: String::new(),
        })).await;

        tokio::spawn(async move {
            let _ = tx.send(Ok(TxEvent {
                status: TxStatus::Submitted as i32,
                tx_id: String::new(),
                error: String::new(),
            })).await;

            match relay
                .submit_zk_input(
                    req.party_index,
                    &req.contract_address,
                    req.shortname as u8,
                    &req.public_args,
                    &req.secret_input,
                    &req.label,
                )
                .await
            {
                Ok(tx_hash) => {
                    let _ = tx.send(Ok(TxEvent {
                        status: TxStatus::Confirmed as i32,
                        tx_id: tx_hash,
                        error: String::new(),
                    })).await;
                }
                Err(e) => {
                    let _ = tx.send(Ok(TxEvent {
                        status: TxStatus::Failed as i32,
                        tx_id: String::new(),
                        error: e.to_string(),
                    })).await;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn get_contract_state(
        &self,
        request: Request<GetContractStateRequest>,
    ) -> Result<Response<GetContractStateResponse>, Status> {
        let addr = request.into_inner().contract_address;
        match self.relay.get_contract_state(&addr).await {
            Ok(state_json) => Ok(Response::new(GetContractStateResponse { state_json })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }
}
