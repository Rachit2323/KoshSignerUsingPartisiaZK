use anyhow::Result;
use std::time::Duration;
use tokio::time::timeout;

pub mod bb_pb {
    tonic::include_proto!("kosh.bb");
}

use bb_pb::{
    bulletin_board_client::BulletinBoardClient, ClearRequest, PostRequest, ReadRequest,
    WatchRequest,
};
use tonic::transport::Channel;

pub struct BulletinBoard {
    client: BulletinBoardClient<Channel>,
}

impl BulletinBoard {
    pub async fn connect(addr: &str) -> Result<Self> {
        let client = BulletinBoardClient::connect(addr.to_string()).await?;
        Ok(Self { client })
    }

    pub async fn post(&mut self, topic: &str, value: &str) -> Result<()> {
        self.client
            .post(PostRequest {
                topic: topic.to_string(),
                value: value.to_string(),
            })
            .await?;
        Ok(())
    }

    pub async fn read(&mut self, topic: &str) -> Result<Option<String>> {
        let resp = self.client.read(ReadRequest { topic: topic.to_string() }).await?.into_inner();
        Ok(if resp.found { Some(resp.value) } else { None })
    }

    /// Watch a topic; wait up to `deadline` for the first value.
    /// If the value already exists on the server, it is returned immediately.
    pub async fn watch_one(&mut self, topic: &str, deadline: Duration) -> Result<String> {
        let mut stream = self
            .client
            .watch(WatchRequest { topic: topic.to_string() })
            .await?
            .into_inner();

        let event = timeout(deadline, stream.message())
            .await
            .map_err(|_| anyhow::anyhow!("watch timeout for topic '{topic}'"))?
            .map_err(|e| anyhow::anyhow!("watch stream error: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("watch stream closed for topic '{topic}'"))?;

        Ok(event.value)
    }

    pub async fn clear(&mut self) -> Result<i32> {
        let resp = self.client.clear(ClearRequest {}).await?.into_inner();
        Ok(resp.keys_cleared)
    }
}
