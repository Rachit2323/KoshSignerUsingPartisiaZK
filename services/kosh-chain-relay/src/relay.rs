// Core chain relay logic — extracted directly from backend/src/chain_relay/mod.rs.
// Added: multi-party key support (PARTISIA_SENDER_KEY_1/2/3 env vars).

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::PathBuf, process::Stdio, sync::Arc, time::Duration};
use tokio::sync::Mutex;

const NODE_FAILURE_COOLDOWN_MS: i64 = 10_000;

#[derive(Clone)]
pub struct ChainRelay {
    node_urls: Vec<String>,
    // party_index → (sender_address, sender_key_hex)
    parties: Arc<HashMap<u32, (String, String)>>,
    client: Client,
    node_cursor: Arc<Mutex<usize>>,
    nonce_cache: Arc<Mutex<HashMap<String, (String, i64)>>>, // sender_address → (chain_id, next_nonce)
    sender_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl ChainRelay {
    pub fn new(
        node_urls: Vec<String>,
        parties: HashMap<u32, (String, String)>,
    ) -> Self {
        Self {
            node_urls,
            parties: Arc::new(parties),
            client: Client::new(),
            node_cursor: Arc::new(Mutex::new(0)),
            nonce_cache: Arc::new(Mutex::new(HashMap::new())),
            sender_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn from_env() -> Result<Self> {
        let urls_raw = std::env::var("PARTISIA_NODE_URLS")
            .context("PARTISIA_NODE_URLS is required and must list the 4 Partisia nodes explicitly")?;
        let node_urls: Vec<String> = urls_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if node_urls.len() < 4 {
            return Err(anyhow!(
                "PARTISIA_NODE_URLS must contain all 4 Partisia nodes; got {}",
                node_urls.len()
            ));
        }

        let mut parties = HashMap::new();
        for idx in 1u32..=3 {
            let key_env = format!("PARTISIA_SENDER_KEY_{idx}");
            let addr_env = format!("PARTISIA_SENDER_ADDRESS_{idx}");
            let key = std::env::var(&key_env)
                .with_context(|| format!("{key_env} is required; relay no longer falls back to shared sender credentials"))?;
            let addr = std::env::var(&addr_env)
                .with_context(|| format!("{addr_env} is required; relay no longer falls back to shared sender credentials"))?;
            parties.insert(idx, (addr, key));
            }

        Ok(Self::new(node_urls, parties))
    }

    pub async fn get_contract_state(&self, contract_address: &str) -> Result<String> {
        let node = self.pick_node().await;
        let url = format!(
            "{node}/shards/Shard0/blockchain/contracts/{contract_address}?requireContractState=true"
        );
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow!("contract read failed HTTP {status}"));
        }
        let body: Value = resp.json().await.context("decode contract state")?;
        Ok(body
            .get("serializedContract")
            .cloned()
            .unwrap_or(body)
            .to_string())
    }

    /// Submit a contract action and stream back status events.
    /// Returns (tx_hash, node_url) on success.
    pub async fn submit(
        &self,
        party_index: u32,
        contract_address: &str,
        shortname: u8,
        args: &[u8],
        label: &str,
    ) -> Result<String> {
        let (sender_address, sender_key) = self
            .parties
            .get(&party_index)
            .ok_or_else(|| anyhow!("no key configured for party {party_index}"))?
            .clone();

        let mut rpc = vec![0x09u8, shortname];
        rpc.extend_from_slice(args);

        let sender_lock = self.sender_lock(&sender_address).await;
        let _sender_guard = sender_lock.lock().await;
        let node = self.pick_node().await;
        let (chain_id, nonce) = self.reserve_nonce(party_index, &node, &sender_address).await?;

        let signed = sign_transaction(
            &sender_key,
            nonce,
            current_time_millis() + 30_000,
            500_000,
            &chain_id,
            contract_address,
            &rpc,
        )?;

        let tx = submit_serialized_transaction(&self.client, &node, &signed).await?;
        tracing::info!("{label} submitted tx={}", tx.tx_hash);

        wait_for_spawned_events(
            &self.client,
            &node,
            &tx.destination_shard_id,
            &tx.tx_hash,
            Duration::from_secs(120),
            Duration::from_secs(2),
        )
        .await
        .and_then(|tree| {
            ensure_execution_success(&tree)?;
            Ok(tx.tx_hash)
        })
    }

    pub async fn submit_zk_input(
        &self,
        party_index: u32,
        contract_address: &str,
        shortname: u8,
        public_args: &[u8],
        secret_input: &[u8],
        label: &str,
    ) -> Result<String> {
        let (sender_address, sender_key) = self
            .parties
            .get(&party_index)
            .ok_or_else(|| anyhow!("no key configured for party {party_index}"))?
            .clone();

        let mut rpc = vec![0x09u8, shortname];
        rpc.extend_from_slice(public_args);

        let request = serde_json::json!({
            "nodeUrls": self.node_urls,
            "senderKey": sender_key,
            "senderAddress": sender_address,
            "contractAddress": contract_address,
            "publicRpcHex": hex::encode(rpc),
            "secretHex": hex::encode(secret_input),
            "gasCost": 750000,
            "maxRetries": self.node_urls.len(),
        });

        let helper = zk_input_helper_path()?;
        let sender_lock = self.sender_lock(&sender_address).await;
        let _sender_guard = sender_lock.lock().await;
        let mut child = tokio::process::Command::new("node")
            .arg(helper)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn Partisia ZK input helper")?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(&serde_json::to_vec(&request)?).await?;
        }

        let output = child.wait_with_output().await?;
        if output.status.success() {
            let response: Value = serde_json::from_slice(&output.stdout)
                .context("decode zk helper stdout")?;
            let tx_hash = response
                .get("txHash")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("zk helper did not return txHash"))?;
            tracing::info!("{label} submitted zk tx={tx_hash}");
            Ok(tx_hash.to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let msg = if !stderr.trim().is_empty() {
                stderr.trim().to_string()
            } else {
                stdout.trim().to_string()
            };
            Err(anyhow!("zk input helper failed: {msg}"))
        }
    }

    async fn pick_node(&self) -> String {
        let mut cursor = self.node_cursor.lock().await;
        let node = self.node_urls[*cursor % self.node_urls.len()].clone();
        *cursor = (*cursor + 1) % self.node_urls.len().max(1);
        node
    }

    async fn reserve_nonce(
        &self,
        _party: u32,
        node: &str,
        sender_address: &str,
    ) -> Result<(String, i64)> {
        let mut cache = self.nonce_cache.lock().await;
        let sender_key = sender_address.to_ascii_lowercase();
        if let Some((chain_id, nonce)) = cache.get_mut(&sender_key) {
            let reserved = (*chain_id).clone();
            let n = *nonce;
            *nonce += 1;
            return Ok((reserved, n));
        }
        let chain_id = fetch_chain_id(&self.client, node).await?;
        let nonce = fetch_nonce(&self.client, node, sender_address).await?;
        cache.insert(sender_key, (chain_id.clone(), nonce + 1));
        Ok((chain_id, nonce))
    }

    async fn sender_lock(&self, sender_address: &str) -> Arc<Mutex<()>> {
        let mut locks = self.sender_locks.lock().await;
        locks
            .entry(sender_address.to_ascii_lowercase())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

fn zk_input_helper_path() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow!("cannot derive repo root from manifest dir"))?;
    Ok(repo_root.join("frontend/scripts/submit-partisia-zk-input.mjs"))
}

// ─── Signing helpers (ported from backend/src/chain_relay/mod.rs) ────────────

fn sign_transaction(
    sender_key_hex: &str,
    nonce: i64,
    valid_to_time: i64,
    gas_cost: i64,
    chain_id: &str,
    contract_address: &str,
    rpc: &[u8],
) -> Result<Vec<u8>> {
    let inner = serialize_inner_transaction(nonce, valid_to_time, gas_cost, contract_address, rpc)?;
    let mut chain_encoded = Vec::new();
    chain_encoded.extend_from_slice(&(chain_id.len() as i32).to_be_bytes());
    chain_encoded.extend_from_slice(chain_id.as_bytes());

    let hash = sha256_many(&[&inner, &chain_encoded]);
    let key_bytes = hex::decode(sender_key_hex.trim_start_matches("0x"))
        .context("decode sender key")?;
    let signing_key = SigningKey::from_slice(&key_bytes)
        .map_err(|e| anyhow!("invalid sender key: {e}"))?;
    let (sig, rec) = signing_key
        .sign_prehash_recoverable(&hash)
        .map_err(|e| anyhow!("sign tx: {e}"))?;
    Ok(serialize_signed_transaction(rec, &sig, &inner))
}

fn serialize_inner_transaction(
    nonce: i64, valid_to: i64, gas: i64,
    contract_address: &str, rpc: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&nonce.to_be_bytes());
    out.extend_from_slice(&valid_to.to_be_bytes());
    out.extend_from_slice(&gas.to_be_bytes());
    let addr = hex::decode(contract_address.trim_start_matches("0x"))
        .context("decode contract address")?;
    out.extend_from_slice(&addr);
    out.extend_from_slice(&(rpc.len() as i32).to_be_bytes());
    out.extend_from_slice(rpc);
    Ok(out)
}

fn serialize_signed_transaction(rec: RecoveryId, sig: &Signature, inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(65 + inner.len());
    out.push(rec.to_byte());
    out.extend_from_slice(&sig.r().to_bytes());
    out.extend_from_slice(&sig.s().to_bytes());
    out.extend_from_slice(inner);
    out
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubmitResult {
    identifier: String,
    destination_shard_id: Option<String>,
}

struct TxInfo { tx_hash: String, destination_shard_id: String }

async fn submit_serialized_transaction(client: &Client, node: &str, signed: &[u8]) -> Result<TxInfo> {
    let url = format!("{node}/chain/transactions");
    let payload = serde_json::json!({
        "payload": base64::engine::general_purpose::STANDARD.encode(signed)
    });
    let resp = client.put(&url).json(&payload).send().await
        .with_context(|| format!("PUT {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("put tx HTTP {status}: {body}"));
    }
    let r: SubmitResult = resp.json().await.context("decode put tx response")?;
    Ok(TxInfo {
        tx_hash: r.identifier,
        destination_shard_id: r.destination_shard_id.unwrap_or_else(|| "Shard0".to_string()),
    })
}

async fn wait_for_spawned_events(
    client: &Client, node: &str, shard_id: &str, tx_id: &str,
    timeout: Duration, poll_interval: Duration,
) -> Result<Value> {
    let started = tokio::time::Instant::now();
    let root = loop {
        let maybe = get_transaction(client, node, shard_id, tx_id).await?;
        if let Some(v) = maybe {
            if v.get("executionStatus").is_some() { break v; }
        }
        if started.elapsed() >= timeout {
            return Err(anyhow!("timed out waiting for tx {tx_id}"));
        }
        tokio::time::sleep(poll_interval).await;
    };

    let mut events = Vec::new();
    let mut pending = root.get("executionStatus")
        .and_then(|s| s.get("events"))
        .and_then(Value::as_array).cloned().unwrap_or_default();

    while let Some(event) = pending.first().cloned() {
        pending.remove(0);
        let shard = event.get("destinationShardId").and_then(Value::as_str)
            .ok_or_else(|| anyhow!("spawned event missing shard"))?;
        let id = event.get("identifier").and_then(Value::as_str)
            .ok_or_else(|| anyhow!("spawned event missing id"))?;
        let executed = loop {
            let maybe = get_transaction(client, node, shard, id).await?;
            if let Some(v) = maybe {
                if v.get("executionStatus").is_some() { break v; }
            }
            if started.elapsed() >= timeout {
                return Err(anyhow!("timed out waiting for spawned event {id}"));
            }
            tokio::time::sleep(poll_interval).await;
        };
        if let Some(spawned) = executed.get("executionStatus")
            .and_then(|s| s.get("events")).and_then(Value::as_array) {
            pending.extend(spawned.iter().cloned());
        }
        events.push(executed);
    }
    Ok(serde_json::json!({ "root": root, "events": events }))
}

async fn get_transaction(client: &Client, node: &str, shard_id: &str, tx_id: &str) -> Result<Option<Value>> {
    let url = format!("{node}/chain/shards/{shard_id}/transactions/{tx_id}");
    let resp = client.get(&url).send().await.with_context(|| format!("GET {url}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND { return Ok(None); }
    if !resp.status().is_success() {
        return Err(anyhow!("get tx HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    Ok(Some(resp.json().await.context("decode tx json")?))
}

fn ensure_execution_success(tree: &Value) -> Result<()> {
    let root_status = tree.get("root").and_then(|r| r.get("executionStatus"))
        .ok_or_else(|| anyhow!("missing root executionStatus"))?;
    check_status(root_status)?;
    if let Some(events) = tree.get("events").and_then(Value::as_array) {
        for event in events {
            let s = event.get("executionStatus")
                .ok_or_else(|| anyhow!("missing spawned executionStatus"))?;
            check_status(s)?;
        }
    }
    Ok(())
}

fn check_status(status: &Value) -> Result<()> {
    if status.get("success").and_then(Value::as_bool) == Some(false) {
        let msg = status.get("failure").and_then(|f| f.get("errorMessage"))
            .and_then(Value::as_str).unwrap_or("unknown error");
        return Err(anyhow!("contract failure: {msg}"));
    }
    Ok(())
}

async fn fetch_chain_id(client: &Client, node: &str) -> Result<String> {
    let url = format!("{node}/chain");
    let resp = client.get(&url).send().await.with_context(|| format!("GET {url}"))?;
    let body: Value = resp.json().await.context("decode chain json")?;
    body.get("chainId").and_then(Value::as_str).map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("chainId missing"))
}

async fn fetch_nonce(client: &Client, node: &str, addr: &str) -> Result<i64> {
    let url = format!("{node}/chain/accounts/{addr}");
    let resp = client.get(&url).send().await.with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("get account HTTP {}", resp.status()));
    }
    let body: Value = resp.json().await.context("decode account json")?;
    body.get("nonce").and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("nonce missing"))
}

fn sha256_many(bufs: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for b in bufs { h.update(b); }
    h.finalize().into()
}

fn current_time_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64
}
