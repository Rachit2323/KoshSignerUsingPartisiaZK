use crate::{
    chain_relay::{RelayHealth, RelayPreflight},
    evm_broadcaster::{BroadcastSignedTxRequest, BroadcastSignedTxResult, UnsignedEthTransfer},
    jobs::{Job, JobKind},
    keystore::{KeyMaterialMetadata, PersistedPartyRuntime},
    orchestrator::{CreateKeyWorkflowRequest, ReuseSignWorkflowRequest},
    party_runtime::{
        dkg::{SchnorrProof, ShamirShare, ThresholdDkgShare},
        gg20::{GG20PartyState, GG20SignatureData},
        mta::{MtAMessage1, MtAMessage2, MtAOutputA, MtAOutputB, MtASessionContext},
        paillier::PaillierKeyPair,
    },
    passkeys::{LinkedKey, PasskeyAccount, PasskeyMe},
    policy::{Policy, PolicyDecision, PolicyInput},
    threshold_read::{ThresholdKeyStatus, ThresholdTaskSignature},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    pub kind: JobKindDto,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum JobKindDto {
    DeployContract,
    CreateKey,
    ReuseSign,
    FreshSign,
    BroadcastSepolia,
}

impl From<JobKindDto> for JobKind {
    fn from(value: JobKindDto) -> Self {
        match value {
            JobKindDto::DeployContract => JobKind::DeployContract,
            JobKindDto::CreateKey => JobKind::CreateKey,
            JobKindDto::ReuseSign => JobKind::ReuseSign,
            JobKindDto::FreshSign => JobKind::FreshSign,
            JobKindDto::BroadcastSepolia => JobKind::BroadcastSepolia,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CreateJobResponse {
    pub job: Job,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub service: String,
    pub database: &'static str,
}

#[derive(Debug, Deserialize)]
pub struct PostTopicRequest {
    pub topic: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct PostTopicResponse {
    pub ok: bool,
}

#[derive(Debug, Deserialize)]
pub struct ReadTopicQuery {
    pub wait: Option<bool>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ReadTopicResponse {
    pub topic: String,
    pub value: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListTopicsResponse {
    pub keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct StoreSecretRequest {
    pub name: String,
    pub plaintext_b64: String,
    pub metadata: KeyMaterialMetadata,
}

#[derive(Debug, Serialize)]
pub struct StoreSecretResponse {
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct LoadSecretResponse {
    pub plaintext_b64: String,
    pub metadata: KeyMaterialMetadata,
}

#[derive(Debug, Deserialize)]
pub struct ValidatePolicyRequest {
    pub tx_tag: String,
    pub signing_parties: Vec<u8>,
    pub threshold: u8,
}

#[derive(Debug, Serialize)]
pub struct ListPoliciesResponse {
    pub policies: Vec<Policy>,
}

#[derive(Debug, Serialize)]
pub struct AddPolicyResponse {
    pub policy: Policy,
}

#[derive(Debug, Serialize)]
pub struct RelayHealthResponse {
    pub relay: RelayHealth,
}

#[derive(Debug, Serialize)]
pub struct RelayContractStateResponse {
    pub contract_address: String,
    pub state: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct RuntimePreflightQuery {
    pub contract_address: String,
    pub key_id: u32,
    pub mode: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RuntimePreflightResponse {
    pub preflight: RelayPreflight,
}

#[derive(Debug, Deserialize)]
pub struct ThresholdKeyStatusQuery {
    pub contract_address: String,
    pub key_id: u32,
}

#[derive(Debug, Deserialize)]
pub struct ThresholdTaskSignatureQuery {
    pub contract_address: String,
    pub key_id: u32,
    pub task_id: u32,
}

pub type ThresholdKeyStatusResponse = ThresholdKeyStatus;
pub type ThresholdTaskSignatureResponse = ThresholdTaskSignature;

#[derive(Debug, Deserialize)]
pub struct GenerateDkgShareRequest {
    pub party_index: u8,
    pub num_parties: u8,
    pub seed_hex: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GenerateDkgShareResponse {
    pub share: ThresholdDkgShare,
    pub schnorr_proof: SchnorrProof,
}

#[derive(Debug, Deserialize)]
pub struct CombineShamirSharesRequest {
    pub party_index: u8,
    pub shares: Vec<ThresholdDkgShare>,
}

#[derive(Debug, Serialize)]
pub struct CombineShamirSharesResponse {
    pub share: ShamirShare,
}

#[derive(Debug, Deserialize)]
pub struct VerifySubshareRequest {
    pub subshare_hex: String,
    pub c_i0_hex: String,
    pub c_i1_hex: String,
    pub recipient_party_index: u8,
}

#[derive(Debug, Serialize)]
pub struct VerifySubshareResponse {
    pub valid: bool,
}

#[derive(Debug, Deserialize)]
pub struct CombinedPublicKeyRequest {
    pub shares: Vec<ThresholdDkgShare>,
}

#[derive(Debug, Serialize)]
pub struct CombinedPublicKeyResponse {
    pub public_key_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct StorePartyRuntimeRequest {
    pub runtime: PersistedPartyRuntime,
}

#[derive(Debug, Serialize)]
pub struct StorePartyRuntimeResponse {
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct LoadPartyRuntimeResponse {
    pub runtime: PersistedPartyRuntime,
}

#[derive(Debug, Deserialize)]
pub struct LoadPartyRuntimeQuery {
    pub contract_address: String,
    pub key_id: u32,
    pub party_index: u8,
}

pub type ValidatePolicyResponse = PolicyDecision;
pub type AddPolicyRequest = PolicyInput;

#[derive(Debug, Deserialize)]
pub struct PaillierKeygenRequest {
    pub bit_length: Option<u16>,
}

#[derive(Debug, Serialize)]
pub struct PaillierKeygenResponse {
    pub key_pair: PaillierKeyPair,
}

#[derive(Debug, Deserialize)]
pub struct MtARound1Request {
    pub a_hex: String,
    pub paillier_key_pair: PaillierKeyPair,
    pub session: Option<MtASessionContext>,
}

#[derive(Debug, Serialize)]
pub struct MtARound1Response {
    pub message: MtAMessage1,
}

#[derive(Debug, Deserialize)]
pub struct MtARound2Request {
    pub message: MtAMessage1,
    pub b_hex: String,
    pub expected_session: Option<MtASessionContext>,
}

#[derive(Debug, Serialize)]
pub struct MtARound2Response {
    pub message: MtAMessage2,
    pub output_b: MtAOutputB,
}

#[derive(Debug, Deserialize)]
pub struct MtAFinalizeRequest {
    pub message: MtAMessage2,
    pub paillier_key_pair: PaillierKeyPair,
    pub expected_session: Option<MtASessionContext>,
}

#[derive(Debug, Serialize)]
pub struct MtAFinalizeResponse {
    pub output_a: MtAOutputA,
}

#[derive(Debug, Deserialize)]
pub struct GG20InitPartyRequest {
    pub party_index: u8,
    pub x_i_hex: String,
    pub msg_hash_hex: Option<String>,
    pub session_id: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct GG20InitPartyResponse {
    pub party: GG20PartyState,
}

#[derive(Debug, Deserialize)]
pub struct GG20RunMtaRequest {
    pub parties: Vec<GG20PartyState>,
}

#[derive(Debug, Serialize)]
pub struct GG20RunMtaResponse {
    pub parties: Vec<GG20PartyState>,
}

#[derive(Debug, Deserialize)]
pub struct GG20ComputeRRequest {
    pub parties: Vec<GG20PartyState>,
}

#[derive(Debug, Serialize)]
pub struct GG20ComputeRResponse {
    pub r_hex: String,
    pub r_bytes_hex: String,
    pub r_point_compressed_hex: String,
    pub recovery_id: u8,
}

#[derive(Debug, Deserialize)]
pub struct GG20SignFoundationRequest {
    pub party_inputs: Vec<GG20PartyInput>,
    pub msg_hash_hex: String,
    pub session_id: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GG20PartyInput {
    pub party_index: u8,
    pub x_i_hex: String,
}

#[derive(Debug, Serialize)]
pub struct GG20SignFoundationResponse {
    pub signature: GG20SignatureData,
}

pub type StartCreateKeyWorkflowRequest = CreateKeyWorkflowRequest;
pub type StartReuseSignWorkflowRequest = ReuseSignWorkflowRequest;

#[derive(Debug, Deserialize)]
pub struct BuildEthTransferRequest {
    pub from: String,
    pub to: String,
    pub value_wei: String,
    pub nonce: u64,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
    pub gas_limit: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct BuildEthTransferResponse {
    pub transaction: UnsignedEthTransfer,
}

pub type BroadcastSignedTransactionRequest = BroadcastSignedTxRequest;
pub type BroadcastSignedTransactionResponse = BroadcastSignedTxResult;

#[derive(Debug, Serialize)]
pub struct ActiveRuntimeResponse {
    pub ok: bool,
    pub runtime: Option<crate::app::ActiveRuntimeState>,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterStartRequest {
    pub label: Option<String>,
    pub contract_address: Option<String>,
    pub key_id: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyRegisterStartResponse {
    pub registration_id: String,
    pub options: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterFinishRequest {
    pub registration_id: String,
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct PasskeyRegisterFinishResponse {
    pub session_token: String,
    pub account: PasskeyAccount,
}

#[derive(Debug, Serialize)]
pub struct PasskeyAuthStartResponse {
    pub authentication_id: String,
    pub options: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyAuthFinishRequest {
    pub authentication_id: String,
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct PasskeyAuthFinishResponse {
    pub session_token: String,
    pub account: PasskeyAccount,
}

#[derive(Debug, Serialize)]
pub struct PasskeyMeResponse {
    pub ok: bool,
    pub me: PasskeyMe,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyLinkKeyRequest {
    pub contract_address: String,
    pub key_id: u32,
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyLinkKeyResponse {
    pub ok: bool,
    pub account: PasskeyAccount,
}

#[derive(Debug, Serialize)]
pub struct PasskeyKeysResponse {
    pub keys: Vec<LinkedKey>,
    pub selected_key: Option<LinkedKey>,
}

#[derive(Debug, Deserialize)]
pub struct PasskeySelectKeyRequest {
    pub contract_address: String,
    pub key_id: u32,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyCreateKeyRequest {
    pub contract_address: String,
    pub num_parties: u8,
    pub seed_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyReuseSignRequest {
    pub tx_tag: String,
    pub signing_parties: Vec<u8>,
    pub threshold: u8,
    pub msg_hash_hex: String,
    pub session_id: Option<u32>,
    pub signed_tx_hex: Option<String>,
}
