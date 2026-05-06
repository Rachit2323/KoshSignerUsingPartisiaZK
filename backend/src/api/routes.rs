use crate::{
    api::dto::{
        ActiveRuntimeResponse, AddPolicyRequest, AddPolicyResponse,
        BroadcastSignedTransactionRequest, BuildEthTransferRequest, BuildEthTransferResponse,
        CombineShamirSharesRequest, CombineShamirSharesResponse, CombinedPublicKeyRequest,
        CombinedPublicKeyResponse, CreateJobRequest, CreateJobResponse, GG20ComputeRRequest,
        GG20ComputeRResponse, GG20InitPartyRequest, GG20InitPartyResponse, GG20RunMtaRequest,
        GG20RunMtaResponse, GG20SignFoundationRequest, GG20SignFoundationResponse,
        GenerateDkgShareRequest, GenerateDkgShareResponse, HealthResponse, ListPoliciesResponse,
        ListTopicsResponse, LoadPartyRuntimeQuery, LoadPartyRuntimeResponse, LoadSecretResponse,
        MtAFinalizeRequest, MtAFinalizeResponse, MtARound1Request, MtARound1Response,
        MtARound2Request, MtARound2Response, PaillierKeygenRequest, PaillierKeygenResponse,
        PasskeyAuthFinishRequest, PasskeyAuthFinishResponse, PasskeyAuthStartResponse,
        PasskeyCreateKeyRequest, PasskeyKeysResponse, PasskeyLinkKeyRequest, PasskeyLinkKeyResponse, PasskeyMeResponse,
        PasskeyRegisterFinishRequest, PasskeyRegisterFinishResponse, PasskeyRegisterStartRequest,
        PasskeyRegisterStartResponse, PasskeyReuseSignRequest, PasskeySelectKeyRequest, PostTopicRequest, PostTopicResponse,
        ReadTopicQuery, ReadTopicResponse, RelayContractStateResponse, RelayHealthResponse,
        RuntimePreflightQuery, RuntimePreflightResponse, StartCreateKeyWorkflowRequest,
        StartReuseSignWorkflowRequest, StorePartyRuntimeRequest, StorePartyRuntimeResponse,
        StoreSecretRequest, StoreSecretResponse, ThresholdKeyStatusQuery,
        ThresholdKeyStatusResponse, ThresholdTaskSignatureQuery, ThresholdTaskSignatureResponse,
        ValidatePolicyRequest, ValidatePolicyResponse, VerifySubshareRequest,
        VerifySubshareResponse,
    },
    app::AppState,
    evm_broadcaster::UnsignedEthTransfer,
    orchestrator,
    party_runtime::{dkg, gg20, mta, paillier},
    threshold_read,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::time::Duration;
use uuid::Uuid;

use super::sse::{stream_job_events, stream_topic_events};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/jobs", post(create_job))
        .route("/api/v1/jobs/:job_id", get(get_job))
        .route("/api/v1/jobs/:job_id/events", get(stream_job_events))
        .route("/api/v1/runtime/active", get(active_runtime))
        .route(
            "/api/v1/passkeys/register/start",
            post(passkey_register_start),
        )
        .route(
            "/api/v1/passkeys/register/finish",
            post(passkey_register_finish),
        )
        .route("/api/v1/passkeys/auth/start", post(passkey_auth_start))
        .route("/api/v1/passkeys/auth/finish", post(passkey_auth_finish))
        .route("/api/v1/passkeys/me", get(passkey_me))
        .route("/api/v1/passkeys/keys", get(passkey_keys))
        .route("/api/v1/passkeys/link-key", post(passkey_link_key))
        .route("/api/v1/passkeys/select-key", post(passkey_select_key))
        .route("/api/v1/passkeys/create-key", post(passkey_create_key))
        .route("/api/v1/passkeys/reuse-sign", post(passkey_reuse_sign))
        .route(
            "/api/v1/coordinator/topics",
            post(post_topic).get(list_topics).delete(clear_topics),
        )
        .route("/api/v1/coordinator/topics/:topic", get(read_topic))
        .route(
            "/api/v1/coordinator/topics/:topic/events",
            get(stream_topic_events),
        )
        .route("/api/v1/keystore/secrets", post(store_secret))
        .route("/api/v1/keystore/secrets/:name", get(load_secret))
        .route(
            "/api/v1/keystore/runtime",
            post(store_party_runtime).get(load_party_runtime),
        )
        .route("/api/v1/policies", post(add_policy).get(list_policies))
        .route("/api/v1/policies/:policy_id", delete(remove_policy))
        .route("/api/v1/policies/validate", post(validate_policy))
        .route("/api/v1/relay/health", get(relay_health))
        .route("/api/v1/runtime/preflight", get(runtime_preflight))
        .route(
            "/api/v1/relay/contracts/:contract_address",
            get(relay_contract_state),
        )
        .route("/api/v1/threshold/key-status", get(threshold_key_status))
        .route(
            "/api/v1/threshold/task-signature",
            get(threshold_task_signature),
        )
        .route("/api/v1/dkg/generate-share", post(generate_dkg_share))
        .route("/api/v1/dkg/combine-share", post(combine_shamir_shares))
        .route("/api/v1/dkg/verify-subshare", post(verify_subshare))
        .route("/api/v1/dkg/combined-public-key", post(combined_public_key))
        .route("/api/v1/paillier/keygen", post(paillier_keygen))
        .route("/api/v1/mta/round1", post(mta_round1))
        .route("/api/v1/mta/round2", post(mta_round2))
        .route("/api/v1/mta/finalize", post(mta_finalize))
        .route("/api/v1/gg20/init-party", post(gg20_init_party))
        .route("/api/v1/gg20/run-mta", post(gg20_run_mta))
        .route("/api/v1/gg20/compute-r", post(gg20_compute_r))
        .route("/api/v1/gg20/sign-foundation", post(gg20_sign_foundation))
        .route(
            "/api/v1/workflows/create-key",
            post(start_create_key_workflow),
        )
        .route(
            "/api/v1/workflows/reuse-sign",
            post(start_reuse_sign_workflow),
        )
        .route(
            "/api/v2/workflows/reuse-sign",
            post(start_reuse_sign_v2_workflow),
        )
        .route("/api/v1/evm/build-eth-transfer", post(build_eth_transfer))
        .route(
            "/api/v1/evm/broadcast-signed",
            post(broadcast_signed_transaction),
        )
        .with_state(state)
}

fn session_token(headers: &HeaderMap) -> Result<String, (StatusCode, String)> {
    headers
        .get("x-kosh-session")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.to_string())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "missing x-kosh-session header".to_string(),
        ))
}

async fn passkey_create_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyCreateKeyRequest>,
) -> impl IntoResponse {
    let token = match session_token(&headers) {
        Ok(token) => token,
        Err((status, message)) => return (status, message).into_response(),
    };
    let key_id = match next_available_key_id(&state, &payload.contract_address).await {
        Ok(key_id) => key_id,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };
    let job = orchestrator::start_create_key_workflow(
        state,
        crate::orchestrator::CreateKeyWorkflowRequest {
            contract_address: payload.contract_address.clone(),
            key_id,
            num_parties: payload.num_parties,
            seed_hex: payload.seed_hex,
        },
    )
    .await;
    let _ = token;
    (
        StatusCode::CREATED,
        Json(CreateJobResponse {
            job,
            contract_address: Some(payload.contract_address),
            key_id: Some(key_id),
        }),
    )
        .into_response()
}

async fn passkey_reuse_sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyReuseSignRequest>,
) -> impl IntoResponse {
    let token = match session_token(&headers) {
        Ok(token) => token,
        Err((status, message)) => return (status, message).into_response(),
    };
    let linked = match state.passkeys.selected_key(&token).await {
        Ok(linked) => linked,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };
    let contract_address = linked.contract_address.clone();
    let key_id = linked.key_id;
    let job = orchestrator::start_reuse_sign_v2_workflow(
        state,
        crate::orchestrator::ReuseSignWorkflowRequest {
            contract_address,
            key_id,
            tx_tag: payload.tx_tag,
            signing_parties: payload.signing_parties,
            threshold: payload.threshold,
            msg_hash_hex: payload.msg_hash_hex,
            session_id: payload.session_id,
            signed_tx_hex: payload.signed_tx_hex,
        },
    )
    .await;
    (
        StatusCode::CREATED,
        Json(CreateJobResponse {
            job,
            contract_address: Some(linked.contract_address),
            key_id: Some(linked.key_id),
        }),
    )
        .into_response()
}

async fn passkey_register_start(
    State(state): State<AppState>,
    Json(payload): Json<PasskeyRegisterStartRequest>,
) -> impl IntoResponse {
    let link_key = match (payload.contract_address, payload.key_id) {
        (Some(contract_address), Some(key_id)) => Some(crate::passkeys::LinkedKey {
            label: payload
                .label
                .clone()
                .unwrap_or_else(|| format!("Key {key_id}")),
            contract_address,
            key_id,
        }),
        _ => None,
    };
    match state
        .passkeys
        .start_registration(
            payload.label.unwrap_or_else(|| "Kosh Passkey".to_string()),
            link_key,
        )
        .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(PasskeyRegisterStartResponse {
                registration_id: result.registration_id.to_string(),
                options: result.options,
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn passkey_register_finish(
    State(state): State<AppState>,
    Json(payload): Json<PasskeyRegisterFinishRequest>,
) -> impl IntoResponse {
    let registration_id = match Uuid::parse_str(&payload.registration_id) {
        Ok(id) => id,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid registration_id: {err}"),
            )
                .into_response()
        }
    };
    match state
        .passkeys
        .finish_registration(registration_id, payload.credential)
        .await
    {
        Ok((session, account)) => (
            StatusCode::OK,
            Json(PasskeyRegisterFinishResponse {
                session_token: session.token,
                account,
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn passkey_auth_start(State(state): State<AppState>) -> impl IntoResponse {
    match state.passkeys.start_authentication().await {
        Ok(result) => (
            StatusCode::OK,
            Json(PasskeyAuthStartResponse {
                authentication_id: result.authentication_id.to_string(),
                options: result.options,
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn passkey_auth_finish(
    State(state): State<AppState>,
    Json(payload): Json<PasskeyAuthFinishRequest>,
) -> impl IntoResponse {
    let authentication_id = match Uuid::parse_str(&payload.authentication_id) {
        Ok(id) => id,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid authentication_id: {err}"),
            )
                .into_response()
        }
    };
    match state
        .passkeys
        .finish_authentication(authentication_id, payload.credential)
        .await
    {
        Ok((session, account)) => (
            StatusCode::OK,
            Json(PasskeyAuthFinishResponse {
                session_token: session.token,
                account,
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn passkey_me(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let token = match session_token(&headers) {
        Ok(token) => token,
        Err((status, message)) => return (status, message).into_response(),
    };
    match state.passkeys.me(&token).await {
        Ok(me) => (StatusCode::OK, Json(PasskeyMeResponse { ok: true, me })).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn passkey_keys(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let token = match session_token(&headers) {
        Ok(token) => token,
        Err((status, message)) => return (status, message).into_response(),
    };
    match state.passkeys.me(&token).await {
        Ok(me) => {
            let account = me.account.unwrap_or(crate::passkeys::PasskeyAccount {
                account_id: Uuid::nil(),
                label: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
                credentials: vec![],
                linked_keys: vec![],
                selected_key: None,
            });
            (
                StatusCode::OK,
                Json(PasskeyKeysResponse {
                    keys: account.linked_keys,
                    selected_key: account.selected_key,
                }),
            )
                .into_response()
        }
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn passkey_link_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyLinkKeyRequest>,
) -> impl IntoResponse {
    let token = match session_token(&headers) {
        Ok(token) => token,
        Err((status, message)) => return (status, message).into_response(),
    };
    match state
        .passkeys
        .link_key(
            &token,
            crate::passkeys::LinkedKey {
                contract_address: payload.contract_address,
                key_id: payload.key_id,
                label: payload
                    .label
                    .unwrap_or_else(|| format!("Key {}", payload.key_id)),
            },
        )
        .await
    {
        Ok(account) => (
            StatusCode::OK,
            Json(PasskeyLinkKeyResponse { ok: true, account }),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn passkey_select_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<PasskeySelectKeyRequest>,
) -> impl IntoResponse {
    let token = match session_token(&headers) {
        Ok(token) => token,
        Err((status, message)) => return (status, message).into_response(),
    };
    match state
        .passkeys
        .select_key(&token, &payload.contract_address, payload.key_id)
        .await
    {
        Ok(account) => (
            StatusCode::OK,
            Json(PasskeyLinkKeyResponse { ok: true, account }),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn next_available_key_id(state: &AppState, contract_address: &str) -> Result<u32, String> {
    for _ in 0..32 {
        let candidate: u32 = 10000 + (rand::random::<u32>() % (u32::MAX - 10000));
        match state.chain_relay.get_contract_data(contract_address).await {
            Ok(contract_state) => {
                match threshold_read::threshold_key_status(&contract_state, candidate).await {
                    Ok(status) if !status.exists => return Ok(candidate),
                    Ok(_) => continue,
                    Err(_) => return Ok(candidate),
                }
            }
            Err(_) => return Ok(candidate),
        }
    }
    Err("failed to allocate a free key id".to_string())
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: state.config.service_name.clone(),
        database: if state.database.is_some() {
            "configured"
        } else {
            "disabled"
        },
    })
}

async fn create_job(
    State(state): State<AppState>,
    Json(payload): Json<CreateJobRequest>,
) -> impl IntoResponse {
    let job = state.jobs.create_job(payload.kind.into()).await;
    (
        StatusCode::CREATED,
        Json(CreateJobResponse {
            job,
            contract_address: None,
            key_id: None,
        }),
    )
}

async fn get_job(State(state): State<AppState>, Path(job_id): Path<Uuid>) -> impl IntoResponse {
    match state.jobs.get_job(job_id).await {
        Some(job) => (StatusCode::OK, Json(job)).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn post_topic(
    State(state): State<AppState>,
    Json(payload): Json<PostTopicRequest>,
) -> impl IntoResponse {
    state.coordinator.post(payload.topic, payload.value).await;
    (StatusCode::OK, Json(PostTopicResponse { ok: true }))
}

async fn read_topic(
    State(state): State<AppState>,
    Path(topic): Path<String>,
    Query(query): Query<ReadTopicQuery>,
) -> impl IntoResponse {
    let wait = query.wait.unwrap_or(false);
    let timeout = query.timeout_ms.map(Duration::from_millis);
    match state.coordinator.read(&topic, wait, timeout).await {
        Ok(value) => (StatusCode::OK, Json(ReadTopicResponse { topic, value })).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

async fn list_topics(State(state): State<AppState>) -> Json<ListTopicsResponse> {
    Json(ListTopicsResponse {
        keys: state.coordinator.list().await,
    })
}

async fn clear_topics(State(state): State<AppState>) -> impl IntoResponse {
    state.coordinator.clear().await;
    StatusCode::NO_CONTENT
}

async fn store_secret(
    State(state): State<AppState>,
    Json(payload): Json<StoreSecretRequest>,
) -> impl IntoResponse {
    let Some(keystore) = &state.keystore else {
        return (StatusCode::SERVICE_UNAVAILABLE, "keystore disabled").into_response();
    };

    let plaintext = match B64.decode(payload.plaintext_b64) {
        Ok(bytes) => bytes,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, format!("invalid base64: {err}")).into_response()
        }
    };

    match keystore
        .store_secret(&payload.name, &plaintext, payload.metadata)
        .await
    {
        Ok(path) => (
            StatusCode::CREATED,
            Json(StoreSecretResponse {
                path: path.display().to_string(),
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

async fn load_secret(State(state): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    let Some(keystore) = &state.keystore else {
        return (StatusCode::SERVICE_UNAVAILABLE, "keystore disabled").into_response();
    };

    match keystore.load_secret(&name).await {
        Ok((plaintext, metadata)) => (
            StatusCode::OK,
            Json(LoadSecretResponse {
                plaintext_b64: B64.encode(plaintext),
                metadata,
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::NOT_FOUND, err.to_string()).into_response(),
    }
}

async fn store_party_runtime(
    State(state): State<AppState>,
    Json(payload): Json<StorePartyRuntimeRequest>,
) -> impl IntoResponse {
    let Some(keystore) = &state.keystore else {
        return (StatusCode::SERVICE_UNAVAILABLE, "keystore disabled").into_response();
    };

    match keystore.store_party_runtime(&payload.runtime).await {
        Ok(path) => (
            StatusCode::CREATED,
            Json(StorePartyRuntimeResponse {
                path: path.display().to_string(),
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

async fn load_party_runtime(
    State(state): State<AppState>,
    Query(query): Query<LoadPartyRuntimeQuery>,
) -> impl IntoResponse {
    let Some(keystore) = &state.keystore else {
        return (StatusCode::SERVICE_UNAVAILABLE, "keystore disabled").into_response();
    };

    match keystore
        .load_party_runtime(&query.contract_address, query.key_id, query.party_index)
        .await
    {
        Ok(runtime) => (StatusCode::OK, Json(LoadPartyRuntimeResponse { runtime })).into_response(),
        Err(err) => (StatusCode::NOT_FOUND, err.to_string()).into_response(),
    }
}

async fn add_policy(
    State(state): State<AppState>,
    Json(payload): Json<AddPolicyRequest>,
) -> impl IntoResponse {
    let policy = state.policy.add(payload).await;
    (StatusCode::CREATED, Json(AddPolicyResponse { policy }))
}

async fn list_policies(State(state): State<AppState>) -> Json<ListPoliciesResponse> {
    Json(ListPoliciesResponse {
        policies: state.policy.list().await,
    })
}

async fn remove_policy(
    State(state): State<AppState>,
    Path(policy_id): Path<Uuid>,
) -> impl IntoResponse {
    match state.policy.remove(policy_id).await {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn validate_policy(
    State(state): State<AppState>,
    Json(payload): Json<ValidatePolicyRequest>,
) -> Json<ValidatePolicyResponse> {
    Json(
        state
            .policy
            .validate(&payload.tx_tag, &payload.signing_parties, payload.threshold)
            .await,
    )
}

async fn relay_health(State(state): State<AppState>) -> Json<RelayHealthResponse> {
    Json(RelayHealthResponse {
        relay: state.chain_relay.health().await,
    })
}

async fn runtime_preflight(
    State(state): State<AppState>,
    Query(query): Query<RuntimePreflightQuery>,
) -> impl IntoResponse {
    let relay = state.chain_relay.health().await;
    let sender_gas_ok = relay.gas_ok.unwrap_or(false);
    let key_status = match state
        .chain_relay
        .get_contract_data(&query.contract_address)
        .await
    {
        Ok(contract_state) => threshold_read::threshold_key_status(&contract_state, query.key_id)
            .await
            .ok(),
        Err(_) => None,
    };
    let key_exists_onchain = key_status
        .as_ref()
        .map(|status| status.exists)
        .unwrap_or(false);
    let local_runtime_present = if let Some(keystore) = &state.keystore {
        keystore
            .load_party_runtime(&query.contract_address, query.key_id, 1)
            .await
            .is_ok()
            && keystore
                .load_party_runtime(&query.contract_address, query.key_id, 2)
                .await
                .is_ok()
    } else {
        false
    };
    let mode = query.mode.unwrap_or_else(|| "sign".to_string());
    let (ok, can_create, can_sign, message) = if !relay.configured {
        (
            false,
            false,
            false,
            "Partisia relay is not configured on this backend.".to_string(),
        )
    } else if !sender_gas_ok {
        (
            false,
            false,
            false,
            format!(
                "Partisia sender {} has insufficient gas. Run: {}",
                relay
                    .sender_address
                    .clone()
                    .unwrap_or_else(|| "<unknown>".to_string()),
                relay.recommended_mint_command.clone().unwrap_or_else(|| {
                    "cargo pbc account --net=testnet mintgas <sender>".to_string()
                })
            ),
        )
    } else if mode == "create" {
        (
            true,
            true,
            false,
            "Backend is ready to create a new key.".to_string(),
        )
    } else if !key_exists_onchain {
        (
            false,
            false,
            false,
            "Key does not exist on-chain. Create it first on this backend.".to_string(),
        )
    } else if !local_runtime_present {
        (false, false, false, "Key exists on-chain, but local signing runtime is missing on this backend. Use Create New Key on this backend first.".to_string())
    } else {
        (
            true,
            false,
            true,
            "Backend is ready to sign with this key.".to_string(),
        )
    };

    (
        StatusCode::OK,
        Json(RuntimePreflightResponse {
            preflight: crate::chain_relay::RelayPreflight {
                ok,
                backend_reachable: true,
                relay_configured: relay.configured,
                sender_address: relay.sender_address.clone(),
                sender_gas_balance: relay.sender_gas_balance,
                sender_gas_ok,
                local_runtime_present,
                key_exists_onchain,
                can_create,
                can_sign,
                recommended_mint_command: relay.recommended_mint_command.clone(),
                message,
            },
        }),
    )
        .into_response()
}

async fn relay_contract_state(
    State(state): State<AppState>,
    Path(contract_address): Path<String>,
) -> impl IntoResponse {
    match state.chain_relay.get_contract_data(&contract_address).await {
        Ok(state_json) => (
            StatusCode::OK,
            Json(RelayContractStateResponse {
                contract_address,
                state: state_json,
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_GATEWAY, err.to_string()).into_response(),
    }
}

async fn threshold_key_status(
    State(state): State<AppState>,
    Query(query): Query<ThresholdKeyStatusQuery>,
) -> impl IntoResponse {
    match state
        .chain_relay
        .get_contract_data(&query.contract_address)
        .await
    {
        Ok(contract_state) => {
            match threshold_read::threshold_key_status(&contract_state, query.key_id).await {
                Ok(status) => {
                    (StatusCode::OK, Json::<ThresholdKeyStatusResponse>(status)).into_response()
                }
                Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
            }
        }
        Err(err) => (StatusCode::BAD_GATEWAY, err.to_string()).into_response(),
    }
}

async fn threshold_task_signature(
    State(state): State<AppState>,
    Query(query): Query<ThresholdTaskSignatureQuery>,
) -> impl IntoResponse {
    match state
        .chain_relay
        .get_contract_data(&query.contract_address)
        .await
    {
        Ok(contract_state) => {
            let task = threshold_read::threshold_task_signature(
                &contract_state,
                query.key_id,
                query.task_id,
            )
            .await;
            match task {
                Ok(task) => {
                    (StatusCode::OK, Json::<ThresholdTaskSignatureResponse>(task)).into_response()
                }
                Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
            }
        }
        Err(err) => (StatusCode::BAD_GATEWAY, err.to_string()).into_response(),
    }
}

async fn generate_dkg_share(Json(payload): Json<GenerateDkgShareRequest>) -> impl IntoResponse {
    let seed = payload
        .seed_hex
        .as_deref()
        .and_then(|s| hex::decode(s).ok());
    match dkg::generate_threshold_dkg_share(
        payload.party_index,
        payload.num_parties,
        seed.as_deref(),
    ) {
        Ok(share) => match dkg::generate_schnorr_proof(
            &share.secret_scalar_hex,
            &share.public_key_share_hex,
            share.party_index,
        ) {
            Ok(schnorr_proof) => (
                StatusCode::OK,
                Json(GenerateDkgShareResponse {
                    share,
                    schnorr_proof,
                }),
            )
                .into_response(),
            Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
        },
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn combine_shamir_shares(
    Json(payload): Json<CombineShamirSharesRequest>,
) -> impl IntoResponse {
    match dkg::combine_shamir_shares(payload.party_index, &payload.shares) {
        Ok(share) => (StatusCode::OK, Json(CombineShamirSharesResponse { share })).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn verify_subshare(Json(payload): Json<VerifySubshareRequest>) -> impl IntoResponse {
    match dkg::verify_feldman_subshare(
        &payload.subshare_hex,
        &payload.c_i0_hex,
        &payload.c_i1_hex,
        payload.recipient_party_index,
    ) {
        Ok(valid) => (StatusCode::OK, Json(VerifySubshareResponse { valid })).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn combined_public_key(Json(payload): Json<CombinedPublicKeyRequest>) -> impl IntoResponse {
    match dkg::compute_combined_public_key(&payload.shares) {
        Ok(public_key_hex) => (
            StatusCode::OK,
            Json(CombinedPublicKeyResponse { public_key_hex }),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn paillier_keygen(Json(payload): Json<PaillierKeygenRequest>) -> impl IntoResponse {
    match paillier::paillier_keygen(payload.bit_length.unwrap_or(1024)) {
        Ok(key_pair) => (StatusCode::OK, Json(PaillierKeygenResponse { key_pair })).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn mta_round1(Json(payload): Json<MtARound1Request>) -> impl IntoResponse {
    match mta::mta_round1_a(
        &payload.a_hex,
        payload.paillier_key_pair.public_key,
        payload.session,
    ) {
        Ok(message) => (StatusCode::OK, Json(MtARound1Response { message })).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn mta_round2(Json(payload): Json<MtARound2Request>) -> impl IntoResponse {
    match mta::mta_round2_b(
        &payload.message,
        &payload.b_hex,
        payload.expected_session.as_ref(),
    ) {
        Ok((message, output_b)) => (
            StatusCode::OK,
            Json(MtARound2Response { message, output_b }),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn mta_finalize(Json(payload): Json<MtAFinalizeRequest>) -> impl IntoResponse {
    match mta::mta_finalize_a(
        &payload.message,
        &payload.paillier_key_pair.public_key,
        &payload.paillier_key_pair.private_key,
        payload.expected_session.as_ref(),
    ) {
        Ok(output_a) => (StatusCode::OK, Json(MtAFinalizeResponse { output_a })).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn gg20_init_party(Json(payload): Json<GG20InitPartyRequest>) -> impl IntoResponse {
    match gg20::gg20_init_party(
        payload.party_index,
        &payload.x_i_hex,
        payload.msg_hash_hex.as_deref(),
        payload.session_id,
    ) {
        Ok(party) => (StatusCode::OK, Json(GG20InitPartyResponse { party })).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn gg20_run_mta(Json(payload): Json<GG20RunMtaRequest>) -> impl IntoResponse {
    let mut parties = payload.parties;
    match gg20::gg20_run_mta_rounds(&mut parties) {
        Ok(()) => (StatusCode::OK, Json(GG20RunMtaResponse { parties })).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn gg20_compute_r(Json(payload): Json<GG20ComputeRRequest>) -> impl IntoResponse {
    match gg20::gg20_compute_r(&payload.parties) {
        Ok((r_hex, r_bytes_hex, r_point_compressed_hex, recovery_id)) => (
            StatusCode::OK,
            Json(GG20ComputeRResponse {
                r_hex,
                r_bytes_hex,
                r_point_compressed_hex,
                recovery_id,
            }),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn gg20_sign_foundation(Json(payload): Json<GG20SignFoundationRequest>) -> impl IntoResponse {
    let party_inputs = payload
        .party_inputs
        .into_iter()
        .map(|p| (p.party_index, p.x_i_hex))
        .collect::<Vec<_>>();
    match gg20::gg20_sign_foundation(&party_inputs, &payload.msg_hash_hex, payload.session_id) {
        Ok(signature) => (
            StatusCode::OK,
            Json(GG20SignFoundationResponse { signature }),
        )
            .into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn start_create_key_workflow(
    State(state): State<AppState>,
    Json(payload): Json<StartCreateKeyWorkflowRequest>,
) -> impl IntoResponse {
    let contract_address = payload.contract_address.clone();
    let key_id = payload.key_id;
    let job = orchestrator::start_create_key_workflow(state, payload).await;
    (
        StatusCode::CREATED,
        Json(CreateJobResponse {
            key_id: Some(key_id),
            contract_address: Some(contract_address),
            job,
        }),
    )
        .into_response()
}

async fn start_reuse_sign_workflow(
    State(state): State<AppState>,
    Json(payload): Json<StartReuseSignWorkflowRequest>,
) -> impl IntoResponse {
    let contract_address = payload.contract_address.clone();
    let key_id = payload.key_id;
    let job = orchestrator::start_reuse_sign_workflow(state, payload).await;
    (
        StatusCode::CREATED,
        Json(CreateJobResponse {
            key_id: Some(key_id),
            contract_address: Some(contract_address),
            job,
        }),
    )
        .into_response()
}

async fn start_reuse_sign_v2_workflow(
    State(state): State<AppState>,
    Json(payload): Json<StartReuseSignWorkflowRequest>,
) -> impl IntoResponse {
    let contract_address = payload.contract_address.clone();
    let key_id = payload.key_id;
    let job = orchestrator::start_reuse_sign_v2_workflow(state, payload).await;
    (
        StatusCode::CREATED,
        Json(CreateJobResponse {
            key_id: Some(key_id),
            contract_address: Some(contract_address),
            job,
        }),
    )
        .into_response()
}

async fn build_eth_transfer(
    State(state): State<AppState>,
    Json(payload): Json<BuildEthTransferRequest>,
) -> impl IntoResponse {
    let transaction = UnsignedEthTransfer {
        from: payload.from,
        to: payload.to,
        value_wei: payload.value_wei,
        chain_id: state.evm_broadcaster.chain_id(),
        nonce: payload.nonce,
        max_fee_per_gas: payload.max_fee_per_gas,
        max_priority_fee_per_gas: payload.max_priority_fee_per_gas,
        gas_limit: payload.gas_limit.unwrap_or(21_000),
        tx_type: "eip1559".to_string(),
    };
    (
        StatusCode::OK,
        Json(BuildEthTransferResponse { transaction }),
    )
        .into_response()
}

async fn broadcast_signed_transaction(
    State(state): State<AppState>,
    Json(payload): Json<BroadcastSignedTransactionRequest>,
) -> impl IntoResponse {
    match state
        .evm_broadcaster
        .broadcast_signed_transaction(&payload.signed_tx_hex)
        .await
    {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(err) => (StatusCode::BAD_GATEWAY, err.to_string()).into_response(),
    }
}

async fn active_runtime(State(state): State<AppState>) -> Json<ActiveRuntimeResponse> {
    Json(ActiveRuntimeResponse {
        ok: true,
        runtime: state.active_runtime.read().await.clone(),
    })
}
