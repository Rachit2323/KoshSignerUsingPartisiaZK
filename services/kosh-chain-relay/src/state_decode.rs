use anyhow::{anyhow, Result};
use base64::Engine;
use kosh_zk_signer::signing_state::{SigningInformation, ZkKeyGenPhase, ZkKeyState, ZkSigningPhase};
use pbc_traits::ReadWriteState;
use serde_json::{Map, Value, json};
use std::panic::{AssertUnwindSafe, catch_unwind};

pub fn normalize_signer_state(raw: &Value) -> Result<Value> {
    let Some(entries) = find_avl_tree_entries(raw, 0) else {
        return Ok(raw.clone());
    };

    let mut decoded_keys = Map::new();
    for entry in entries {
        let Some((key_id, key_state)) = decode_key_entry(entry)? else {
            continue;
        };
        decoded_keys.insert(key_id.to_string(), key_state_to_json(raw, &key_state));
    }

    if decoded_keys.is_empty() {
        return Ok(raw.clone());
    }

    if let Some(existing_keys) = raw.get("keys").and_then(Value::as_object) {
        let mut merged_root = raw.clone();
        let keys_value = merged_root
            .get_mut("keys")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| anyhow!("expected keys object in normalized signer state"))?;

        for (key_id, decoded) in decoded_keys {
            if let Some(existing) = existing_keys.get(&key_id).and_then(Value::as_object) {
                let mut merged = decoded.as_object().cloned().unwrap_or_default();
                for (field, value) in existing {
                    merged.entry(field.clone()).or_insert_with(|| value.clone());
                }
                keys_value.insert(key_id, Value::Object(merged));
            } else {
                keys_value.insert(key_id, decoded);
            }
        }

        Ok(merged_root)
    } else {
        Ok(json!({ "keys": decoded_keys }))
    }
}

fn decode_key_entry(entry: &Value) -> Result<Option<(u32, ZkKeyState)>> {
    let key_b64 = match entry
        .get("key")
        .and_then(|key| key.get("data"))
        .and_then(|data| data.get("data"))
        .and_then(Value::as_str)
    {
        Some(v) => v,
        None => return Ok(None),
    };
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|err| anyhow!("decode avl key: {err}"))?;
    if key_bytes.len() != 4 {
        return Ok(None);
    }
    let key_id = u32::from_le_bytes([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]]);

    let value_b64 = entry
        .get("value")
        .and_then(|value| value.get("data"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing avl tree value bytes"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value_b64)
        .map_err(|err| anyhow!("decode avl tree value: {err}"))?;
    let decoded = catch_unwind(AssertUnwindSafe(|| {
        ZkKeyState::state_read_from(&mut bytes.as_slice())
    }))
    .map_err(|_| anyhow!("panic while decoding avl tree value"))?;

    Ok(Some((key_id, decoded)))
}

fn key_state_to_json(root: &Value, key: &ZkKeyState) -> Value {
    let signing_information = read_signing_information_from_avl(root, &key.signing_information)
        .into_iter()
        .map(|(task_id, info)| (task_id.to_string(), signing_information_to_json(&info)))
        .collect::<Map<String, Value>>();

    let gg20_delta_zk_vars = key
        .gg20_delta_zk_vars
        .iter()
        .map(stored_share_var_to_json)
        .collect::<Vec<_>>();
    let zk_psig_kinv_vars = key
        .zk_psig_kinv_vars
        .iter()
        .map(stored_share_var_to_json)
        .collect::<Vec<_>>();

    json!({
        "public_key": key.public_key.as_ref().map(hex::encode),
        "keygen_phase": { "discriminant": keygen_phase_discriminant(&key.keygen_phase) },
        "signing_phase": { "discriminant": signing_phase_discriminant(&key.signing_phase) },
        "ts_r_bytes": hex::encode(&key.ts_r_bytes),
        "ts_recovery_id": key.ts_recovery_id,
        "ts_active": key.ts_active,
        "gg20_delta_zk_count": key.gg20_delta_zk_count,
        "gg20_delta_zk_expected": key.gg20_delta_zk_expected,
        "gg20_delta_zk_vars_len": key.gg20_delta_zk_vars.len(),
        "gg20_delta_zk_vars": gg20_delta_zk_vars,
        "pqc_approval_task_id": key.pqc_approval_task_id,
        "pqc_approval_deadline_block": key.pqc_approval_deadline_block,
        "gg20_task_id": key.gg20_task_id,
        "zk_psig_kinv_count": key.zk_psig_kinv_count,
        "zk_psig_kinv_expected": key.zk_psig_kinv_expected,
        "zk_psig_kinv_vars_len": key.zk_psig_kinv_vars.len(),
        "zk_psig_kinv_vars": zk_psig_kinv_vars,
        "signing_information": signing_information,
    })
}

fn stored_share_var_to_json(var: &kosh_zk_signer::signing_state::StoredShareVar) -> Value {
    json!({
        "variable_id": var.variable_id,
        "key_id": var.key_id,
        "share_index": var.share_index,
        "is_high_half": var.is_high_half,
    })
}

fn signing_information_to_json(info: &SigningInformation) -> Value {
    json!({
        "verified": info.verified,
        "signature": info.signature.as_ref().map(hex::encode),
        "recovery_id": info.recovery_id,
    })
}

fn read_signing_information_from_avl(
    state: &Value,
    map: &impl ReadWriteState,
) -> Vec<(u32, SigningInformation)> {
    let tree_id = avl_tree_id(map);
    let Some(entries) = find_avl_tree_entries(state, tree_id) else {
        return vec![];
    };

    let mut decoded = entries
        .iter()
        .filter_map(|entry| {
            let key_b64 = entry
                .get("key")
                .and_then(|key| key.get("data"))
                .and_then(|data| data.get("data"))
                .and_then(Value::as_str)?;
            let key_bytes = base64::engine::general_purpose::STANDARD
                .decode(key_b64)
                .ok()?;
            if key_bytes.len() != 4 {
                return None;
            }
            let task_id =
                u32::from_le_bytes([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]]);
            let value_b64 = entry
                .get("value")
                .and_then(|value| value.get("data"))
                .and_then(Value::as_str)?;
            let value_bytes = base64::engine::general_purpose::STANDARD
                .decode(value_b64)
                .ok()?;
            let info = SigningInformation::state_read_from(&mut value_bytes.as_slice());
            Some((task_id, info))
        })
        .collect::<Vec<_>>();
    decoded.sort_by_key(|(task_id, _)| *task_id);
    decoded
}

fn avl_tree_id(map: &impl ReadWriteState) -> u64 {
    let mut bytes = Vec::new();
    map.state_write_to(&mut bytes)
        .expect("serialize avl tree id");
    i32::from_le_bytes(bytes[..4].try_into().expect("tree id bytes")) as u64
}

fn find_avl_tree_entries<'a>(state: &'a Value, tree_id: u64) -> Option<&'a Vec<Value>> {
    avl_trees_root(state)?
        .iter()
        .find(|tree| tree.get("key").and_then(Value::as_u64) == Some(tree_id))
        .and_then(|tree| tree.get("value"))
        .and_then(|value| value.get("avlTree"))
        .and_then(Value::as_array)
}

fn avl_trees_root(state: &Value) -> Option<&Vec<Value>> {
    state
        .get("openState")
        .and_then(|value| value.get("avlTrees"))
        .and_then(Value::as_array)
        .or_else(|| {
            state
                .get("serializedContract")
                .and_then(|value| value.get("openState"))
                .and_then(|value| value.get("avlTrees"))
                .and_then(Value::as_array)
        })
}

fn keygen_phase_discriminant(phase: &ZkKeyGenPhase) -> u64 {
    match phase {
        ZkKeyGenPhase::WaitingForDealer {} => 0,
        ZkKeyGenPhase::SubmittingShares {} => 1,
        ZkKeyGenPhase::Complete {} => 2,
        ZkKeyGenPhase::DkgCommitting {} => 3,
        ZkKeyGenPhase::DkgRevealing {} => 4,
        ZkKeyGenPhase::DkgFinalized {} => 5,
    }
}

fn signing_phase_discriminant(phase: &ZkSigningPhase) -> u64 {
    match phase {
        ZkSigningPhase::Idle {} => 0,
        ZkSigningPhase::ReconstructingKey { .. } => 1,
        ZkSigningPhase::Signing { .. } => 2,
        ZkSigningPhase::Complete { .. } => 3,
        ZkSigningPhase::ThresholdSigning { .. } => 4,
        ZkSigningPhase::NonceCommitting { .. } => 5,
        ZkSigningPhase::NonceRevealing { .. } => 6,
    }
}
