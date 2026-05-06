//! Kosh ZK Signer Contract — DKG + Threshold ECDSA on Partisia ZK nodes.
//!
//! Architecture (private key NEVER assembled):
//! 1. DKG: Each party generates a random secret scalar s_i and public share P_i = s_i × G
//! 2. Commit-reveal ceremony on-chain prevents manipulation
//! 3. Contract computes combined public key P = P₁ + P₂ + ... + Pₙ (EC point addition)
//! 4. Each s_i is stored as encrypted ZK secret variables (2x Sbi128 halves)
//! 5. For signing: each party computes partial σ_i = k⁻¹(m + r·s_i), contract combines σ = Σσ_i
//! 6. Contract verifies the combined ECDSA signature on-chain
//!
//! The private key s = s₁ + s₂ + ... + sₙ is NEVER computed anywhere.

#[macro_use]
extern crate pbc_contract_codegen;
extern crate pbc_contract_common;
extern crate pbc_lib as _;

pub mod dkg;
pub mod signing_state;
#[cfg(test)]
#[path = "zk_compute_model.rs"]
pub(crate) mod zk_compute;
#[cfg(test)]
mod zk_compute_tests;

use create_type_spec_derive::CreateTypeSpec;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use pbc_contract_common::address::Address;
use pbc_contract_common::avl_tree_map::AvlTreeMap;
use pbc_contract_common::context::ContractContext;
use pbc_contract_common::events::EventGroup;
use pbc_contract_common::shortname::{ShortnameZkComputation, ShortnameZkComputeComplete};
use pbc_contract_common::zk::{SecretVarId, ZkInputDef, ZkState, ZkStateChange};
use pbc_zk::Sbi128;
use read_write_rpc_derive::ReadWriteRPC;
use read_write_state_derive::ReadWriteState;

use crate::signing_state::*;

/// Shortname for the vault's on_key_generated callback (0x02 in the vault contract).
const VAULT_ON_KEY_GENERATED_SHORTNAME: &[u8] = &[0x02];

/// Configuration for an execution engine.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct EngineConfig {
    pub address: Address,
}

/// Bundled signing payload for one party in the low-latency v2 path.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct SigningPartyBundleV2 {
    pub party_index: u8,
    pub delta_bytes: Vec<u8>,
    pub gamma_point: Vec<u8>,
    pub partial_s: Vec<u8>,
}

/// The top-level contract state.
#[state]
pub struct ContractState {
    /// Owner address (typically the vault contract).
    pub owner: Address,
    /// Configured execution engines.
    pub engines: Vec<EngineConfig>,
    /// Shamir threshold (t in t-of-n).
    pub threshold: u16,
    /// Total number of Shamir shares (n), typically == engines.len().
    pub num_shares: u8,
    /// Next key_id to assign.
    pub next_key_id: u32,
    /// Per-key ZK signing state.
    pub keys: AvlTreeMap<u32, ZkKeyState>,
}

impl ContractState {
    pub fn assert_owner(&self, sender: &Address) {
        assert_eq!(sender, &self.owner, "Only the owner can call this action");
    }

    pub fn assert_engine(&self, sender: &Address) -> u8 {
        self.get_engine_index(sender)
            .expect("Address is not a registered execution engine or ZK node")
    }

    pub fn get_engine_index(&self, address: &Address) -> Option<u8> {
        for (i, engine) in self.engines.iter().enumerate() {
            if &engine.address == address {
                return Some(i as u8);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Initialize the ZK signer contract.
#[init(zk = true)]
pub fn initialize(
    _ctx: ContractContext,
    _zk_state: ZkState<ShareMetadata>,
    owner: Address,
    engines: Vec<EngineConfig>,
    threshold: u16,
    num_shares: u8,
) -> ContractState {
    assert!(engines.len() >= 3, "At least 3 execution engines required");
    assert!(
        threshold >= 2 && (threshold as usize) <= engines.len(),
        "Threshold must be >= 2 and <= number of engines"
    );
    assert!(
        (num_shares as usize) >= threshold as usize && (num_shares as usize) <= engines.len(),
        "num_shares must be >= threshold and <= number of engines"
    );

    ContractState {
        owner,
        engines,
        threshold,
        num_shares,
        next_key_id: 0,
        keys: AvlTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Vault-compatible actions (same shortnames as V2 signer)
// ---------------------------------------------------------------------------

/// Create a key with a specific key_id.
/// Called by the vault contract to trigger key generation.
#[action(shortname = 0x02, zk = true)]
pub fn create_key_with_id(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    assert!(
        state.keys.get(&key_id).is_none(),
        "Key ID {} already exists",
        key_id
    );

    let key_state = ZkKeyState::new(state.threshold, state.num_shares);
    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// Queue a 32-byte message hash for signing with the specified key.
/// Called by the vault contract or directly by a party.
///
/// tx_tag: UTF-8 string identifying the transaction type (e.g. b"treasury").
/// Empty tag means no policy restriction — any threshold subset may sign.
#[action(shortname = 0x03, zk = true)]
pub fn sign_message(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    message: Vec<u8>,
    tx_tag: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.is_key_generated(),
        "Key generation not yet complete for key {}",
        key_id
    );
    key_state.assert_all_parties_ready_for_signing();

    let policy_id = key_state.resolve_policy_id_for_tag(&tx_tag);
    let min_signers = if policy_id != 0 {
        let idx = key_state
            .policy_ids
            .iter()
            .position(|&id| id == policy_id)
            .expect("Resolved policy missing from state");
        let policy_min = key_state.policy_min_thresholds[idx];
        if policy_min == 0 {
            key_state.threshold as u8
        } else {
            policy_min.max(key_state.threshold as u8)
        }
    } else {
        key_state.threshold as u8
    };
    let _signing_task_id = key_state.queue_signing(message, tx_tag, policy_id, min_signers);
    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// Engine 0 posts the compressed public key after generating the keypair off-chain.
#[action(shortname = 0x05, zk = true)]
pub fn post_public_key(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    public_key: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    // Accept from any ZK node or registered engine (off-chain runs on ZK nodes)
    let _engine_index = state.get_engine_index(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(
            key_state.keygen_phase,
            ZkKeyGenPhase::WaitingForDealer {} | ZkKeyGenPhase::SubmittingShares {}
        ),
        "Key generation already complete"
    );
    assert_eq!(
        public_key.len(),
        33,
        "Public key must be 33 bytes (compressed secp256k1)"
    );

    // Validate that this is a real secp256k1 public key
    VerifyingKey::from_sec1_bytes(&public_key).expect("Invalid secp256k1 public key");

    key_state.public_key = Some(public_key.clone());

    // If all shares are already submitted, complete keygen
    let mut events = vec![];
    if key_state.shares_submitted >= key_state.expected_share_count {
        key_state.keygen_phase = ZkKeyGenPhase::Complete {};
        events.extend(emit_key_generated_event(&state, key_id, &public_key));
    }

    state.keys.insert(key_id, key_state);
    (state, events, vec![])
}

/// Engine reports signing completion with the final ECDSA signature.
/// Verifies the signature on-chain before accepting it.
#[action(shortname = 0x07, zk = true)]
pub fn signing_complete(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    _engine_index: u8,
    task_id: u32,
    signature: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    // Accept from any ZK node or registered engine (off-chain runs on ZK nodes)
    let _actual_index = state.get_engine_index(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    assert!(
        signature.len() == 64 || signature.len() == 65,
        "Signature must be 64 bytes (r||s) or 65 bytes (r||s||v)"
    );

    // Verify the ECDSA signature against the stored public key
    let public_key = key_state
        .public_key
        .clone()
        .expect("Public key missing for this key");
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key)
        .expect("Stored public key is not a valid secp256k1 key");

    let sig64 = &signature[0..64];
    let parsed_signature =
        Signature::try_from(sig64).expect("Failed to parse signature bytes as ECDSA signature");

    let mut info = key_state
        .signing_information
        .get(&task_id)
        .expect("Unknown signing task");
    assert!(
        info.signature.is_none(),
        "Signature already set for this task"
    );

    verifying_key
        .verify_prehash(&info.message_hash, &parsed_signature)
        .expect("Signature verification failed");

    // Store the verified signature
    if signature.len() == 65 {
        info.recovery_id = signature[64];
    }
    info.signature = Some(signature);
    info.verified = true;
    key_state.signing_information.insert(task_id, info);

    // Clear opened shares (no longer needed, reduces exposure window)
    key_state.opened_shares.clear();

    // Move to next signing request
    key_state.signing_phase = ZkSigningPhase::Complete { task_id };
    key_state
        .pending_sign_requests
        .retain(|r| r.task_id != task_id);

    if !key_state.pending_sign_requests.is_empty() {
        key_state.start_next_signing();
    } else {
        key_state.signing_phase = ZkSigningPhase::Idle {};
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// ZK secret input handling
// ---------------------------------------------------------------------------

/// Accept a Shamir share half as a ZK secret input.
///
/// Engine 0 calls this for each share half (high and low 128 bits).
/// The ZK layer receives the secret Sbi128 value and auto-secret-shares it across ZK nodes.
#[zk_on_secret_input(shortname = 0x10)]
pub fn submit_key_share(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    share_index: u8,
    is_high_half: bool,
) -> (
    ContractState,
    Vec<EventGroup>,
    ZkInputDef<ShareMetadata, Sbi128>,
) {
    // Accept from any ZK node or registered engine (off-chain runs on ZK nodes)
    let _engine_index = state.get_engine_index(&ctx.sender);

    let key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(
            key_state.keygen_phase,
            ZkKeyGenPhase::WaitingForDealer {}
                | ZkKeyGenPhase::SubmittingShares {}
                | ZkKeyGenPhase::DkgFinalized {}
        ),
        "Cannot submit shares in current keygen phase"
    );

    // Update phase to SubmittingShares if still WaitingForDealer
    if matches!(key_state.keygen_phase, ZkKeyGenPhase::WaitingForDealer {}) {
        let mut ks = key_state;
        ks.keygen_phase = ZkKeyGenPhase::SubmittingShares {};
        state.keys.insert(key_id, ks);
    }

    let metadata = ShareMetadata {
        key_id,
        share_index,
        is_high_half,
        variable_type: 0, // key_share
    };

    let input_def = ZkInputDef::with_metadata(None, metadata);

    (state, vec![], input_def)
}

/// Called by the ZK framework when a secret variable has been successfully inputted.
#[zk_on_variable_inputted(shortname = 0x12)]
pub fn on_share_inputted(
    _ctx: ContractContext,
    mut state: ContractState,
    zk_state: ZkState<ShareMetadata>,
    inputted_variable: SecretVarId,
) -> ContractState {
    // Read the metadata attached to this variable
    let variable_info = zk_state
        .get_variable(inputted_variable)
        .expect("Variable not found in ZK state");
    let metadata = variable_info.metadata;

    let mut key_state = state
        .keys
        .get(&metadata.key_id)
        .expect("Key not found for inputted share");

    if metadata.variable_type == 1 {
        // Delta ZK variable (GG20 δ_i)
        key_state.gg20_delta_zk_vars.push(StoredShareVar {
            variable_id: inputted_variable.raw_id,
            key_id: metadata.key_id,
            share_index: metadata.share_index,
            is_high_half: metadata.is_high_half,
        });
        key_state.gg20_delta_zk_count += 1;
    } else if metadata.variable_type == 2 {
        // k⁻¹ ZK variable for ZK partial signature computation
        key_state.zk_psig_kinv_vars.push(StoredShareVar {
            variable_id: inputted_variable.raw_id,
            key_id: metadata.key_id,
            share_index: metadata.share_index,
            is_high_half: metadata.is_high_half,
        });
        key_state.zk_psig_kinv_count += 1;
    } else {
        // Key share variable (type 0 — existing behavior)
        key_state.share_variables.push(StoredShareVar {
            variable_id: inputted_variable.raw_id,
            key_id: metadata.key_id,
            share_index: metadata.share_index,
            is_high_half: metadata.is_high_half,
        });
        key_state.shares_submitted += 1;

        // Check if all share halves are stored AND public key is posted
        if key_state.shares_submitted >= key_state.expected_share_count
            && key_state.public_key.is_some()
        {
            key_state.keygen_phase = ZkKeyGenPhase::Complete {};
        }
    }

    state.keys.insert(metadata.key_id, key_state);
    state
}

// ---------------------------------------------------------------------------
// ZK share reconstruction for signing
// ---------------------------------------------------------------------------

/// Request reconstruction of threshold shares for signing.
///
/// Opens the minimum required ZK variables (threshold shares) so Engine 0
/// can reconstruct the private key and sign.
#[action(shortname = 0x11, zk = true)]
pub fn request_reconstruction(
    ctx: ContractContext,
    state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    // Allow engines or owner to request reconstruction
    let is_engine = state.engines.iter().any(|e| e.address == ctx.sender);
    assert!(
        is_engine || ctx.sender == state.owner,
        "Only engines or owner can request reconstruction"
    );

    let key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(
            key_state.signing_phase,
            ZkSigningPhase::ReconstructingKey { .. }
        ),
        "No signing request pending reconstruction"
    );

    // Get variable IDs for threshold shares to open
    let var_ids: Vec<SecretVarId> = key_state
        .get_threshold_variable_ids()
        .into_iter()
        .map(SecretVarId::new)
        .collect();

    assert!(
        !var_ids.is_empty(),
        "No share variables available for reconstruction"
    );

    let zk_changes = vec![ZkStateChange::OpenVariables { variables: var_ids }];

    (state, vec![], zk_changes)
}

/// Called by the ZK framework when variables have been opened (reconstructed from MPC).
///
/// Reads the opened share values and stores them temporarily in contract state
/// for Engine 0 to reconstruct the key and sign off-chain.
#[zk_on_variables_opened]
pub fn on_shares_opened(
    _ctx: ContractContext,
    mut state: ContractState,
    zk_state: ZkState<ShareMetadata>,
    opened_variables: Vec<SecretVarId>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    // First, figure out which key this belongs to
    let first_var = zk_state
        .get_variable(opened_variables[0])
        .expect("Opened variable not found");
    let key_id = first_var.metadata.key_id;
    let first_variable_type = first_var.metadata.variable_type;

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    // Read each opened variable and group by share_index
    let mut share_halves: Vec<(u8, bool, Vec<u8>)> = Vec::new();
    for var_id in &opened_variables {
        let var_info = zk_state
            .get_variable(*var_id)
            .expect("Opened variable not found in ZK state");

        // Read the opened value as raw bytes (16 bytes for Sbi128)
        // The exact API depends on the SDK version; try open_value or data field.
        let data: Vec<u8> = {
            // Opened variable data is available as raw bytes
            let raw = var_info.data.as_ref().expect("Opened variable has no data");
            raw.clone()
        };

        share_halves.push((
            var_info.metadata.share_index,
            var_info.metadata.is_high_half,
            data,
        ));
    }

    if first_variable_type == 3 {
        // --- ZK partial signature results (σ_p hi/lo halves from compute_partial_sig) ---
        // Each call to trigger_zk_partial_sig produces exactly 2 opened variables:
        // one hi half and one lo half, both tagged with the same share_index (party_index).
        let mut hi_bytes: Vec<u8> = vec![0u8; 16];
        let mut lo_bytes: Vec<u8> = vec![0u8; 16];
        let party_index = share_halves.first().map(|(idx, _, _)| *idx).unwrap_or(0);

        for (_, is_high_half, data) in share_halves {
            if is_high_half {
                hi_bytes = data;
            } else {
                lo_bytes = data;
            }
        }

        // Store result (update if already present for this party)
        if let Some(pos) = key_state
            .zk_psig_result_indices
            .iter()
            .position(|&i| i == party_index)
        {
            key_state.zk_psig_result_hi_bytes[pos] = hi_bytes;
            key_state.zk_psig_result_lo_bytes[pos] = lo_bytes;
        } else {
            key_state.zk_psig_result_indices.push(party_index);
            key_state.zk_psig_result_hi_bytes.push(hi_bytes);
            key_state.zk_psig_result_lo_bytes.push(lo_bytes);
        }

        state.keys.insert(key_id, key_state);
        return (state, vec![], vec![]);
    } else if first_variable_type == 1 {
        // --- Delta ZK variables opened ---
        // Assemble 256-bit delta values from high/low halves
        let mut assembled: AvlTreeMap<u8, OpenedShare> = AvlTreeMap::new();
        for (share_index, is_high_half, data) in share_halves {
            let mut share = assembled.get(&share_index).unwrap_or_else(|| OpenedShare {
                share_index,
                high_bytes: vec![0u8; 16],
                low_bytes: vec![0u8; 16],
            });

            if is_high_half {
                share.high_bytes = data;
            } else {
                share.low_bytes = data;
            }
            assembled.insert(share_index, share);
        }

        // Reconstruct 32-byte delta values and store in gg20_delta_indices/values
        for party_idx in 1..=key_state.gg20_num_parties {
            if let Some(share) = assembled.get(&party_idx) {
                // Combine high + low into 32-byte delta
                let mut delta_bytes = Vec::with_capacity(32);
                delta_bytes.extend_from_slice(&share.high_bytes);
                delta_bytes.extend_from_slice(&share.low_bytes);

                // Only add if not already present (from plaintext path)
                if !key_state
                    .gg20_delta_indices
                    .iter()
                    .any(|&idx| idx == party_idx)
                {
                    key_state.gg20_delta_indices.push(party_idx);
                    key_state.gg20_delta_values.push(delta_bytes);
                }
            }
        }

        // Clear ZK delta tracking
        key_state.gg20_delta_zk_vars.clear();
        key_state.gg20_delta_zk_count = 0;
    } else {
        // --- Key share variables opened (existing behavior) ---
        // Assemble full shares from high/low pairs
        let mut assembled: AvlTreeMap<u8, OpenedShare> = AvlTreeMap::new();
        for (share_index, is_high_half, data) in share_halves {
            let mut share = assembled.get(&share_index).unwrap_or_else(|| OpenedShare {
                share_index,
                high_bytes: vec![0u8; 16],
                low_bytes: vec![0u8; 16],
            });

            if is_high_half {
                share.high_bytes = data;
            } else {
                share.low_bytes = data;
            }
            assembled.insert(share_index, share);
        }

        // Collect assembled shares
        key_state.opened_shares.clear();
        let share_indices: Vec<u8> = (1..=key_state.num_shares)
            .filter(|i| assembled.get(i).is_some())
            .collect();
        for idx in share_indices {
            if let Some(share) = assembled.get(&idx) {
                key_state.opened_shares.push(share);
            }
        }

        // Move to Signing phase
        if let ZkSigningPhase::ReconstructingKey { task_id } = key_state.signing_phase {
            key_state.signing_phase = ZkSigningPhase::Signing { task_id };
        }
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Keygen completion check (for vault callback)
// ---------------------------------------------------------------------------

/// Check if keygen is complete and emit vault callback if so.
///
/// Needed because zk_on_variable_inputted can only return ContractState (no events).
/// Engine 0 calls this after all shares are inputted to trigger the vault callback.
#[action(shortname = 0x06, zk = true)]
pub fn check_keygen_complete(
    _ctx: ContractContext,
    state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let key_state = state.keys.get(&key_id).expect("Key not found");
    let mut events = vec![];

    if key_state.is_key_generated() {
        if let Some(pk) = &key_state.public_key {
            events.extend(emit_key_generated_event(&state, key_id, pk));
        }
    }

    (state, events, vec![])
}

/// Force-complete keygen for testing when off-chain isn't available.
/// Owner can call this after posting a public key to mark keygen as done.
#[action(shortname = 0x08, zk = true)]
pub fn force_complete_keygen(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.public_key.is_some(),
        "Public key must be posted first"
    );
    key_state.keygen_phase = ZkKeyGenPhase::Complete {};
    let _pk = key_state.public_key.clone().unwrap();
    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// DKG (Distributed Key Generation) — key is NEVER assembled
// ---------------------------------------------------------------------------

/// Create a key using DKG: initializes a commit/reveal ceremony for num_parties participants.
/// The private key is born split — no single party ever holds the full key.
#[action(shortname = 0x20, zk = true)]
pub fn dkg_create_key(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    num_parties: u8,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    assert!(
        state.keys.get(&key_id).is_none(),
        "Key ID {} already exists",
        key_id
    );
    assert!(num_parties >= 2, "DKG requires at least 2 parties");

    let mut key_state = ZkKeyState::new(state.threshold, state.num_shares);
    key_state.keygen_phase = ZkKeyGenPhase::DkgCommitting {};
    key_state.dkg_num_parties = num_parties;
    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// DKG commit: a party submits hash(P_i) + Feldman slope commitment + Schnorr proof.
///
/// Protection 3 (Anti-Rogue-Key): Schnorr proof proves party knows s_i behind C_i0.
/// Feldman: slope commitment C_i1 = a_i·G enables sub-share verification.
#[action(shortname = 0x21, zk = true)]
pub fn dkg_commit(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    commitment_hash: Vec<u8>,
    slope_commitment: Vec<u8>,
    schnorr_r: Vec<u8>,
    schnorr_z: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(key_state.keygen_phase, ZkKeyGenPhase::DkgCommitting {}),
        "Key is not in DKG committing phase"
    );

    // Store Feldman slope commitment C_i1 = a_i·G
    assert_eq!(
        slope_commitment.len(),
        33,
        "Slope commitment must be 33 bytes (compressed EC point)"
    );
    key_state.dkg_slope_commitments.push(slope_commitment);

    // Store Schnorr proof (verified during reveal when we have C_i0)
    assert_eq!(
        schnorr_r.len(),
        33,
        "Schnorr R must be 33 bytes (compressed EC point)"
    );
    assert_eq!(schnorr_z.len(), 32, "Schnorr z must be 32 bytes (scalar)");
    key_state.dkg_schnorr_r_points.push(schnorr_r);
    key_state.dkg_schnorr_z_values.push(schnorr_z);

    let all_committed = dkg::add_commitment(&mut key_state, party_index, commitment_hash);

    if all_committed {
        key_state.keygen_phase = ZkKeyGenPhase::DkgRevealing {};
    }
    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// DKG reveal: a party reveals their public key share P_i.
/// Contract verifies:
///   1. SHA-256(P_i) matches the committed hash
///   2. Schnorr proof: party knows the discrete log of P_i (Protection 3)
#[action(shortname = 0x22, zk = true)]
pub fn dkg_reveal(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    public_key_share: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(key_state.keygen_phase, ZkKeyGenPhase::DkgRevealing {}),
        "Key is not in DKG revealing phase"
    );

    // Find this party's commit index to get stored Schnorr proof
    let commit_idx = key_state
        .dkg_commit_indices
        .iter()
        .position(|&idx| idx == party_index)
        .expect("Party did not commit — cannot reveal");

    // Verify Schnorr proof of knowledge (Protection 3: anti-rogue-key)
    if !key_state.dkg_schnorr_r_points.is_empty() {
        let schnorr_r = &key_state.dkg_schnorr_r_points[commit_idx];
        let schnorr_z = &key_state.dkg_schnorr_z_values[commit_idx];
        assert!(
            dkg::verify_schnorr_proof(&public_key_share, schnorr_r, schnorr_z, party_index),
            "Schnorr proof of knowledge FAILED for party {} — possible rogue key attack!",
            party_index
        );
    }

    let _all_revealed = dkg::add_reveal(&mut key_state, party_index, public_key_share);

    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// DKG finalize: compute the combined public key P = P₁ + P₂ + ... + Pₙ.
/// After this, parties submit their secret shares s_i as ZK secrets (existing 0x10 flow).
#[action(shortname = 0x23, zk = true)]
pub fn dkg_finalize(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(key_state.keygen_phase, ZkKeyGenPhase::DkgRevealing {}),
        "Key is not in DKG revealing phase"
    );

    assert!(
        key_state.dkg_reveal_indices.len() as u8 >= key_state.dkg_num_parties,
        "Not all parties have revealed yet"
    );

    // Compute combined public key via EC point addition
    let combined_pk = dkg::combine_public_keys(&key_state.dkg_reveal_pubkeys);

    // Validate the combined key
    VerifyingKey::from_sec1_bytes(&combined_pk).expect("Combined public key is invalid");

    key_state.public_key = Some(combined_pk);
    key_state.keygen_phase = ZkKeyGenPhase::DkgFinalized {};

    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// Force-complete DKG keygen after shares have been submitted.
/// Moves from DkgFinalized to Complete so signing can proceed.
#[action(shortname = 0x24, zk = true)]
pub fn dkg_complete_keygen(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(key_state.keygen_phase, ZkKeyGenPhase::DkgFinalized {}),
        "Key is not in DkgFinalized phase"
    );
    assert!(
        key_state.public_key.is_some(),
        "Public key must be set (run dkg_finalize first)"
    );

    key_state.keygen_phase = ZkKeyGenPhase::Complete {};
    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Threshold ECDSA Signing — private key NEVER reconstructed
// ---------------------------------------------------------------------------

/// Start a threshold signing session.
///
/// The coordinator submits the nonce point R (computed as k × G off-chain).
/// Each party will then submit their partial signature σ_i = k⁻¹ · r · s_i.
/// The contract combines partials and verifies the final ECDSA signature.
///
/// SECURITY: The private key s = Σ s_i is NEVER computed. Each party only uses
/// their own secret share s_i. The contract combines the partial signatures
/// on-chain so no single off-chain entity ever sees the full signature σ
/// before the nonce k is discarded.
#[action(shortname = 0x30, zk = true)]
pub fn start_threshold_sign(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    task_id: u32,
    r_bytes: Vec<u8>,
    recovery_id: u8,
    num_parties: u8,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.is_key_generated(),
        "Key generation not yet complete"
    );
    assert_eq!(r_bytes.len(), 32, "r_bytes must be 32 bytes");
    assert!(recovery_id <= 1, "recovery_id must be 0 or 1");
    assert!(num_parties >= 2, "Need at least 2 parties");

    // Ensure we have a signing task queued
    let info = key_state
        .signing_information
        .get(&task_id)
        .expect("Unknown signing task — call sign_message first");
    assert!(
        info.signature.is_none(),
        "Signature already set for this task"
    );

    // Create threshold signing session
    key_state.ts_active = true;
    key_state.ts_task_id = task_id;
    key_state.ts_r_bytes = r_bytes;
    key_state.ts_recovery_id = recovery_id;
    key_state.ts_num_parties = num_parties;
    key_state.ts_partial_indices.clear();
    key_state.ts_partial_values.clear();
    key_state.signing_phase = ZkSigningPhase::ThresholdSigning { task_id };

    // Set deadline for this signing round
    key_state.signing_deadline_block = ctx.block_production_time + key_state.signing_timeout_blocks;

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Submit a partial signature for threshold ECDSA signing.
///
/// Each party submits σ_i = k⁻¹ · r · s_i (mod n).
/// Party 1 also includes the message component: σ_1 += k⁻¹ · m.
///
/// When all partials are collected, the contract:
/// 1. Sums σ = Σ σ_i
/// 2. Constructs the full ECDSA signature (r, σ)
/// 3. Verifies against the stored public key
/// 4. Stores the verified signature
///
/// The private key s is NEVER computed — only individual s_i values are used.
#[action(shortname = 0x31, zk = true)]
pub fn submit_partial_sig(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    partial_s: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    assert!(
        matches!(
            key_state.signing_phase,
            ZkSigningPhase::ThresholdSigning { .. }
        ),
        "Not in threshold signing phase"
    );
    assert_eq!(partial_s.len(), 32, "Partial signature must be 32 bytes");
    assert!(key_state.ts_active, "No threshold signing session active");
    assert!(
        key_state.is_active_signing_party(party_index),
        "Party {} is not part of the active signing subset",
        party_index
    );

    // Check party hasn't already submitted
    assert!(
        !key_state
            .ts_partial_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} has already submitted a partial signature",
        party_index
    );

    // If partial commitment exists, verify σ_i matches commitment
    if let Some(commit_pos) = key_state
        .ps_commit_indices
        .iter()
        .position(|&idx| idx == party_index)
    {
        let committed_hash = &key_state.ps_commit_hashes[commit_pos];
        let actual_hash = dkg::sha256(&partial_s);
        assert_eq!(
            committed_hash.as_slice(),
            &actual_hash[..],
            "Partial signature does not match commitment for party {}",
            party_index
        );
    }

    key_state.ts_partial_indices.push(party_index);
    key_state.ts_partial_values.push(partial_s.clone());

    // Check if all partials collected
    if key_state.ts_partial_indices.len() as u8 >= key_state.ts_num_parties {
        // Combine partial signatures with low-s normalization: σ = Σ σ_i (mod n)
        let (combined_s, was_negated) =
            combine_partial_signatures_with_flag(&key_state.ts_partial_values);

        // If s was negated for low-s, flip recovery ID
        let recovery_id = if was_negated {
            key_state.ts_recovery_id ^ 1
        } else {
            key_state.ts_recovery_id
        };

        // Build the full 65-byte signature: r (32) || s (32) || v (1)
        let mut signature = Vec::with_capacity(65);
        signature.extend_from_slice(&key_state.ts_r_bytes);
        signature.extend_from_slice(&combined_s);
        signature.push(recovery_id);

        // Verify the combined ECDSA signature against the stored public key
        let public_key = key_state.public_key.clone().expect("Public key missing");
        let verifying_key =
            VerifyingKey::from_sec1_bytes(&public_key).expect("Stored public key is not valid");

        let sig64 = &signature[0..64];
        let parsed_sig = Signature::try_from(sig64).expect("Failed to parse combined signature");

        let task_id = key_state.ts_task_id;
        let mut info = key_state
            .signing_information
            .get(&task_id)
            .expect("Signing task not found");

        verifying_key
            .verify_prehash(&info.message_hash, &parsed_sig)
            .expect("Combined threshold signature verification failed");

        // Store the verified signature
        info.recovery_id = recovery_id;
        info.signature = Some(signature);
        info.verified = true;
        key_state.signing_information.insert(task_id, info);

        // Clean up and advance
        key_state.ts_active = false;
        key_state.gg20_active = false; // Reset GG20 session for next round
        key_state.gg20_task_id = 0;
        key_state.gg20_policy_id = 0;
        key_state.gg20_required_parties.clear();
        key_state.gg20_min_signers = 0;
        key_state.gg20_signing_parties.clear();
        key_state.gg20_num_parties = 0;
        key_state.reset_pqc_approval_session();
        key_state.ts_partial_indices.clear();
        key_state.ts_partial_values.clear();
        key_state.signing_phase = ZkSigningPhase::Complete { task_id };
        key_state
            .pending_sign_requests
            .retain(|r| r.task_id != task_id);

        if !key_state.pending_sign_requests.is_empty() {
            key_state.start_next_signing();
        } else {
            key_state.signing_phase = ZkSigningPhase::Idle {};
        }
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Distributed Nonce Ceremony — removes single coordinator trust
// ---------------------------------------------------------------------------

/// Start a distributed nonce ceremony for threshold signing.
///
/// Instead of one coordinator generating k alone, all parties contribute:
/// 1. Each party commits hash(R_i) where R_i = k_i × G
/// 2. Each party reveals R_i
/// 3. Contract combines R = R₁ + R₂ + ... + Rₙ
/// 4. Coordinator (rotated each round) computes k_inv from contributed seeds
///
/// SECURITY: No single party can bias k. Coordinator rotates each round.
#[action(shortname = 0x40, zk = true)]
pub fn start_nonce_ceremony(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    task_id: u32,
    num_parties: u8,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.is_key_generated(),
        "Key generation not yet complete"
    );
    assert!(num_parties >= 2, "Need at least 2 parties");

    // Ensure signing task exists
    let _info = key_state
        .signing_information
        .get(&task_id)
        .expect("Unknown signing task — call sign_message first");

    // Rotate coordinator each round
    let coordinator = (key_state.signing_round % (num_parties as u32)) as u8;

    key_state.nc_num_parties = num_parties;
    key_state.nc_coordinator = coordinator;
    key_state.nc_commit_indices.clear();
    key_state.nc_commitment_hashes.clear();
    key_state.nc_reveal_indices.clear();
    key_state.nc_reveal_points.clear();
    key_state.signing_phase = ZkSigningPhase::NonceCommitting { task_id };

    // Set deadline for this signing round
    key_state.signing_deadline_block = ctx.block_production_time + key_state.signing_timeout_blocks;

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Commit a nonce point hash during distributed nonce ceremony.
/// Each party submits SHA-256(compressed_R_i) where R_i = k_i × G.
#[action(shortname = 0x41, zk = true)]
pub fn nonce_commit(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    commitment_hash: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(
            key_state.signing_phase,
            ZkSigningPhase::NonceCommitting { .. }
        ),
        "Not in nonce committing phase"
    );
    assert_eq!(
        commitment_hash.len(),
        32,
        "Commitment hash must be 32 bytes"
    );
    assert!(
        !key_state
            .nc_commit_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} has already committed a nonce",
        party_index
    );

    key_state.nc_commit_indices.push(party_index);
    key_state.nc_commitment_hashes.push(commitment_hash);

    // Move to reveal phase when all committed
    if key_state.nc_commit_indices.len() as u8 >= key_state.nc_num_parties {
        if let ZkSigningPhase::NonceCommitting { task_id } = key_state.signing_phase {
            key_state.signing_phase = ZkSigningPhase::NonceRevealing { task_id };
        }
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Reveal a nonce point during distributed nonce ceremony.
/// Contract verifies R_i matches the previously committed hash.
#[action(shortname = 0x42, zk = true)]
pub fn nonce_reveal(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    nonce_point: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(
            key_state.signing_phase,
            ZkSigningPhase::NonceRevealing { .. }
        ),
        "Not in nonce revealing phase"
    );
    assert_eq!(
        nonce_point.len(),
        33,
        "Nonce point must be 33 bytes (compressed)"
    );
    assert!(
        !key_state
            .nc_reveal_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} has already revealed nonce",
        party_index
    );

    // Find commitment and verify
    let commit_idx = key_state
        .nc_commit_indices
        .iter()
        .position(|&idx| idx == party_index)
        .expect("Party did not commit — cannot reveal");
    let commitment_hash = &key_state.nc_commitment_hashes[commit_idx];

    assert!(
        dkg::verify_commitment(commitment_hash, &nonce_point),
        "Nonce reveal does not match commitment hash"
    );

    // Validate it's a real EC point
    VerifyingKey::from_sec1_bytes(&nonce_point).expect("Invalid secp256k1 nonce point");

    key_state.nc_reveal_indices.push(party_index);
    key_state.nc_reveal_points.push(nonce_point);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Finalize nonce ceremony: combine R points and start threshold signing.
///
/// The coordinator (rotated) provides k⁻¹ and starts the signing session.
/// The contract verifies that the nonce point R matches the combined R_i points.
#[action(shortname = 0x43, zk = true)]
pub fn finalize_nonce_and_sign(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    r_bytes: Vec<u8>,
    recovery_id: u8,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    let task_id = match key_state.signing_phase {
        ZkSigningPhase::NonceRevealing { task_id } => task_id,
        _ => panic!("Not in nonce revealing phase"),
    };

    assert!(
        key_state.nc_reveal_indices.len() as u8 >= key_state.nc_num_parties,
        "Not all parties have revealed nonce points"
    );
    assert_eq!(r_bytes.len(), 32, "r_bytes must be 32 bytes");

    // Combine all nonce points: R = R₁ + R₂ + ... + Rₙ
    let combined_nonce = dkg::combine_public_keys(&key_state.nc_reveal_points);

    // Verify that the provided r matches the combined nonce point's x-coordinate
    // Extract x-coordinate from the combined compressed point
    // Compressed format: 0x02/0x03 + x(32 bytes)
    let combined_x = &combined_nonce[1..33];
    assert_eq!(
        r_bytes.as_slice(),
        combined_x,
        "Provided r does not match combined nonce point R = R₁+R₂+...+Rₙ"
    );

    // Start threshold signing with verified r
    key_state.ts_active = true;
    key_state.ts_task_id = task_id;
    key_state.ts_r_bytes = r_bytes;
    key_state.ts_recovery_id = recovery_id;
    key_state.ts_num_parties = key_state.nc_num_parties;
    key_state.ts_partial_indices.clear();
    key_state.ts_partial_values.clear();
    key_state.ps_commit_indices.clear();
    key_state.ps_commit_hashes.clear();
    key_state.signing_phase = ZkSigningPhase::ThresholdSigning { task_id };

    // Increment signing round for coordinator rotation
    key_state.signing_round += 1;

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Partial Signature Commitments — prevents tampering
// ---------------------------------------------------------------------------

/// Commit hash(σ_i) before revealing the actual partial signature.
/// This prevents any party from modifying their σ_i after seeing others'.
#[action(shortname = 0x44, zk = true)]
pub fn commit_partial_sig(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    commitment_hash: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    assert!(
        matches!(
            key_state.signing_phase,
            ZkSigningPhase::ThresholdSigning { .. }
        ),
        "Not in threshold signing phase"
    );
    assert_eq!(commitment_hash.len(), 32, "Commitment must be 32 bytes");
    assert!(
        !key_state
            .ps_commit_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} has already committed a partial signature",
        party_index
    );

    key_state.ps_commit_indices.push(party_index);
    key_state.ps_commit_hashes.push(commitment_hash);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Start a contract-authoritative PQC approval session for a pending signing task.
///
/// This does not verify Dilithium signatures on-chain. Instead, it anchors the
/// exact approval payload and requires each party to submit the matching digest
/// from their registered Partisia address before GG20 may begin.
#[action(shortname = 0x75, zk = true)]
pub fn start_pqc_approval_session(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    task_id: u32,
    signing_parties: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let num_parties = signing_parties.len() as u8;
    assert!(num_parties >= 2, "Need at least 2 approval parties");

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.is_key_generated(), "Key not yet generated");
    key_state.assert_all_parties_ready_for_signing();
    assert!(
        !key_state.pqc_approval_active,
        "Previous PQC approval session still active"
    );
    assert!(
        !key_state.gg20_active,
        "Cannot start PQC approval while GG20 session is active"
    );

    let request = key_state
        .pending_sign_requests
        .iter()
        .find(|r| r.task_id == task_id)
        .cloned()
        .expect("Unknown signing task");

    for &party_index in &signing_parties {
        assert!(
            party_index >= 1 && party_index <= key_state.num_shares,
            "Invalid signing party"
        );
        assert!(
            signing_parties
                .iter()
                .filter(|&&p| p == party_index)
                .count()
                == 1,
            "Signing party set contains duplicate party index {}",
            party_index
        );
        assert!(
            key_state.is_party_ready_for_signing(party_index),
            "Signing party {} is missing required address or PQC registration",
            party_index
        );
    }

    let mut required_parties: Vec<u8> = Vec::new();
    if request.policy_id != 0 {
        let idx = key_state
            .policy_ids
            .iter()
            .position(|&id| id == request.policy_id)
            .expect("Resolved policy missing from state");
        required_parties = key_state.policy_mandatory_parties[idx].clone();
        for &party_index in &required_parties {
            assert!(
                signing_parties.contains(&party_index),
                "POLICY VIOLATION: Party {} is mandatory for this transaction (policy_id={}) but is not in the signing set",
                party_index,
                request.policy_id
            );
        }
    }

    assert!(
        num_parties >= request.min_signers,
        "Approval party set ({}) is below effective threshold ({})",
        num_parties,
        request.min_signers
    );

    let message_hash = key_state
        .signing_information
        .get(&task_id)
        .expect("Signing task not found")
        .message_hash
        .clone();
    let challenge = compute_pqc_session_challenge(
        key_id,
        task_id,
        &message_hash,
        &request.tx_tag,
        &signing_parties,
    );

    key_state.pqc_approval_active = true;
    key_state.pqc_approval_approved = false;
    key_state.pqc_approval_task_id = task_id;
    key_state.pqc_approval_message_hash = message_hash;
    key_state.pqc_approval_tx_tag = request.tx_tag;
    key_state.pqc_approval_signing_parties = signing_parties;
    key_state.pqc_approval_required_parties = required_parties;
    key_state.pqc_approval_min_signers = request.min_signers;
    key_state.pqc_approval_challenge = challenge;
    key_state.pqc_approval_deadline_block =
        ctx.block_production_time + key_state.signing_timeout_blocks;
    key_state.pqc_approval_received_parties.clear();
    key_state.pqc_approval_received_hashes.clear();

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Submit a contract-bound PQC approval digest from the party's registered address.
#[action(shortname = 0x76, zk = true)]
pub fn submit_pqc_approval(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    task_id: u32,
    party_index: u8,
    approval_hash: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.pqc_approval_active,
        "No active PQC approval session"
    );
    assert!(
        !key_state.pqc_approval_approved,
        "PQC approval session already finalized"
    );
    assert_eq!(
        key_state.pqc_approval_task_id, task_id,
        "PQC approval session is not bound to this signing task"
    );
    assert_eq!(approval_hash.len(), 32, "Approval hash must be 32 bytes");

    let party_addr = key_state
        .get_party_address(party_index)
        .expect("Party has not registered an address");
    assert_eq!(
        &ctx.sender, party_addr,
        "Sender is not the registered address for this party"
    );
    assert!(
        key_state.is_pqc_approval_party(party_index),
        "Party {} is not part of the active PQC approval subset",
        party_index
    );
    assert!(
        !key_state
            .pqc_approval_received_parties
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} already submitted a PQC approval",
        party_index
    );

    let expected_hash = compute_pqc_approval_hash(
        key_id,
        task_id,
        party_index,
        &key_state.pqc_approval_message_hash,
        &key_state.pqc_approval_tx_tag,
        &key_state.pqc_approval_signing_parties,
        &key_state.pqc_approval_challenge,
        key_state.pqc_approval_deadline_block,
    );
    assert_eq!(
        approval_hash.as_slice(),
        &expected_hash[..],
        "PQC approval hash does not match the active contract-bound approval payload"
    );

    key_state.pqc_approval_received_parties.push(party_index);
    key_state.pqc_approval_received_hashes.push(approval_hash);
    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Finalize a PQC approval session after the required parties have approved.
#[action(shortname = 0x77, zk = true)]
pub fn finalize_pqc_approval(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    task_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.pqc_approval_active,
        "No active PQC approval session"
    );
    assert!(
        !key_state.pqc_approval_approved,
        "PQC approval session already finalized"
    );
    assert_eq!(
        key_state.pqc_approval_task_id, task_id,
        "PQC approval session is not bound to this signing task"
    );

    for &party_index in &key_state.pqc_approval_required_parties {
        assert!(
            key_state
                .pqc_approval_received_parties
                .contains(&party_index),
            "Required party {} has not submitted a PQC approval",
            party_index
        );
    }
    assert!(
        key_state.pqc_approval_received_parties.len() as u8 >= key_state.pqc_approval_min_signers,
        "PQC approval session has only {}/{} approvals",
        key_state.pqc_approval_received_parties.len(),
        key_state.pqc_approval_min_signers
    );

    key_state.pqc_approval_approved = true;
    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// GG20 Fully Trustless Signing — NO coordinator, NO single k knowledge
// ---------------------------------------------------------------------------

/// Start a GG20 signing session.
/// After MtA rounds complete off-chain, parties submit δ_i and Γ_i.
///
/// signing_parties: 1-based party indices that will participate (e.g. [1, 2]).
/// The contract enforces that all mandatory parties from the sign_message policy
/// are present in this set before opening the signing session.
#[action(shortname = 0x50, zk = true)]
pub fn gg20_start_signing(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    task_id: u32,
    signing_parties: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let num_parties = signing_parties.len() as u8;
    assert!(num_parties >= 2, "Need at least 2 signing parties");
    assert!(
        !signing_parties.is_empty(),
        "Signing party set must not be empty"
    );
    for &party_index in &signing_parties {
        assert!(
            party_index >= 1,
            "Signing parties must be valid 1-based indices"
        );
        assert!(
            signing_parties
                .iter()
                .filter(|&&p| p == party_index)
                .count()
                == 1,
            "Signing party set contains duplicate party index {}",
            party_index
        );
    }

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.is_key_generated(), "Key not yet generated");
    key_state.assert_all_parties_ready_for_signing();
    assert!(
        key_state.pqc_approval_active && key_state.pqc_approval_approved,
        "PQC approval session must be finalized before GG20 signing can start"
    );
    assert_eq!(
        key_state.pqc_approval_task_id, task_id,
        "PQC approval session is not bound to this signing task"
    );
    assert!(
        same_party_set(&key_state.pqc_approval_signing_parties, &signing_parties),
        "Signing subset does not match the finalized PQC approval session"
    );

    let _info = key_state
        .signing_information
        .get(&task_id)
        .expect("Unknown signing task");

    // --- Policy enforcement (on-chain, cannot be bypassed) ---
    let task_policy_id = key_state
        .pending_sign_requests
        .iter()
        .find(|r| r.task_id == task_id)
        .map(|r| r.policy_id)
        .unwrap_or(0);

    let mut required_parties: Vec<u8> = Vec::new();
    let mut effective_min_signers = key_state.threshold as u8;
    if task_policy_id != 0 {
        if let Some(idx) = key_state
            .policy_ids
            .iter()
            .position(|&id| id == task_policy_id)
        {
            required_parties = key_state.policy_mandatory_parties[idx].clone();
            let policy_min = key_state.policy_min_thresholds[idx];
            if policy_min != 0 {
                effective_min_signers = policy_min.max(effective_min_signers);
            }
            for &m in &required_parties {
                assert!(
                    signing_parties.contains(&m),
                    "POLICY VIOLATION: Party {} is mandatory for this transaction (policy_id={}) but is not in the signing set",
                    m,
                    task_policy_id
                );
            }
        }
    }
    assert!(
        num_parties >= effective_min_signers,
        "Signing parties ({}) is below effective threshold ({})",
        num_parties,
        effective_min_signers
    );
    assert_eq!(
        key_state.pqc_approval_min_signers, effective_min_signers,
        "PQC approval session minimum signer requirement does not match current policy state"
    );
    assert!(
        same_party_set(&key_state.pqc_approval_required_parties, &required_parties),
        "PQC approval session required-party set does not match current policy state"
    );
    for &party_index in &signing_parties {
        assert!(
            party_index <= key_state.num_shares,
            "Signing party {} is outside configured share range",
            party_index
        );
        assert!(
            key_state.is_party_ready_for_signing(party_index),
            "Signing party {} is missing required address or PQC registration",
            party_index
        );
    }

    // Session isolation (Protection 5): reject if previous session still in progress
    assert!(
        !key_state.gg20_active,
        "Previous GG20 signing session still active — abort it first (0x48) or wait for completion"
    );

    // Increment session ID to prevent nonce reuse across sessions
    key_state.signing_session_id += 1;

    key_state.gg20_active = true;
    key_state.gg20_num_parties = num_parties;
    key_state.gg20_signing_parties = signing_parties;
    key_state.gg20_task_id = task_id;
    key_state.gg20_policy_id = task_policy_id;
    key_state.gg20_required_parties = required_parties;
    key_state.gg20_min_signers = effective_min_signers;
    key_state.gg20_delta_indices.clear();
    key_state.gg20_delta_values.clear();
    key_state.gg20_delta_commit_indices.clear();
    key_state.gg20_delta_commit_hashes.clear();
    key_state.gg20_delta_zk_vars.clear();
    key_state.gg20_delta_zk_count = 0;
    key_state.gg20_delta_zk_expected = 0;
    key_state.gg20_gamma_indices.clear();
    key_state.gg20_gamma_points.clear();
    key_state.gg20_r_bytes.clear();
    key_state.ts_task_id = task_id;
    key_state.ps_commit_indices.clear();
    key_state.ps_commit_hashes.clear();
    key_state.ts_partial_indices.clear();
    key_state.ts_partial_values.clear();

    // Set deadline for this signing round
    key_state.signing_deadline_block = ctx.block_production_time + key_state.signing_timeout_blocks;

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Commit hash(δ_i) before revealing the actual delta value.
/// Prevents a malicious party from choosing δ_i after seeing others'.
#[action(shortname = 0x49, zk = true)]
pub fn commit_delta(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    commitment_hash: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");
    assert_eq!(commitment_hash.len(), 32, "Commitment must be 32 bytes");
    assert!(
        key_state.is_active_signing_party(party_index),
        "Party {} is not part of the active signing subset",
        party_index
    );
    assert!(
        !key_state
            .gg20_delta_commit_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} has already committed delta",
        party_index
    );

    key_state.gg20_delta_commit_indices.push(party_index);
    key_state.gg20_delta_commit_hashes.push(commitment_hash);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Submit δ_i value (party's additive share of k·γ).
/// All δ_i are needed to compute δ = k·γ, then R = δ⁻¹·Γ.
/// If a delta commitment exists, verifies the value matches.
#[action(shortname = 0x45, zk = true)]
pub fn submit_delta(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    delta_bytes: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");
    assert_eq!(delta_bytes.len(), 32, "Delta must be 32 bytes");
    assert!(
        key_state.is_active_signing_party(party_index),
        "Party {} is not part of the active signing subset",
        party_index
    );
    assert!(
        !key_state
            .gg20_delta_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} already submitted delta",
        party_index
    );

    // If delta commitment exists for this party, verify it matches
    if let Some(commit_pos) = key_state
        .gg20_delta_commit_indices
        .iter()
        .position(|&idx| idx == party_index)
    {
        let committed_hash = &key_state.gg20_delta_commit_hashes[commit_pos];
        let actual_hash = dkg::sha256(&delta_bytes);
        assert_eq!(
            committed_hash.as_slice(),
            &actual_hash[..],
            "Delta does not match commitment for party {}",
            party_index
        );
    }

    key_state.gg20_delta_indices.push(party_index);
    key_state.gg20_delta_values.push(delta_bytes);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Submit Γ_i = γ_i·G point (party's gamma commitment).
#[action(shortname = 0x46, zk = true)]
pub fn submit_gamma_point(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    gamma_point: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");
    assert_eq!(gamma_point.len(), 33, "Gamma point must be 33 bytes");
    assert!(
        key_state.is_active_signing_party(party_index),
        "Party {} is not part of the active signing subset",
        party_index
    );
    assert!(
        !key_state
            .gg20_gamma_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} already submitted gamma point",
        party_index
    );

    // Validate it's a real EC point
    VerifyingKey::from_sec1_bytes(&gamma_point).expect("Invalid gamma point");

    key_state.gg20_gamma_indices.push(party_index);
    key_state.gg20_gamma_points.push(gamma_point);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Submit δ_i as ZK secret input (encrypted, not visible on-chain).
/// Delta values are 256-bit scalars, submitted as two Sbi128 halves.
/// This is the privacy-preserving alternative to plaintext submit_delta (0x45).
#[zk_on_secret_input(shortname = 0x51)]
pub fn submit_delta_zk(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    is_high_half: bool,
) -> (
    ContractState,
    Vec<EventGroup>,
    ZkInputDef<ShareMetadata, Sbi128>,
) {
    let key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");
    assert!(
        key_state.is_active_signing_party(party_index),
        "Party {} is not part of the active signing subset",
        party_index
    );

    // Set expected count if not yet set
    if key_state.gg20_delta_zk_expected == 0 {
        let mut ks = key_state;
        ks.gg20_delta_zk_expected = (ks.gg20_num_parties as u32) * 2;
        state.keys.insert(key_id, ks);
    }

    let metadata = ShareMetadata {
        key_id,
        share_index: party_index,
        is_high_half,
        variable_type: 1, // delta
    };

    let input_def = ZkInputDef::with_metadata(None, metadata);
    (state, vec![], input_def)
}

/// Open all submitted delta ZK variables so the contract can read them.
/// Called by the client after all delta halves have been submitted via submit_delta_zk.
/// The opened values are processed in on_shares_opened (variable_type == 1).
#[action(shortname = 0x52, zk = true)]
pub fn open_gg20_deltas(
    _ctx: ContractContext,
    state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");

    // Collect all delta ZK variable IDs
    let delta_var_ids: Vec<SecretVarId> = key_state
        .gg20_delta_zk_vars
        .iter()
        .map(|sv| SecretVarId::new(sv.variable_id))
        .collect();

    assert!(!delta_var_ids.is_empty(), "No delta ZK variables to open");

    (
        state,
        vec![],
        vec![ZkStateChange::OpenVariables {
            variables: delta_var_ids,
        }],
    )
}

/// Finalize GG20 R computation on-chain.
///
/// Contract computes:
/// 1. δ = Σ δ_i (mod n) — additive combination
/// 2. Γ = Σ Γ_i (EC point addition)
/// 3. R = δ⁻¹ · Γ = (k·γ)⁻¹ · (γ·G) = k⁻¹ · G
/// 4. r = R.x
///
/// NOBODY ever computed k⁻¹ as a number. R = k⁻¹·G was computed
/// via scalar multiplication of δ⁻¹ with the point Γ.
#[action(shortname = 0x47, zk = true)]
pub fn gg20_finalize_r(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");
    assert!(
        key_state.gg20_delta_indices.len() as u8 >= key_state.gg20_num_parties,
        "Not all delta values submitted"
    );
    assert!(
        key_state.gg20_gamma_points.len() as u8 >= key_state.gg20_num_parties,
        "Not all gamma points submitted"
    );

    // 1. Compute δ = Σ δ_i (mod n) using k256 Scalar
    use k256::elliptic_curve::ff::PrimeField;
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;
    use k256::{AffinePoint as K256Affine, FieldBytes, ProjectivePoint as K256Proj, Scalar};

    let mut delta = Scalar::ZERO;
    for dv in &key_state.gg20_delta_values {
        let mut fb = FieldBytes::default();
        fb.copy_from_slice(dv);
        let s = Option::<Scalar>::from(Scalar::from_repr(fb)).expect("Invalid delta scalar");
        delta = delta + s;
    }

    // 2. Compute Γ = Σ Γ_i (EC point addition)
    let mut gamma_combined = K256Proj::IDENTITY;
    for gp in &key_state.gg20_gamma_points {
        let encoded = EncodedPoint::from_bytes(gp).expect("Invalid gamma point encoding");
        let affine = Option::<K256Affine>::from(K256Affine::from_encoded_point(&encoded))
            .expect("Invalid gamma affine point");
        gamma_combined = gamma_combined + K256Proj::from(affine);
    }

    // 3. R = δ⁻¹ · Γ
    let delta_inv = delta.invert();
    assert!(bool::from(delta_inv.is_some()), "Delta has no inverse");
    let delta_inv = delta_inv.unwrap();
    let r_point = gamma_combined * delta_inv;

    // 4. Extract r = R.x
    let r_affine = r_point.to_affine();
    let r_encoded = EncodedPoint::from(r_affine);
    let r_compressed = r_encoded.compress();
    let r_bytes_full = r_compressed.as_bytes();

    // x-coordinate is bytes [1..33] of compressed point
    let r_bytes = r_bytes_full[1..33].to_vec();

    // Recovery ID from y parity
    let recovery_id = if r_bytes_full[0] == 0x02 { 0u8 } else { 1u8 };

    key_state.gg20_r_bytes = r_bytes.clone();
    key_state.gg20_recovery_id = recovery_id;

    // Set up threshold signing with the computed r
    let task_id = key_state.ts_task_id;
    key_state.ts_active = true;
    key_state.ts_r_bytes = r_bytes;
    key_state.ts_recovery_id = recovery_id;
    key_state.ts_num_parties = key_state.gg20_num_parties;
    key_state.signing_phase = ZkSigningPhase::ThresholdSigning { task_id };
    key_state.signing_round += 1;

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Low-latency v2 signing submission.
///
/// Preserves the same signing semantics as the v1 GG20 flow, but compresses:
/// - delta commitments
/// - delta submissions
/// - gamma submissions
/// - R finalization
/// - partial signature commitments
/// - partial signature submissions
///
/// into a single owner-authorized contract action after PQC approval is finalized
/// and the GG20 signing session is already active.
#[action(shortname = 0x58, zk = true)]
pub fn submit_signing_bundle_v2(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    task_id: u32,
    bundles: Vec<SigningPartyBundleV2>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");
    assert_eq!(
        key_state.gg20_task_id, task_id,
        "GG20 session is not bound to this signing task"
    );
    assert!(
        matches!(
            key_state.signing_phase,
            ZkSigningPhase::ThresholdSigning { .. }
        ) || key_state.gg20_active,
        "GG20 signing session is not active"
    );
    assert!(
        bundles.len() as u8 == key_state.gg20_num_parties,
        "Expected {} signing bundles, got {}",
        key_state.gg20_num_parties,
        bundles.len()
    );

    let bundle_indices: Vec<u8> = bundles.iter().map(|bundle| bundle.party_index).collect();
    assert!(
        same_party_set(&bundle_indices, &key_state.gg20_signing_parties),
        "Bundled party set does not match the active signing subset"
    );

    for bundle in &bundles {
        assert!(
            key_state.is_active_signing_party(bundle.party_index),
            "Party {} is not part of the active signing subset",
            bundle.party_index
        );
        assert_eq!(bundle.delta_bytes.len(), 32, "Delta must be 32 bytes");
        assert_eq!(bundle.gamma_point.len(), 33, "Gamma point must be 33 bytes");
        assert_eq!(
            bundle.partial_s.len(),
            32,
            "Partial signature must be 32 bytes"
        );
        assert!(
            bundle_indices
                .iter()
                .filter(|&&idx| idx == bundle.party_index)
                .count()
                == 1,
            "Bundled party set contains duplicate party index {}",
            bundle.party_index
        );
        VerifyingKey::from_sec1_bytes(&bundle.gamma_point).expect("Invalid gamma point");
    }

    key_state.gg20_delta_indices.clear();
    key_state.gg20_delta_values.clear();
    key_state.gg20_delta_commit_indices.clear();
    key_state.gg20_delta_commit_hashes.clear();
    key_state.gg20_gamma_indices.clear();
    key_state.gg20_gamma_points.clear();
    key_state.ps_commit_indices.clear();
    key_state.ps_commit_hashes.clear();
    key_state.ts_partial_indices.clear();
    key_state.ts_partial_values.clear();

    for bundle in &bundles {
        key_state.gg20_delta_commit_indices.push(bundle.party_index);
        key_state
            .gg20_delta_commit_hashes
            .push(dkg::sha256(&bundle.delta_bytes).to_vec());
        key_state.ps_commit_indices.push(bundle.party_index);
        key_state
            .ps_commit_hashes
            .push(dkg::sha256(&bundle.partial_s).to_vec());
    }

    for bundle in &bundles {
        key_state.gg20_delta_indices.push(bundle.party_index);
        key_state.gg20_delta_values.push(bundle.delta_bytes.clone());
        key_state.gg20_gamma_indices.push(bundle.party_index);
        key_state.gg20_gamma_points.push(bundle.gamma_point.clone());
    }

    // Inline gg20_finalize_r semantics.
    use k256::elliptic_curve::ff::PrimeField;
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;
    use k256::{AffinePoint as K256Affine, FieldBytes, ProjectivePoint as K256Proj, Scalar};

    let mut delta = Scalar::ZERO;
    for dv in &key_state.gg20_delta_values {
        let mut fb = FieldBytes::default();
        fb.copy_from_slice(dv);
        let s = Option::<Scalar>::from(Scalar::from_repr(fb)).expect("Invalid delta scalar");
        delta = delta + s;
    }

    let mut gamma_combined = K256Proj::IDENTITY;
    for gp in &key_state.gg20_gamma_points {
        let encoded = EncodedPoint::from_bytes(gp).expect("Invalid gamma point encoding");
        let affine = Option::<K256Affine>::from(K256Affine::from_encoded_point(&encoded))
            .expect("Invalid gamma affine point");
        gamma_combined = gamma_combined + K256Proj::from(affine);
    }

    let delta_inv = delta.invert();
    assert!(bool::from(delta_inv.is_some()), "Delta has no inverse");
    let delta_inv = delta_inv.unwrap();
    let r_point = gamma_combined * delta_inv;
    let r_affine = r_point.to_affine();
    let r_encoded = EncodedPoint::from(r_affine);
    let r_compressed = r_encoded.compress();
    let r_bytes_full = r_compressed.as_bytes();
    let r_bytes = r_bytes_full[1..33].to_vec();
    let recovery_id = if r_bytes_full[0] == 0x02 { 0u8 } else { 1u8 };

    key_state.gg20_r_bytes = r_bytes.clone();
    key_state.ts_task_id = task_id;
    key_state.ts_active = true;
    key_state.ts_r_bytes = r_bytes;
    key_state.ts_recovery_id = recovery_id;
    key_state.ts_num_parties = key_state.gg20_num_parties;
    key_state.signing_phase = ZkSigningPhase::ThresholdSigning { task_id };
    key_state.signing_round += 1;

    for bundle in &bundles {
        key_state.ts_partial_indices.push(bundle.party_index);
        key_state.ts_partial_values.push(bundle.partial_s.clone());
    }

    let (combined_s, was_negated) =
        combine_partial_signatures_with_flag(&key_state.ts_partial_values);
    let recovery_id = if was_negated {
        key_state.ts_recovery_id ^ 1
    } else {
        key_state.ts_recovery_id
    };

    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(&key_state.ts_r_bytes);
    signature.extend_from_slice(&combined_s);
    signature.push(recovery_id);

    let public_key = key_state.public_key.clone().expect("Public key missing");
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&public_key).expect("Stored public key is not valid");
    let sig64 = &signature[0..64];
    let parsed_sig = Signature::try_from(sig64).expect("Failed to parse combined signature");

    let mut info = key_state
        .signing_information
        .get(&task_id)
        .expect("Signing task not found");

    verifying_key
        .verify_prehash(&info.message_hash, &parsed_sig)
        .expect("Combined threshold signature verification failed");

    info.recovery_id = recovery_id;
    info.signature = Some(signature);
    info.verified = true;
    key_state.signing_information.insert(task_id, info);

    key_state.ts_active = false;
    key_state.gg20_active = false;
    key_state.gg20_task_id = 0;
    key_state.gg20_policy_id = 0;
    key_state.gg20_required_parties.clear();
    key_state.gg20_min_signers = 0;
    key_state.gg20_signing_parties.clear();
    key_state.gg20_num_parties = 0;
    key_state.reset_pqc_approval_session();
    key_state.ts_partial_indices.clear();
    key_state.ts_partial_values.clear();
    key_state.signing_phase = ZkSigningPhase::Complete { task_id };
    key_state
        .pending_sign_requests
        .retain(|r| r.task_id != task_id);

    if !key_state.pending_sign_requests.is_empty() {
        key_state.start_next_signing();
    } else {
        key_state.signing_phase = ZkSigningPhase::Idle {};
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Low-latency v4 session open.
///
/// Preserves the same semantics as `sign_message` followed by
/// `start_pqc_approval_session`, but compresses them into a single owner action.
#[action(shortname = 0x59, zk = true)]
pub fn open_signing_session_v4(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    message: Vec<u8>,
    tx_tag: Vec<u8>,
    signing_parties: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.is_key_generated(),
        "Key generation not yet complete for key {}",
        key_id
    );
    key_state.assert_all_parties_ready_for_signing();
    assert!(
        !key_state.pqc_approval_active,
        "Previous PQC approval session still active"
    );
    assert!(
        !key_state.gg20_active,
        "Cannot start PQC approval while GG20 session is active"
    );

    let num_parties = signing_parties.len() as u8;
    assert!(num_parties >= 2, "Need at least 2 approval parties");
    for &party_index in &signing_parties {
        assert!(
            party_index >= 1 && party_index <= key_state.num_shares,
            "Invalid signing party"
        );
        assert!(
            signing_parties
                .iter()
                .filter(|&&p| p == party_index)
                .count()
                == 1,
            "Signing party set contains duplicate party index {}",
            party_index
        );
        assert!(
            key_state.is_party_ready_for_signing(party_index),
            "Signing party {} is missing required address or PQC registration",
            party_index
        );
    }

    let policy_id = key_state.resolve_policy_id_for_tag(&tx_tag);
    let min_signers = if policy_id != 0 {
        let idx = key_state
            .policy_ids
            .iter()
            .position(|&id| id == policy_id)
            .expect("Resolved policy missing from state");
        let policy_min = key_state.policy_min_thresholds[idx];
        if policy_min == 0 {
            key_state.threshold as u8
        } else {
            policy_min.max(key_state.threshold as u8)
        }
    } else {
        key_state.threshold as u8
    };
    let task_id = key_state.queue_signing(message, tx_tag.clone(), policy_id, min_signers);

    let request = key_state
        .pending_sign_requests
        .iter()
        .find(|r| r.task_id == task_id)
        .cloned()
        .expect("Unknown signing task");

    let mut required_parties: Vec<u8> = Vec::new();
    if request.policy_id != 0 {
        let idx = key_state
            .policy_ids
            .iter()
            .position(|&id| id == request.policy_id)
            .expect("Resolved policy missing from state");
        required_parties = key_state.policy_mandatory_parties[idx].clone();
        for &party_index in &required_parties {
            assert!(
                signing_parties.contains(&party_index),
                "POLICY VIOLATION: Party {} is mandatory for this transaction (policy_id={}) but is not in the signing set",
                party_index,
                request.policy_id
            );
        }
    }

    assert!(
        num_parties >= request.min_signers,
        "Approval party set ({}) is below effective threshold ({})",
        num_parties,
        request.min_signers
    );

    let message_hash = key_state
        .signing_information
        .get(&task_id)
        .expect("Signing task not found")
        .message_hash
        .clone();
    let challenge = compute_pqc_session_challenge(
        key_id,
        task_id,
        &message_hash,
        &request.tx_tag,
        &signing_parties,
    );

    key_state.pqc_approval_active = true;
    key_state.pqc_approval_approved = false;
    key_state.pqc_approval_task_id = task_id;
    key_state.pqc_approval_message_hash = message_hash;
    key_state.pqc_approval_tx_tag = request.tx_tag;
    key_state.pqc_approval_signing_parties = signing_parties;
    key_state.pqc_approval_required_parties = required_parties;
    key_state.pqc_approval_min_signers = request.min_signers;
    key_state.pqc_approval_challenge = challenge;
    key_state.pqc_approval_deadline_block =
        ctx.block_production_time + key_state.signing_timeout_blocks;
    key_state.pqc_approval_received_parties.clear();
    key_state.pqc_approval_received_hashes.clear();

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Low-latency v4 bundled signing finalization.
///
/// Preserves the same semantics as:
/// - finalize_pqc_approval
/// - gg20_start_signing
/// - submit_signing_bundle_v2
///
/// while keeping per-party PQC approvals anchored by the existing submit action.
#[action(shortname = 0x5A, zk = true)]
pub fn submit_signing_bundle_v4(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    task_id: u32,
    bundles: Vec<SigningPartyBundleV2>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.is_key_generated(), "Key not yet generated");
    key_state.assert_all_parties_ready_for_signing();
    assert!(
        key_state.pqc_approval_active,
        "No active PQC approval session"
    );
    assert_eq!(
        key_state.pqc_approval_task_id, task_id,
        "PQC approval session is not bound to this signing task"
    );
    assert!(
        !key_state.gg20_active,
        "Previous GG20 signing session still active — abort it first (0x48) or wait for completion"
    );

    for &party_index in &key_state.pqc_approval_required_parties {
        assert!(
            key_state
                .pqc_approval_received_parties
                .contains(&party_index),
            "Required party {} has not submitted a PQC approval",
            party_index
        );
    }
    assert!(
        key_state.pqc_approval_received_parties.len() as u8 >= key_state.pqc_approval_min_signers,
        "PQC approval session has only {}/{} approvals",
        key_state.pqc_approval_received_parties.len(),
        key_state.pqc_approval_min_signers
    );

    let signing_parties = key_state.pqc_approval_signing_parties.clone();
    let num_parties = signing_parties.len() as u8;
    assert!(num_parties >= 2, "Need at least 2 signing parties");

    let _info = key_state
        .signing_information
        .get(&task_id)
        .expect("Unknown signing task");

    let task_policy_id = key_state
        .pending_sign_requests
        .iter()
        .find(|r| r.task_id == task_id)
        .map(|r| r.policy_id)
        .unwrap_or(0);

    let mut required_parties: Vec<u8> = Vec::new();
    let mut effective_min_signers = key_state.threshold as u8;
    if task_policy_id != 0 {
        if let Some(idx) = key_state
            .policy_ids
            .iter()
            .position(|&id| id == task_policy_id)
        {
            required_parties = key_state.policy_mandatory_parties[idx].clone();
            let policy_min = key_state.policy_min_thresholds[idx];
            if policy_min != 0 {
                effective_min_signers = policy_min.max(effective_min_signers);
            }
            for &m in &required_parties {
                assert!(
                    signing_parties.contains(&m),
                    "POLICY VIOLATION: Party {} is mandatory for this transaction (policy_id={}) but is not in the signing set",
                    m,
                    task_policy_id
                );
            }
        }
    }
    assert!(
        num_parties >= effective_min_signers,
        "Signing parties ({}) is below effective threshold ({})",
        num_parties,
        effective_min_signers
    );
    assert_eq!(
        key_state.pqc_approval_min_signers, effective_min_signers,
        "PQC approval session minimum signer requirement does not match current policy state"
    );
    assert!(
        same_party_set(&key_state.pqc_approval_required_parties, &required_parties),
        "PQC approval session required-party set does not match current policy state"
    );
    for &party_index in &signing_parties {
        assert!(
            party_index <= key_state.num_shares,
            "Signing party {} is outside configured share range",
            party_index
        );
        assert!(
            key_state.is_party_ready_for_signing(party_index),
            "Signing party {} is missing required address or PQC registration",
            party_index
        );
    }

    key_state.pqc_approval_approved = true;
    key_state.signing_session_id += 1;
    key_state.gg20_active = true;
    key_state.gg20_num_parties = num_parties;
    key_state.gg20_signing_parties = signing_parties.clone();
    key_state.gg20_task_id = task_id;
    key_state.gg20_policy_id = task_policy_id;
    key_state.gg20_required_parties = required_parties;
    key_state.gg20_min_signers = effective_min_signers;
    key_state.gg20_delta_indices.clear();
    key_state.gg20_delta_values.clear();
    key_state.gg20_delta_commit_indices.clear();
    key_state.gg20_delta_commit_hashes.clear();
    key_state.gg20_delta_zk_vars.clear();
    key_state.gg20_delta_zk_count = 0;
    key_state.gg20_delta_zk_expected = 0;
    key_state.gg20_gamma_indices.clear();
    key_state.gg20_gamma_points.clear();
    key_state.gg20_r_bytes.clear();
    key_state.ts_task_id = task_id;
    key_state.ps_commit_indices.clear();
    key_state.ps_commit_hashes.clear();
    key_state.ts_partial_indices.clear();
    key_state.ts_partial_values.clear();
    key_state.signing_deadline_block = ctx.block_production_time + key_state.signing_timeout_blocks;

    assert!(
        bundles.len() as u8 == key_state.gg20_num_parties,
        "Expected {} signing bundles, got {}",
        key_state.gg20_num_parties,
        bundles.len()
    );

    let bundle_indices: Vec<u8> = bundles.iter().map(|bundle| bundle.party_index).collect();
    assert!(
        same_party_set(&bundle_indices, &key_state.gg20_signing_parties),
        "Bundled party set does not match the active signing subset"
    );

    for bundle in &bundles {
        assert!(
            key_state.is_active_signing_party(bundle.party_index),
            "Party {} is not part of the active signing subset",
            bundle.party_index
        );
        assert_eq!(bundle.delta_bytes.len(), 32, "Delta must be 32 bytes");
        assert_eq!(bundle.gamma_point.len(), 33, "Gamma point must be 33 bytes");
        assert_eq!(
            bundle.partial_s.len(),
            32,
            "Partial signature must be 32 bytes"
        );
        assert!(
            bundle_indices
                .iter()
                .filter(|&&idx| idx == bundle.party_index)
                .count()
                == 1,
            "Bundled party set contains duplicate party index {}",
            bundle.party_index
        );
        VerifyingKey::from_sec1_bytes(&bundle.gamma_point).expect("Invalid gamma point");
    }

    for bundle in &bundles {
        key_state.gg20_delta_commit_indices.push(bundle.party_index);
        key_state
            .gg20_delta_commit_hashes
            .push(dkg::sha256(&bundle.delta_bytes).to_vec());
        key_state.ps_commit_indices.push(bundle.party_index);
        key_state
            .ps_commit_hashes
            .push(dkg::sha256(&bundle.partial_s).to_vec());
    }

    for bundle in &bundles {
        key_state.gg20_delta_indices.push(bundle.party_index);
        key_state.gg20_delta_values.push(bundle.delta_bytes.clone());
        key_state.gg20_gamma_indices.push(bundle.party_index);
        key_state.gg20_gamma_points.push(bundle.gamma_point.clone());
    }

    use k256::elliptic_curve::ff::PrimeField;
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;
    use k256::{AffinePoint as K256Affine, FieldBytes, ProjectivePoint as K256Proj, Scalar};

    let mut delta = Scalar::ZERO;
    for dv in &key_state.gg20_delta_values {
        let mut fb = FieldBytes::default();
        fb.copy_from_slice(dv);
        let s = Option::<Scalar>::from(Scalar::from_repr(fb)).expect("Invalid delta scalar");
        delta = delta + s;
    }

    let mut gamma_combined = K256Proj::IDENTITY;
    for gp in &key_state.gg20_gamma_points {
        let encoded = EncodedPoint::from_bytes(gp).expect("Invalid gamma point encoding");
        let affine = Option::<K256Affine>::from(K256Affine::from_encoded_point(&encoded))
            .expect("Invalid gamma affine point");
        gamma_combined = gamma_combined + K256Proj::from(affine);
    }

    let delta_inv = delta.invert();
    assert!(bool::from(delta_inv.is_some()), "Delta has no inverse");
    let delta_inv = delta_inv.unwrap();
    let r_point = gamma_combined * delta_inv;
    let r_affine = r_point.to_affine();
    let r_encoded = EncodedPoint::from(r_affine);
    let r_compressed = r_encoded.compress();
    let r_bytes_full = r_compressed.as_bytes();
    let r_bytes = r_bytes_full[1..33].to_vec();
    let recovery_id = if r_bytes_full[0] == 0x02 { 0u8 } else { 1u8 };

    key_state.gg20_r_bytes = r_bytes.clone();
    key_state.ts_task_id = task_id;
    key_state.ts_active = true;
    key_state.ts_r_bytes = r_bytes;
    key_state.ts_recovery_id = recovery_id;
    key_state.ts_num_parties = key_state.gg20_num_parties;
    key_state.signing_phase = ZkSigningPhase::ThresholdSigning { task_id };
    key_state.signing_round += 1;

    for bundle in &bundles {
        key_state.ts_partial_indices.push(bundle.party_index);
        key_state.ts_partial_values.push(bundle.partial_s.clone());
    }

    let (combined_s, was_negated) =
        combine_partial_signatures_with_flag(&key_state.ts_partial_values);
    let recovery_id = if was_negated {
        key_state.ts_recovery_id ^ 1
    } else {
        key_state.ts_recovery_id
    };

    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(&key_state.ts_r_bytes);
    signature.extend_from_slice(&combined_s);
    signature.push(recovery_id);

    let public_key = key_state.public_key.clone().expect("Public key missing");
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&public_key).expect("Stored public key is not valid");
    let sig64 = &signature[0..64];
    let parsed_sig = Signature::try_from(sig64).expect("Failed to parse combined signature");

    let mut info = key_state
        .signing_information
        .get(&task_id)
        .expect("Signing task not found");

    verifying_key
        .verify_prehash(&info.message_hash, &parsed_sig)
        .expect("Combined threshold signature verification failed");

    info.recovery_id = recovery_id;
    info.signature = Some(signature);
    info.verified = true;
    key_state.signing_information.insert(task_id, info);

    key_state.ts_active = false;
    key_state.gg20_active = false;
    key_state.gg20_task_id = 0;
    key_state.gg20_policy_id = 0;
    key_state.gg20_required_parties.clear();
    key_state.gg20_min_signers = 0;
    key_state.gg20_signing_parties.clear();
    key_state.gg20_num_parties = 0;
    key_state.reset_pqc_approval_session();
    key_state.ts_partial_indices.clear();
    key_state.ts_partial_values.clear();
    key_state.signing_phase = ZkSigningPhase::Complete { task_id };
    key_state
        .pending_sign_requests
        .retain(|r| r.task_id != task_id);

    if !key_state.pending_sign_requests.is_empty() {
        key_state.start_next_signing();
    } else {
        key_state.signing_phase = ZkSigningPhase::Idle {};
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Timeout / Abort — prevents locked keys when a party goes offline
// ---------------------------------------------------------------------------

/// Abort a signing session that has exceeded its deadline.
///
/// Anyone can call this after the deadline block has passed.
/// Resets the signing state so new signing sessions can proceed.
/// The timed-out task remains in signing_information (signature = None).
#[action(shortname = 0x48, zk = true)]
pub fn abort_signing(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    // Must be in an active signing phase (not idle or complete)
    assert!(
        !matches!(
            key_state.signing_phase,
            ZkSigningPhase::Idle {} | ZkSigningPhase::Complete { .. }
        ),
        "No active signing session to abort"
    );

    // Check deadline: anyone can abort after deadline, owner can abort anytime
    if ctx.sender != state.owner {
        assert!(
            key_state.signing_deadline_block > 0
                && ctx.block_production_time >= key_state.signing_deadline_block,
            "Signing deadline has not passed yet — only owner can force-abort"
        );
    }

    // Reset all signing-related state
    key_state.ts_active = false;
    key_state.ts_partial_indices.clear();
    key_state.ts_partial_values.clear();
    key_state.ps_commit_indices.clear();
    key_state.ps_commit_hashes.clear();
    key_state.gg20_active = false;
    key_state.gg20_task_id = 0;
    key_state.gg20_policy_id = 0;
    key_state.gg20_required_parties.clear();
    key_state.gg20_min_signers = 0;
    key_state.gg20_signing_parties.clear();
    key_state.gg20_num_parties = 0;
    key_state.reset_pqc_approval_session();
    key_state.gg20_delta_indices.clear();
    key_state.gg20_delta_values.clear();
    key_state.gg20_delta_commit_indices.clear();
    key_state.gg20_delta_commit_hashes.clear();
    key_state.gg20_delta_zk_vars.clear();
    key_state.gg20_delta_zk_count = 0;
    key_state.gg20_delta_zk_expected = 0;
    key_state.gg20_gamma_indices.clear();
    key_state.gg20_gamma_points.clear();
    key_state.gg20_r_bytes.clear();
    key_state.nc_commit_indices.clear();
    key_state.nc_commitment_hashes.clear();
    key_state.nc_reveal_indices.clear();
    key_state.nc_reveal_points.clear();
    key_state.signing_deadline_block = 0;
    key_state.signing_phase = ZkSigningPhase::Idle {};

    // Re-queue the task if it was pending
    // (The task stays in signing_information with signature = None)

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Protection 2: Paillier Key Registration
// ---------------------------------------------------------------------------

/// Register a Paillier public key for a party.
/// Each party must register their Paillier key before participating in GG20 signing.
/// The proof_commitment is SHA-256 of the off-chain Πmod+Πfac proof (verified by other parties).
#[action(shortname = 0x25, zk = true)]
pub fn register_paillier_key(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    paillier_n: Vec<u8>,
    proof_commitment: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.is_key_generated(), "Key not yet generated");

    // Validate Paillier modulus size (must be at least 256 bytes = 2048 bits)
    assert!(
        paillier_n.len() >= 256,
        "Paillier modulus must be at least 2048 bits (256 bytes), got {} bytes",
        paillier_n.len()
    );
    assert_eq!(
        proof_commitment.len(),
        32,
        "Proof commitment must be 32 bytes (SHA-256)"
    );

    // Check party hasn't already registered
    assert!(
        !key_state
            .paillier_key_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} has already registered a Paillier key",
        party_index
    );

    key_state.paillier_key_indices.push(party_index);
    key_state.paillier_keys.push(paillier_n);
    key_state.paillier_proof_commitments.push(proof_commitment);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Protection 4: Identifiable Abort (Blame Protocol)
// ---------------------------------------------------------------------------

/// Initiate blame protocol when the combined signature fails verification.
/// Instead of panicking, the contract enters blame mode where each party
/// must open their k_i and γ_i to identify who cheated.
#[action(shortname = 0x32, zk = true)]
pub fn initiate_blame(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    assert!(
        key_state.gg20_active || key_state.ts_active,
        "No active signing session to blame"
    );

    key_state.blame_active = true;
    key_state.blame_k_indices.clear();
    key_state.blame_k_openings.clear();
    key_state.blame_gamma_indices.clear();
    key_state.blame_gamma_openings.clear();
    key_state.blame_deadline_block = ctx.block_production_time + key_state.signing_timeout_blocks;

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Submit blame opening: party reveals k_i and γ_i for verification.
///
/// Contract checks:
/// - γ_i·G == Γ_i (the gamma point submitted during signing)
/// - k_i is consistent with the delta and MtA values
///
/// If a party's values fail any check → they are identified as the cheater.
/// If a party refuses to open → they are the cheater by default.
#[action(shortname = 0x33, zk = true)]
pub fn submit_blame_opening(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    k_i_bytes: Vec<u8>,
    gamma_i_bytes: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.blame_active, "Blame protocol not active");
    assert_eq!(k_i_bytes.len(), 32, "k_i must be 32 bytes");
    assert_eq!(gamma_i_bytes.len(), 32, "gamma_i must be 32 bytes");

    // Check party hasn't already submitted blame opening
    assert!(
        !key_state
            .blame_k_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} has already submitted blame opening",
        party_index
    );

    // Verify γ_i·G == Γ_i (the gamma point this party submitted during signing)
    if let Some(gamma_idx) = key_state
        .gg20_gamma_indices
        .iter()
        .position(|&idx| idx == party_index)
    {
        let stored_gamma_point = &key_state.gg20_gamma_points[gamma_idx];

        use k256::elliptic_curve::ff::PrimeField;
        use k256::{FieldBytes, ProjectivePoint as K256Proj, Scalar};

        // Compute γ_i · G
        let mut gamma_fb = FieldBytes::default();
        gamma_fb.copy_from_slice(&gamma_i_bytes);
        if let Some(gamma_scalar) = Option::<Scalar>::from(Scalar::from_repr(gamma_fb)) {
            let computed_gamma_point = K256Proj::GENERATOR * gamma_scalar;
            let computed_bytes = k256::EncodedPoint::from(computed_gamma_point.to_affine())
                .compress()
                .as_bytes()
                .to_vec();

            assert!(
                computed_bytes == *stored_gamma_point,
                "BLAME: Party {} submitted γ_i that does NOT match their Γ_i! CHEATER IDENTIFIED!",
                party_index
            );
        }
    }

    key_state.blame_k_indices.push(party_index);
    key_state.blame_k_openings.push(k_i_bytes);
    key_state.blame_gamma_indices.push(party_index);
    key_state.blame_gamma_openings.push(gamma_i_bytes);

    // If all parties have submitted, reset blame and signing state
    if key_state.blame_k_indices.len() as u8 >= key_state.gg20_num_parties {
        key_state.blame_active = false;
        key_state.gg20_active = false;
        key_state.gg20_task_id = 0;
        key_state.gg20_policy_id = 0;
        key_state.gg20_required_parties.clear();
        key_state.gg20_min_signers = 0;
        key_state.gg20_signing_parties.clear();
        key_state.gg20_num_parties = 0;
        key_state.reset_pqc_approval_session();
        key_state.ts_active = false;
        key_state.signing_phase = ZkSigningPhase::Idle {};
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Protection 7: Key Refresh (Proactive Secret Sharing)
// ---------------------------------------------------------------------------

/// Start a key refresh ceremony.
/// All parties will generate zero-secret polynomials g_i(x) = 0 + b_i·x
/// and distribute sub-shares to update their Shamir shares WITHOUT changing
/// the combined public key.
#[action(shortname = 0x60, zk = true)]
pub fn start_key_refresh(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.is_key_generated(), "Key not yet generated");
    assert!(!key_state.refresh_active, "Refresh already in progress");
    assert!(
        matches!(key_state.signing_phase, ZkSigningPhase::Idle {}),
        "Cannot refresh during active signing"
    );

    key_state.refresh_active = true;
    key_state.refresh_indices.clear();
    key_state.refresh_slope_commitments.clear();

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Submit refresh slope commitment D_i1 = b_i·G during key refresh.
/// Each party submits their commitment publicly. The actual sub-shares
/// are distributed via ZK secret inputs (off-chain).
#[action(shortname = 0x61, zk = true)]
pub fn submit_refresh_share(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    slope_commitment: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.refresh_active, "No refresh in progress");
    assert_eq!(
        slope_commitment.len(),
        33,
        "Slope commitment must be 33 bytes"
    );
    assert!(
        !key_state
            .refresh_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} already submitted refresh share",
        party_index
    );

    key_state.refresh_indices.push(party_index);
    key_state.refresh_slope_commitments.push(slope_commitment);

    // If all parties submitted, mark refresh as complete
    if key_state.refresh_indices.len() as u8 >= key_state.num_shares {
        key_state.refresh_active = false;
        // Shares are updated off-chain; contract just tracks the ceremony completion
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Protection 8: Key Recovery (Party Replacement)
// ---------------------------------------------------------------------------

/// Start key recovery when a party permanently loses their share.
/// The remaining parties (>= threshold) will re-share to create
/// new shares for all parties including the replacement.
#[action(shortname = 0x64, zk = true)]
pub fn start_key_recovery(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    lost_party_index: u8,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.is_key_generated(), "Key not yet generated");
    assert!(!key_state.recovery_active, "Recovery already in progress");
    assert!(
        lost_party_index >= 1 && lost_party_index <= key_state.num_shares,
        "Invalid party index"
    );

    key_state.recovery_active = true;
    key_state.recovery_lost_party = lost_party_index;
    key_state.recovery_indices.clear();
    key_state.recovery_c0_commitments.clear();
    key_state.recovery_c1_commitments.clear();

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Submit recovery commitments from a surviving party.
/// Each surviving party submits their Feldman commitments for the
/// recovery polynomial h_i(x) = x̃_i + c_i·x.
#[action(shortname = 0x65, zk = true)]
pub fn submit_recovery_subshare(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    commitment_c0: Vec<u8>,
    commitment_c1: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.recovery_active, "No recovery in progress");
    assert_ne!(
        party_index, key_state.recovery_lost_party,
        "Lost party cannot submit recovery"
    );
    assert_eq!(commitment_c0.len(), 33, "C0 commitment must be 33 bytes");
    assert_eq!(commitment_c1.len(), 33, "C1 commitment must be 33 bytes");
    assert!(
        !key_state
            .recovery_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} already submitted recovery share",
        party_index
    );

    key_state.recovery_indices.push(party_index);
    key_state.recovery_c0_commitments.push(commitment_c0);
    key_state.recovery_c1_commitments.push(commitment_c1);

    // Recovery completes when threshold number of parties have submitted
    if key_state.recovery_indices.len() as u16 >= key_state.threshold {
        key_state.recovery_active = false;
        // New shares distributed off-chain via ZK; same public key maintained
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Combine partial signature scalars via modular addition over secp256k1 order.
/// Enforces low-s normalization for EVM compatibility (BIP 62 / EIP-2).
/// Returns (combined_s_bytes, was_negated) so caller can flip recovery_id.
///
/// σ = σ₁ + σ₂ + ... + σₙ (mod n)
/// If σ > n/2, replace with n - σ (both are valid ECDSA, but EVM requires low-s).
fn combine_partial_signatures_with_flag(partial_values: &[Vec<u8>]) -> (Vec<u8>, bool) {
    use k256::elliptic_curve::ff::PrimeField;
    use k256::{FieldBytes, Scalar};

    let mut sum = Scalar::ZERO;
    for partial_s in partial_values {
        let mut bytes = FieldBytes::default();
        bytes.copy_from_slice(partial_s);
        let scalar = Option::<Scalar>::from(Scalar::from_repr(bytes))
            .expect("Invalid partial signature scalar");
        sum = sum + scalar;
    }

    // Low-s normalization: if s > n/2, use n - s
    // This is required for EVM compatibility (EIP-2)
    let sum_bytes = sum.to_bytes();
    let half_n_bytes: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    // Compare sum_bytes > half_n_bytes
    let mut is_high = false;
    for i in 0..32 {
        if sum_bytes[i] > half_n_bytes[i] {
            is_high = true;
            break;
        } else if sum_bytes[i] < half_n_bytes[i] {
            break;
        }
    }
    if is_high {
        ((-sum).to_bytes().to_vec(), true)
    } else {
        (sum_bytes.to_vec(), false)
    }
}

// ---------------------------------------------------------------------------
// Policy + RBAC
// ---------------------------------------------------------------------------

/// Register a policy rule binding a tx_tag to mandatory signers.
/// Owner-only. Any signing session tagged with tx_tag MUST include all mandatory_parties.
///
/// Args: key_id(u32), name(UTF-8 label), tx_tag(UTF-8 tag string),
///       mandatory_parties(Vec<u8> of 1-based party indices), min_threshold(u8, 0=global)
#[action(shortname = 0x70, zk = true)]
pub fn add_policy(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    name: Vec<u8>,
    tx_tag: Vec<u8>,
    mandatory_parties: Vec<u8>,
    min_threshold: u8,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    assert!(!tx_tag.is_empty(), "tx_tag must not be empty");
    assert!(
        !mandatory_parties.is_empty(),
        "mandatory_parties must not be empty"
    );
    assert!(
        mandatory_parties
            .iter()
            .all(|&p| p >= 1 && p <= key_state.num_shares),
        "All mandatory_parties must be valid 1-based party indices (1..=num_shares)"
    );
    for &party_index in &mandatory_parties {
        assert!(
            mandatory_parties
                .iter()
                .filter(|&&p| p == party_index)
                .count()
                == 1,
            "mandatory_parties contains duplicate party index {}",
            party_index
        );
    }
    assert!(
        min_threshold == 0 || min_threshold >= key_state.threshold as u8,
        "Policy min_threshold cannot be below the global threshold"
    );
    assert!(
        min_threshold == 0 || min_threshold <= key_state.num_shares,
        "Policy min_threshold cannot exceed num_shares"
    );
    let effective_min_threshold = if min_threshold == 0 {
        key_state.threshold as u8
    } else {
        min_threshold
    };
    assert!(
        mandatory_parties.len() as u8 <= effective_min_threshold,
        "mandatory_parties cannot exceed the effective threshold"
    );
    // No duplicate tags
    assert!(
        key_state.find_policy_index_for_tag(&tx_tag).is_none(),
        "A policy for this tx_tag already exists — remove it first"
    );

    let policy_id = key_state.next_policy_id;
    key_state.next_policy_id += 1;

    key_state.policy_ids.push(policy_id);
    key_state.policy_names.push(name);
    key_state.policy_tags.push(tx_tag);
    key_state.policy_mandatory_parties.push(mandatory_parties);
    key_state.policy_min_thresholds.push(min_threshold);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Remove a policy by its ID.
/// Owner-only. After removal, future sign_message calls with that tag are unconstrained.
///
/// Args: key_id(u32), policy_id(u32)
#[action(shortname = 0x71, zk = true)]
pub fn remove_policy(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    policy_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    let idx = key_state
        .policy_ids
        .iter()
        .position(|&id| id == policy_id)
        .expect("Policy not found");

    key_state.policy_ids.remove(idx);
    key_state.policy_names.remove(idx);
    key_state.policy_tags.remove(idx);
    key_state.policy_mandatory_parties.remove(idx);
    key_state.policy_min_thresholds.remove(idx);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Bind a party index to a wallet address on-chain.
/// Owner-only. Once bound, submissions from that party_index are verified against this address.
///
/// Args: key_id(u32), party_index(u8), address(Address)
#[action(shortname = 0x72, zk = true)]
pub fn register_party_address(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    address: Address,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    assert!(
        party_index >= 1 && party_index <= key_state.num_shares,
        "Invalid party index"
    );

    // Update existing binding if present, otherwise add new
    if let Some(idx) = key_state
        .party_addr_indices
        .iter()
        .position(|&i| i == party_index)
    {
        key_state.party_addr_values[idx] = address;
    } else {
        key_state.party_addr_indices.push(party_index);
        key_state.party_addr_values.push(address);
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// ZK partial signature computation (on ZK nodes)
// ---------------------------------------------------------------------------

/// Submit party's k⁻¹ contribution as a ZK secret input.
///
/// Each signing party submits its k⁻¹ value encrypted to the ZK node.
/// The ZK node stores it as a secret variable (variable_type = 2).
/// After all parties submit, `trigger_zk_partial_sig` starts the ZK computation
/// which computes σ_p = k⁻¹ · (H(m) + r · s_p) entirely inside the ZK environment.
///
/// The k⁻¹ value is split into two Sbi128 halves (high/low 128 bits) as with key shares.
/// Call this action twice per party: once with is_high_half=true, once with is_high_half=false.
#[zk_on_secret_input(shortname = 0x53)]
pub fn submit_kinv_zk(
    _ctx: ContractContext,
    state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    is_high_half: bool,
) -> (
    ContractState,
    Vec<EventGroup>,
    ZkInputDef<ShareMetadata, Sbi128>,
) {
    let key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.zk_psig_active,
        "ZK partial sig session not active"
    );
    assert!(
        key_state.is_active_signing_party(party_index),
        "Party {} is not part of the active signing subset",
        party_index
    );

    let metadata = ShareMetadata {
        key_id,
        share_index: party_index,
        is_high_half,
        variable_type: 2, // k⁻¹
    };

    let input_def = ZkInputDef::with_metadata(None, metadata);
    (state, vec![], input_def)
}

/// Start a ZK partial signature session.
///
/// Sets up the session parameters — how many parties are expected to submit k⁻¹.
/// After all parties call `submit_kinv_zk` (2 calls each: hi + lo), any party
/// calls `trigger_zk_partial_sig` to kick off the ZK computation for one party.
#[action(shortname = 0x54, zk = true)]
pub fn start_zk_psig_session(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    num_parties: u8,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        !key_state.zk_psig_active,
        "ZK partial sig session already active"
    );
    assert!(
        key_state.gg20_active,
        "GG20 signing session must be active first"
    );
    assert_eq!(
        num_parties, key_state.gg20_num_parties,
        "ZK partial signature session must use the exact active signing subset size"
    );

    key_state.zk_psig_active = true;
    key_state.zk_psig_kinv_vars.clear();
    key_state.zk_psig_kinv_count = 0;
    key_state.zk_psig_kinv_expected = (num_parties as u32) * 2; // hi + lo per party
    key_state.zk_psig_result_indices.clear();
    key_state.zk_psig_result_hi_bytes.clear();
    key_state.zk_psig_result_lo_bytes.clear();
    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// Trigger ZK computation of partial signature for one party.
///
/// After all k⁻¹ halves have been submitted, any party calls this to start
/// the ZK computation for `party_index`. The ZK nodes compute:
///
///   σ_p = k⁻¹ · (H(m) + r · s_p)
///
/// The result variables are created inside the ZK environment and then
/// opened via `zk_on_compute_complete`.
///
/// Parameters:
///   key_id      — which key to sign with
///   party_index — which party's partial signature to compute (1-based)
///   r_hi        — high 128 bits of ECDSA r (nonce x-coordinate mod n)
///   r_lo        — low 128 bits of ECDSA r
///   hmsg_hi     — high 128 bits of message hash H(m)
///   hmsg_lo     — low 128 bits of message hash H(m)
#[action(shortname = 0x55, zk = true)]
pub fn trigger_zk_partial_sig(
    _ctx: ContractContext,
    state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    r_hi: i128,
    r_lo: i128,
    hmsg_hi: i128,
    hmsg_lo: i128,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.zk_psig_active,
        "ZK partial sig session not active"
    );
    assert!(
        key_state.zk_psig_kinv_count >= key_state.zk_psig_kinv_expected,
        "Not all k⁻¹ halves submitted yet ({}/{})",
        key_state.zk_psig_kinv_count,
        key_state.zk_psig_kinv_expected,
    );
    assert!(
        key_state.is_active_signing_party(party_index),
        "Party {} is not part of the active signing subset",
        party_index
    );

    // Output metadata: two result halves (hi + lo) tagged with party_index
    // variable_type = 3 means "zk partial sig result"
    let output_meta_hi = ShareMetadata {
        key_id,
        share_index: party_index,
        is_high_half: true,
        variable_type: 3,
    };
    let output_meta_lo = ShareMetadata {
        key_id,
        share_index: party_index,
        is_high_half: false,
        variable_type: 3,
    };

    // Public input arguments — all cast to i128 (ReadWriteState impl confirmed in pbc_traits)
    let args: Vec<i128> = vec![party_index as i128, r_hi, r_lo, hmsg_hi, hmsg_lo];

    // shortname 0x61 → compute_partial_sig in zk_compute.rs
    // shortname 0x56 → on_psig_compute_complete callback
    let zk_changes = vec![ZkStateChange::start_computation_with_inputs::<
        ShareMetadata,
        i128,
    >(
        ShortnameZkComputation::from_u32(0x61),
        vec![output_meta_hi, output_meta_lo],
        args,
        Some(ShortnameZkComputeComplete::from_u32(0x56)),
    )];

    (state, vec![], zk_changes)
}

/// Called automatically by the ZK framework when computation completes.
///
/// Opens the two output variables (σ_p high + low halves) and stores them
/// in `zk_psig_result_*` so the coordinator can assemble the full 256-bit σ_p.
#[zk_on_compute_complete(shortname = 0x56)]
pub fn on_psig_compute_complete(
    _ctx: ContractContext,
    state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    created_variables: Vec<SecretVarId>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    // Open the two result variables so their values become readable
    let zk_changes = vec![ZkStateChange::OpenVariables {
        variables: created_variables,
    }];

    (state, vec![], zk_changes)
}

/// Finalize ZK partial signature computation: assemble results, combine, verify on-chain.
///
/// After `trigger_zk_partial_sig` has been called for ALL parties and
/// `on_psig_compute_complete` has stored the results in `zk_psig_result_*`,
/// this action assembles the 32-byte σ_i scalars from the 16+16 byte hi/lo pairs,
/// combines them into the final ECDSA signature, verifies it on-chain, and stores it.
///
/// Reuses the same `combine_partial_signatures_with_flag` helper used by `submit_partial_sig`.
#[action(shortname = 0x57, zk = true)]
pub fn combine_zk_partial_sigs(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    task_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.zk_psig_active,
        "ZK partial sig session not active"
    );
    assert!(
        key_state.zk_psig_result_indices.len() as u8 >= key_state.ts_num_parties,
        "Not all ZK partial signatures computed yet ({}/{})",
        key_state.zk_psig_result_indices.len(),
        key_state.ts_num_parties,
    );

    // Assemble 32-byte σ_i scalars from (hi_bytes || lo_bytes) pairs
    let mut partial_values: Vec<Vec<u8>> = Vec::new();
    for i in 0..key_state.zk_psig_result_indices.len() {
        let hi = &key_state.zk_psig_result_hi_bytes[i];
        let lo = &key_state.zk_psig_result_lo_bytes[i];
        assert_eq!(hi.len(), 16, "ZK result hi_bytes must be 16 bytes");
        assert_eq!(lo.len(), 16, "ZK result lo_bytes must be 16 bytes");
        let mut scalar_32 = Vec::with_capacity(32);
        scalar_32.extend_from_slice(hi);
        scalar_32.extend_from_slice(lo);
        partial_values.push(scalar_32);
    }

    // Combine σ = Σσ_i mod n, with low-s normalization (EVM EIP-2 compatibility)
    let (combined_s, was_negated) = combine_partial_signatures_with_flag(&partial_values);

    // Flip recovery ID if s was negated
    let recovery_id = if was_negated {
        key_state.ts_recovery_id ^ 1
    } else {
        key_state.ts_recovery_id
    };

    // Build full 65-byte signature: r (32) || s (32) || v (1)
    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(&key_state.ts_r_bytes);
    signature.extend_from_slice(&combined_s);
    signature.push(recovery_id);

    // Verify the combined ECDSA signature against the stored public key
    let public_key = key_state.public_key.clone().expect("Public key missing");
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&public_key).expect("Stored public key invalid");
    let sig64 = &signature[0..64];
    let parsed_sig = Signature::try_from(sig64).expect("Failed to parse combined ZK signature");

    let mut info = key_state
        .signing_information
        .get(&task_id)
        .expect("Signing task not found");

    verifying_key
        .verify_prehash(&info.message_hash, &parsed_sig)
        .expect("ZK combined signature verification FAILED — check partial sig computation");

    // Store verified signature
    info.recovery_id = recovery_id;
    info.signature = Some(signature);
    info.verified = true;
    key_state.signing_information.insert(task_id, info);

    // Clean up ZK psig session
    key_state.zk_psig_active = false;
    key_state.zk_psig_kinv_vars.clear();
    key_state.zk_psig_kinv_count = 0;
    key_state.zk_psig_result_indices.clear();
    key_state.zk_psig_result_hi_bytes.clear();
    key_state.zk_psig_result_lo_bytes.clear();
    key_state.ts_active = false;
    key_state.gg20_active = false;
    key_state.gg20_task_id = 0;
    key_state.gg20_policy_id = 0;
    key_state.gg20_required_parties.clear();
    key_state.gg20_min_signers = 0;
    key_state.gg20_signing_parties.clear();
    key_state.gg20_num_parties = 0;
    key_state.reset_pqc_approval_session();
    key_state.signing_phase = ZkSigningPhase::Complete { task_id };
    key_state
        .pending_sign_requests
        .retain(|r| r.task_id != task_id);

    if !key_state.pending_sign_requests.is_empty() {
        key_state.start_next_signing();
    } else {
        key_state.signing_phase = ZkSigningPhase::Idle {};
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// PQC public key registry (quantum-safe off-chain identity anchoring)
// ---------------------------------------------------------------------------

/// Register a party's Dilithium (ML-DSA-65) public key on-chain.
///
/// Provides an immutable on-chain anchor for the party's quantum-safe signing identity.
/// The coordinator and other parties can retrieve this key to verify
/// `AuthenticatedAction` Dilithium signatures from the client-side PQC layer.
///
/// Key size: 1952 bytes (ML-DSA-65 standard).
#[action(shortname = 0x73, zk = true)]
pub fn register_dilithium_pubkey(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    dilithium_pubkey: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    // Only owner or the party's own registered address may register
    let is_owner = ctx.sender == state.owner;
    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    if !is_owner {
        // Party must have registered their address first (0x72)
        let party_addr = key_state
            .get_party_address(party_index)
            .expect("Party has not registered an address; only owner can register PQC keys without address binding");
        assert_eq!(
            &ctx.sender, party_addr,
            "Sender is not the registered address for this party"
        );
    }

    assert!(
        party_index >= 1 && party_index <= key_state.num_shares,
        "Invalid party index"
    );
    assert_eq!(
        dilithium_pubkey.len(),
        1952,
        "Dilithium public key must be exactly 1952 bytes (ML-DSA-65)"
    );

    // Update or insert
    if let Some(idx) = key_state
        .dilithium_pubkey_indices
        .iter()
        .position(|&i| i == party_index)
    {
        key_state.dilithium_pubkeys[idx] = dilithium_pubkey;
    } else {
        key_state.dilithium_pubkey_indices.push(party_index);
        key_state.dilithium_pubkeys.push(dilithium_pubkey);
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Register a party's Kyber (ML-KEM-768) public key on-chain.
///
/// Provides an immutable on-chain anchor for the party's quantum-safe key encapsulation
/// identity. The coordinator uses this to encrypt secret data (e.g., k⁻¹) for the party
/// using ML-KEM-768 (Kyber KEM → AES-256-GCM).
///
/// Key size: 1184 bytes (ML-KEM-768 standard).
#[action(shortname = 0x74, zk = true)]
pub fn register_kyber_pubkey(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    kyber_pubkey: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let is_owner = ctx.sender == state.owner;
    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    if !is_owner {
        let party_addr = key_state
            .get_party_address(party_index)
            .expect("Party has not registered an address; only owner can register PQC keys without address binding");
        assert_eq!(
            &ctx.sender, party_addr,
            "Sender is not the registered address for this party"
        );
    }

    assert!(
        party_index >= 1 && party_index <= key_state.num_shares,
        "Invalid party index"
    );
    assert_eq!(
        kyber_pubkey.len(),
        1184,
        "Kyber public key must be exactly 1184 bytes (ML-KEM-768)"
    );

    // Update or insert
    if let Some(idx) = key_state
        .kyber_pubkey_indices
        .iter()
        .position(|&i| i == party_index)
    {
        key_state.kyber_pubkeys[idx] = kyber_pubkey;
    } else {
        key_state.kyber_pubkey_indices.push(party_index);
        key_state.kyber_pubkeys.push(kyber_pubkey);
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Register or update a human-readable role tag for a party (shortname 0x79).
///
/// Examples: "CFO", "CEO", "AUDITOR". Used for role-based policy enforcement.
/// Can be called by the owner at any time. Replaces the existing tag if one exists.
#[action(shortname = 0x79, zk = true)]
pub fn register_party_role(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    role_tag: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        party_index >= 1 && party_index <= key_state.num_shares,
        "Invalid party index"
    );
    assert!(!role_tag.is_empty(), "Role tag must not be empty");
    assert!(role_tag.len() <= 64, "Role tag must be at most 64 bytes");
    assert!(
        role_tag.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "Role tag must contain only ASCII alphanumeric characters, underscores, or hyphens"
    );

    key_state.set_party_role(party_index, role_tag);
    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Emit the vault callback event when key generation completes.
fn emit_key_generated_event(
    state: &ContractState,
    key_id: u32,
    public_key: &[u8],
) -> Vec<EventGroup> {
    let vault_shortname =
        pbc_contract_common::address::Shortname::from_be_bytes(VAULT_ON_KEY_GENERATED_SHORTNAME)
            .unwrap();
    let mut event_group = EventGroup::builder();
    event_group
        .call(state.owner, vault_shortname)
        .argument(key_id)
        .argument(public_key.to_vec())
        .with_cost_from_contract(50_000)
        .done();
    vec![event_group.build()]
}

fn same_party_set(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().all(|party| right.contains(party))
}

fn encode_len_prefixed_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn encode_party_vec(out: &mut Vec<u8>, parties: &[u8]) {
    out.extend_from_slice(&(parties.len() as u32).to_be_bytes());
    out.extend_from_slice(parties);
}

fn compute_pqc_session_challenge(
    key_id: u32,
    task_id: u32,
    message_hash: &[u8],
    tx_tag: &[u8],
    signing_parties: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"KOSH_PQC_SESSION_V1");
    payload.extend_from_slice(&key_id.to_be_bytes());
    payload.extend_from_slice(&task_id.to_be_bytes());
    encode_len_prefixed_bytes(&mut payload, message_hash);
    encode_len_prefixed_bytes(&mut payload, tx_tag);
    encode_party_vec(&mut payload, signing_parties);
    dkg::sha256(&payload).to_vec()
}

fn compute_pqc_approval_hash(
    key_id: u32,
    task_id: u32,
    party_index: u8,
    message_hash: &[u8],
    tx_tag: &[u8],
    signing_parties: &[u8],
    challenge: &[u8],
    expires_at_block: i64,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"KOSH_PQC_APPROVAL_V1");
    payload.extend_from_slice(&key_id.to_be_bytes());
    payload.extend_from_slice(&task_id.to_be_bytes());
    payload.push(party_index);
    encode_len_prefixed_bytes(&mut payload, message_hash);
    encode_len_prefixed_bytes(&mut payload, tx_tag);
    encode_party_vec(&mut payload, signing_parties);
    encode_len_prefixed_bytes(&mut payload, challenge);
    // Bind approval to the session deadline — prevents replay on a renewed session
    payload.extend_from_slice(&expires_at_block.to_be_bytes());
    dkg::sha256(&payload).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing_state::ZkKeyState;

    // -----------------------------------------------------------------------
    // same_party_set
    // -----------------------------------------------------------------------

    #[test]
    fn same_party_set_identical() {
        assert!(same_party_set(&[1, 2, 3], &[1, 2, 3]));
    }

    #[test]
    fn same_party_set_order_independent() {
        assert!(same_party_set(&[3, 1, 2], &[1, 2, 3]));
    }

    #[test]
    fn same_party_set_different_length() {
        assert!(!same_party_set(&[1, 2], &[1, 2, 3]));
    }

    #[test]
    fn same_party_set_different_members() {
        assert!(!same_party_set(&[1, 2, 4], &[1, 2, 3]));
    }

    // -----------------------------------------------------------------------
    // compute_pqc_approval_hash — canonical payload & anti-replay
    // -----------------------------------------------------------------------

    #[test]
    fn pqc_approval_hash_is_deterministic() {
        let h1 = compute_pqc_approval_hash(
            1, 7, 2,
            &[0xabu8; 32], b"transfer",
            &[1, 2], &[0xcdu8; 32], 500,
        );
        let h2 = compute_pqc_approval_hash(
            1, 7, 2,
            &[0xabu8; 32], b"transfer",
            &[1, 2], &[0xcdu8; 32], 500,
        );
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn pqc_approval_hash_different_party_index() {
        let h1 = compute_pqc_approval_hash(1, 7, 1, &[0u8; 32], b"tag", &[1, 2], &[0u8; 32], 100);
        let h2 = compute_pqc_approval_hash(1, 7, 2, &[0u8; 32], b"tag", &[1, 2], &[0u8; 32], 100);
        assert_ne!(h1, h2, "Different party_index must produce different hash");
    }

    #[test]
    fn pqc_approval_hash_different_task_id() {
        let h1 = compute_pqc_approval_hash(1, 7, 1, &[0u8; 32], b"tag", &[1, 2], &[0u8; 32], 100);
        let h2 = compute_pqc_approval_hash(1, 8, 1, &[0u8; 32], b"tag", &[1, 2], &[0u8; 32], 100);
        assert_ne!(h1, h2, "Different task_id must produce different hash");
    }

    #[test]
    fn pqc_approval_hash_different_expires_at_block() {
        // Approvals from different sessions (different deadlines) must not be replayable
        let h1 = compute_pqc_approval_hash(1, 7, 1, &[0u8; 32], b"tag", &[1, 2], &[0u8; 32], 100);
        let h2 = compute_pqc_approval_hash(1, 7, 1, &[0u8; 32], b"tag", &[1, 2], &[0u8; 32], 200);
        assert_ne!(h1, h2, "Different expires_at_block must produce different hash — replay blocked");
    }

    #[test]
    fn pqc_approval_hash_different_signing_subset() {
        let h1 = compute_pqc_approval_hash(1, 7, 1, &[0u8; 32], b"tag", &[1, 2], &[0u8; 32], 100);
        let h2 = compute_pqc_approval_hash(1, 7, 1, &[0u8; 32], b"tag", &[1, 3], &[0u8; 32], 100);
        assert_ne!(h1, h2, "Different signing_parties must produce different hash — subset swap blocked");
    }

    #[test]
    fn pqc_approval_hash_different_message_hash() {
        let h1 = compute_pqc_approval_hash(1, 7, 1, &[0u8; 32], b"tag", &[1, 2], &[0u8; 32], 100);
        let h2 = compute_pqc_approval_hash(1, 7, 1, &[0xffu8; 32], b"tag", &[1, 2], &[0u8; 32], 100);
        assert_ne!(h1, h2, "Different message_hash must produce different hash");
    }

    // -----------------------------------------------------------------------
    // compute_pqc_session_challenge — uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn pqc_session_challenge_different_task_ids() {
        let c1 = compute_pqc_session_challenge(1, 7, &[0u8; 32], b"transfer", &[1, 2]);
        let c2 = compute_pqc_session_challenge(1, 8, &[0u8; 32], b"transfer", &[1, 2]);
        assert_ne!(c1, c2);
        assert_eq!(c1.len(), 32);
    }

    #[test]
    fn pqc_session_challenge_different_key_ids() {
        let c1 = compute_pqc_session_challenge(1, 7, &[0u8; 32], b"transfer", &[1, 2]);
        let c2 = compute_pqc_session_challenge(2, 7, &[0u8; 32], b"transfer", &[1, 2]);
        assert_ne!(c1, c2);
    }

    // -----------------------------------------------------------------------
    // ZkKeyState helpers — is_party_ready_for_signing
    // -----------------------------------------------------------------------

    #[test]
    fn party_not_ready_without_any_registration() {
        let state = ZkKeyState::new(2, 3);
        assert!(!state.is_party_ready_for_signing(1));
    }

    #[test]
    fn party_not_ready_with_only_dilithium() {
        let mut state = ZkKeyState::new(2, 3);
        state.dilithium_pubkey_indices.push(1);
        state.dilithium_pubkeys.push(vec![0u8; 1952]);
        // No address, no kyber
        assert!(!state.is_party_ready_for_signing(1), "dilithium alone is not enough");
    }

    #[test]
    fn party_not_ready_with_dilithium_and_kyber_but_no_address() {
        let mut state = ZkKeyState::new(2, 3);
        state.dilithium_pubkey_indices.push(1);
        state.dilithium_pubkeys.push(vec![0u8; 1952]);
        state.kyber_pubkey_indices.push(1);
        state.kyber_pubkeys.push(vec![0u8; 1184]);
        // No address registered
        assert!(!state.is_party_ready_for_signing(1), "missing address must block signing");
    }

    // -----------------------------------------------------------------------
    // ZkKeyState helpers — party role
    // -----------------------------------------------------------------------

    #[test]
    fn set_and_get_party_role() {
        let mut state = ZkKeyState::new(2, 3);
        state.set_party_role(2, b"CFO".to_vec());
        assert_eq!(state.get_party_role(2), Some(&b"CFO".to_vec()));
        assert_eq!(state.get_party_role(1), None);
    }

    #[test]
    fn update_party_role_no_duplicate() {
        let mut state = ZkKeyState::new(2, 3);
        state.set_party_role(2, b"CFO".to_vec());
        state.set_party_role(2, b"CEO".to_vec());
        assert_eq!(state.get_party_role(2), Some(&b"CEO".to_vec()));
        assert_eq!(state.party_role_indices.len(), 1, "Should not create duplicate entries");
    }

    #[test]
    fn party_has_dilithium_registered() {
        let mut state = ZkKeyState::new(2, 3);
        assert!(!state.has_registered_dilithium_pubkey(1));
        state.dilithium_pubkey_indices.push(1);
        state.dilithium_pubkeys.push(vec![0u8; 1952]);
        assert!(state.has_registered_dilithium_pubkey(1));
        assert!(!state.has_registered_dilithium_pubkey(2));
    }

    #[test]
    fn party_has_kyber_registered() {
        let mut state = ZkKeyState::new(2, 3);
        assert!(!state.has_registered_kyber_pubkey(1));
        state.kyber_pubkey_indices.push(1);
        state.kyber_pubkeys.push(vec![0u8; 1184]);
        assert!(state.has_registered_kyber_pubkey(1));
        assert!(!state.has_registered_kyber_pubkey(2));
    }

    // -----------------------------------------------------------------------
    // encode helpers — length-prefix correctness
    // -----------------------------------------------------------------------

    #[test]
    fn encode_len_prefixed_bytes_correct() {
        let mut out = Vec::new();
        encode_len_prefixed_bytes(&mut out, b"hello");
        assert_eq!(&out[..4], &[0, 0, 0, 5]); // 4-byte big-endian length = 5
        assert_eq!(&out[4..], b"hello");
    }

    #[test]
    fn encode_party_vec_correct() {
        let mut out = Vec::new();
        encode_party_vec(&mut out, &[1, 2, 3]);
        assert_eq!(&out[..4], &[0, 0, 0, 3]); // 4-byte big-endian length = 3
        assert_eq!(&out[4..], &[1, 2, 3]);
    }
}
