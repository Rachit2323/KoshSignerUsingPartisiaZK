/// Binary encoding for kosh-zk-signer contract actions.
/// Partisia RPC format: [0x09, shortname, ...args]
/// u32 → big-endian 4 bytes, Vec<u8> → 4-byte BE length + data

fn encode_u32_be(n: u32) -> Vec<u8> {
    n.to_be_bytes().to_vec()
}

fn encode_vec(data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

/// Wraps args with the Partisia RPC prefix: [0x09, shortname, ...args]
fn encode_action(shortname: u8, args: &[u8]) -> Vec<u8> {
    let mut rpc = vec![0x09u8, shortname];
    rpc.extend_from_slice(args);
    rpc
}

/// 0x20 dkg_create_key
pub fn build_dkg_create_key(key_id: u32, num_parties: u8) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(num_parties);
    encode_action(0x20, &args)
}

/// 0x21 dkg_commit
pub fn build_dkg_commit(
    key_id: u32,
    party_index: u8,
    commitment_hash: &[u8],   // 32 bytes SHA-256
    slope_commitment: &[u8],  // 33 bytes compressed EC point
    schnorr_r: &[u8],         // 33 bytes compressed EC point
    schnorr_z: &[u8],         // 32 bytes scalar
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(commitment_hash));
    args.extend_from_slice(&encode_vec(slope_commitment));
    args.extend_from_slice(&encode_vec(schnorr_r));
    args.extend_from_slice(&encode_vec(schnorr_z));
    encode_action(0x21, &args)
}

/// 0x22 dkg_reveal
pub fn build_dkg_reveal(key_id: u32, party_index: u8, pk_share: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(pk_share));
    encode_action(0x22, &args)
}

/// 0x23 dkg_finalize
pub fn build_dkg_finalize(key_id: u32) -> Vec<u8> {
    encode_action(0x23, &encode_u32_be(key_id))
}

/// 0x24 dkg_complete_keygen
pub fn build_dkg_complete_keygen(key_id: u32) -> Vec<u8> {
    encode_action(0x24, &encode_u32_be(key_id))
}

/// 0x50 gg20_start_signing (triggers ZK nodes to start partial sig computation)
pub fn build_gg20_start_signing(key_id: u32, task_id: u32, signing_parties: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    args.extend_from_slice(&encode_vec(signing_parties));
    encode_action(0x50, &args)
}

/// 0x49 commit_delta (commit hash of delta_i before reveal)
pub fn build_commit_delta(key_id: u32, party_index: u8, commitment_hash: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(commitment_hash));
    encode_action(0x49, &args)
}

/// 0x45 submit_delta (reveal plaintext delta_i scalar)
pub fn build_submit_delta(key_id: u32, party_index: u8, delta_bytes: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(delta_bytes));
    encode_action(0x45, &args)
}

/// 0x46 submit_gamma_point (Gamma_i = gamma_i * G)
pub fn build_submit_gamma(key_id: u32, party_index: u8, gamma_point: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(gamma_point));
    encode_action(0x46, &args)
}

/// 0x47 gg20_finalize_r (Party 1: compute R = delta^-1 * Gamma on-chain)
pub fn build_gg20_finalize_r(key_id: u32) -> Vec<u8> {
    encode_action(0x47, &encode_u32_be(key_id))
}

/// 0x52 submit_partial_sig (submit s_i after R is known)
pub fn build_submit_partial_sig(
    key_id: u32,
    task_id: u32,
    party_index: u8,
    partial_sig: &[u8],
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    args.push(party_index);
    args.extend_from_slice(&encode_vec(partial_sig));
    encode_action(0x52, &args)
}

/// 0x75 start_pqc_approval_session (required before gg20_start_signing)
pub fn build_start_pqc_approval(key_id: u32, task_id: u32, signing_parties: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    args.extend_from_slice(&encode_vec(signing_parties));
    encode_action(0x75, &args)
}

/// 0x76 submit_pqc_approval
pub fn build_submit_pqc_approval(
    key_id: u32,
    task_id: u32,
    party_index: u8,
    approval_hash: &[u8],
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    args.push(party_index);
    args.extend_from_slice(&encode_vec(approval_hash));
    encode_action(0x76, &args)
}

/// 0x77 finalize_pqc_approval
pub fn build_finalize_pqc_approval(key_id: u32, task_id: u32) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    encode_action(0x77, &args)
}
