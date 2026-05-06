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

/// 0x20 dkg_create_key
pub fn build_dkg_create_key(key_id: u32, num_parties: u8) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(num_parties);
    args
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
    args
}

/// 0x22 dkg_reveal
pub fn build_dkg_reveal(key_id: u32, party_index: u8, pk_share: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(pk_share));
    args
}

/// 0x23 dkg_finalize
pub fn build_dkg_finalize(key_id: u32) -> Vec<u8> {
    encode_u32_be(key_id)
}

/// 0x24 dkg_complete_keygen
pub fn build_dkg_complete_keygen(key_id: u32) -> Vec<u8> {
    encode_u32_be(key_id)
}

/// 0x50 gg20_start_signing (triggers ZK nodes to start partial sig computation)
pub fn build_gg20_start_signing(key_id: u32, task_id: u32, signing_parties: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    args.extend_from_slice(&encode_vec(signing_parties));
    args
}

/// 0x49 commit_delta (commit hash of delta_i before reveal)
pub fn build_commit_delta(key_id: u32, party_index: u8, commitment_hash: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(commitment_hash));
    args
}

/// 0x45 submit_delta (reveal plaintext delta_i scalar)
pub fn build_submit_delta(key_id: u32, party_index: u8, delta_bytes: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(delta_bytes));
    args
}

/// 0x46 submit_gamma_point (Gamma_i = gamma_i * G)
pub fn build_submit_gamma(key_id: u32, party_index: u8, gamma_point: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(gamma_point));
    args
}

/// 0x47 gg20_finalize_r (Party 1: compute R = delta^-1 * Gamma on-chain)
pub fn build_gg20_finalize_r(key_id: u32) -> Vec<u8> {
    encode_u32_be(key_id)
}

/// 0x10 submit_key_share (secret input; raw args only)
pub fn build_submit_key_share(
    key_id: u32,
    share_index: u8,
    is_high_half: bool,
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(share_index);
    args.push(if is_high_half { 1 } else { 0 });
    args
}

/// 0x51 submit_delta_zk (secret input; raw args only)
pub fn build_submit_delta_zk(
    key_id: u32,
    party_index: u8,
    is_high_half: bool,
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.push(if is_high_half { 1 } else { 0 });
    args
}

/// 0x52 open_gg20_deltas
pub fn build_open_gg20_deltas(key_id: u32) -> Vec<u8> {
    encode_u32_be(key_id)
}

/// 0x53 submit_kinv_zk (secret input; raw args only)
pub fn build_submit_kinv_zk(
    key_id: u32,
    party_index: u8,
    is_high_half: bool,
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.push(if is_high_half { 1 } else { 0 });
    args
}

/// 0x54 start_zk_psig_session
pub fn build_start_zk_psig_session(key_id: u32, num_parties: u8) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(num_parties);
    args
}

/// 0x55 trigger_zk_partial_sig
pub fn build_trigger_zk_partial_sig(
    key_id: u32,
    party_index: u8,
    r_hi: i128,
    r_lo: i128,
    hmsg_hi: i128,
    hmsg_lo: i128,
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&r_hi.to_be_bytes());
    args.extend_from_slice(&r_lo.to_be_bytes());
    args.extend_from_slice(&hmsg_hi.to_be_bytes());
    args.extend_from_slice(&hmsg_lo.to_be_bytes());
    args
}

/// 0x57 combine_zk_partial_sigs
pub fn build_combine_zk_partial_sigs(key_id: u32, task_id: u32) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    args
}

/// 0x75 start_pqc_approval_session (required before gg20_start_signing)
pub fn build_start_pqc_approval(key_id: u32, task_id: u32, signing_parties: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    args.extend_from_slice(&encode_vec(signing_parties));
    args
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
    args
}

/// 0x77 finalize_pqc_approval
pub fn build_finalize_pqc_approval(key_id: u32, task_id: u32) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    args
}
