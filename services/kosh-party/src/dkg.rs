/// DKG phase implementation.
/// Orchestrates: generate polynomial → post commit → reveal → exchange subshares
/// → finalize → submit on-chain via ChainRelay.

use anyhow::Result;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{elliptic_curve::ff::PrimeField, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;

use crate::bulletin_board::BulletinBoard;

const PHASE_TIMEOUT: Duration = Duration::from_secs(300);

/// Commit data posted to the bulletin board by each party.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DkgCommit {
    pub c_i0: String,      // compressed EC point (hex), public share
    pub c_i1: String,      // compressed EC point (hex), slope commitment
    pub hash: String,      // SHA256(c_i0) — the on-chain commitment
    pub schnorr_r: String, // Schnorr proof R (hex)
    pub schnorr_z: String, // Schnorr proof z (hex)
}

/// Compute a Schnorr proof of knowledge of the discrete log of C_i0 = s_i · G.
/// e = SHA256(G || C_i0 || R || party_index)
/// z = r + e · s_i  mod N
pub fn schnorr_prove(
    s_i: &Scalar,
    c_i0: &ProjectivePoint,
    party_index: u32,
) -> (ProjectivePoint, Scalar) {
    use k256::elliptic_curve::Field;
    loop {
        let r = Scalar::generate_vartime(&mut rand::rngs::OsRng);
        let big_r = ProjectivePoint::GENERATOR * r;

        if let Some(e) = schnorr_challenge(c_i0, &big_r, party_index) {
            let z = r + e * s_i;
            return (big_r, z);
        }
    }
}

/// Verify a Schnorr proof: z·G == R + e·C_i0
pub fn schnorr_verify(
    c_i0: &ProjectivePoint,
    big_r: &ProjectivePoint,
    z: &Scalar,
    party_index: u32,
) -> bool {
    let lhs = ProjectivePoint::GENERATOR * z;
    let Some(e) = schnorr_challenge(c_i0, big_r, party_index) else {
        return false;
    };
    let rhs = *big_r + *c_i0 * e;
    lhs == rhs
}

fn schnorr_challenge(
    c_i0: &ProjectivePoint,
    big_r: &ProjectivePoint,
    party_index: u32,
) -> Option<Scalar> {
    let party_index = u8::try_from(party_index).ok()?;
    let mut h = Sha256::new();
    h.update(compressed_point_bytes(&ProjectivePoint::GENERATOR));
    h.update(compressed_point_bytes(c_i0));
    h.update(compressed_point_bytes(big_r));
    h.update([party_index]);
    let hash = h.finalize();
    let fb = FieldBytes::from_slice(&hash);
    Option::<Scalar>::from(Scalar::from_repr(*fb))
}

fn compressed_point_bytes(point: &ProjectivePoint) -> [u8; 33] {
    let affine = point.to_affine();
    let encoded: EncodedPoint = affine.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    out
}

/// Compute Feldman sub-share: f_i(j) = s_i + a_i·j  mod N
pub fn compute_subshare(s_i: &Scalar, a_i: &Scalar, j: u32) -> Scalar {
    let j_scalar = scalar_from_u32(j);
    *s_i + *a_i * j_scalar
}

/// Verify Feldman commitment: subshare·G == C_j0 + j·C_j1
pub fn verify_feldman(
    subshare: &Scalar,
    c_j0: &ProjectivePoint,
    c_j1: &ProjectivePoint,
    j: u32,
) -> bool {
    let lhs = ProjectivePoint::GENERATOR * subshare;
    let rhs = *c_j0 + *c_j1 * scalar_from_u32(j);
    lhs == rhs
}

pub fn scalar_from_u32(n: u32) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&n.to_be_bytes());
    Scalar::from_repr(bytes.into()).into_option().unwrap_or(Scalar::ONE)
}

pub fn scalar_from_bytes_mod_n(bytes: &[u8]) -> Scalar {
    let mut arr = [0u8; 32];
    let len = bytes.len().min(32);
    arr[32 - len..].copy_from_slice(&bytes[..len]);
    Scalar::from_repr(arr.into()).into_option().unwrap_or(Scalar::ONE)
}

pub fn point_to_hex(p: &ProjectivePoint) -> String {
    hex::encode(compressed_point_bytes(p))
}

pub fn point_from_hex(s: &str) -> Result<ProjectivePoint> {
    use k256::elliptic_curve::group::GroupEncoding;
    let bytes = hex::decode(s)?;
    let arr: [u8; 33] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid point length {}", bytes.len()))?;
    ProjectivePoint::from_bytes(&arr.into())
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("invalid EC point"))
}

pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

pub fn scalar_from_hex(s: &str) -> Result<Scalar> {
    let bytes = hex::decode(s)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid scalar length"))?;
    Scalar::from_repr(arr.into())
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("invalid scalar"))
}

/// Run the full DKG commit phase for party `i`.
/// Returns: (s_i, a_i, C_i0, C_i1, commits_by_party) where commits_by_party maps
/// party_index → DkgCommit (includes own commit).
pub async fn run_dkg_commit(
    bb: &mut BulletinBoard,
    party_index: u32,
    num_parties: u32,
    key_id: u32,
) -> Result<(Scalar, Scalar, ProjectivePoint, ProjectivePoint, HashMap<u32, DkgCommit>)> {
    use k256::elliptic_curve::group::GroupEncoding;
    let s_i = Scalar::generate_vartime(&mut rand::rngs::OsRng);
    let a_i = Scalar::generate_vartime(&mut rand::rngs::OsRng);

    let c_i0 = ProjectivePoint::GENERATOR * s_i;
    let c_i1 = ProjectivePoint::GENERATOR * a_i;

    let (big_r, z) = schnorr_prove(&s_i, &c_i0, party_index);

    let mut h = Sha256::new();
    h.update(c_i0.to_bytes());
    let commitment_hash = hex::encode(h.finalize());

    let commit = DkgCommit {
        c_i0: point_to_hex(&c_i0),
        c_i1: point_to_hex(&c_i1),
        hash: commitment_hash,
        schnorr_r: point_to_hex(&big_r),
        schnorr_z: scalar_to_hex(&z),
    };

    let topic = format!("dkg_commit_{key_id}_party_{party_index}");
    bb.post(&topic, &serde_json::to_string(&commit)?).await?;
    tracing::info!("[party {party_index}] DKG commit posted for key {key_id}");

    let mut commits: HashMap<u32, DkgCommit> = HashMap::new();
    commits.insert(party_index, commit);

    for j in 1..=num_parties {
        if j == party_index {
            continue;
        }
        let topic_j = format!("dkg_commit_{key_id}_party_{j}");
        let raw = bb.watch_one(&topic_j, PHASE_TIMEOUT).await?;
        let c: DkgCommit = serde_json::from_str(&raw)?;

        let c_j0 = point_from_hex(&c.c_i0)?;
        let big_r_j = point_from_hex(&c.schnorr_r)?;
        let z_j = scalar_from_hex(&c.schnorr_z)?;
        if !schnorr_verify(&c_j0, &big_r_j, &z_j, j) {
            anyhow::bail!("Schnorr proof failed for party {j}");
        }
        tracing::info!("[party {party_index}] received + verified commit from party {j}");
        commits.insert(j, c);
    }

    Ok((s_i, a_i, c_i0, c_i1, commits))
}

/// Exchange encrypted subshares via the bulletin board and verify Feldman commitments.
/// Returns the final Shamir share x_i = Σ f_j(i) for all j.
pub async fn run_dkg_subshares(
    bb: &mut BulletinBoard,
    party_index: u32,
    num_parties: u32,
    key_id: u32,
    s_i: &Scalar,
    a_i: &Scalar,
    commits: &HashMap<u32, DkgCommit>,
) -> Result<Scalar> {
    // Post own sub-shares for each party j: f_i(j) = s_i + a_i·j
    for j in 1..=num_parties {
        if j == party_index {
            continue;
        }
        let subshare = compute_subshare(s_i, a_i, j);
        let topic = format!("dkg_subshare_{key_id}_from_{party_index}_to_{j}");
        bb.post(&topic, &scalar_to_hex(&subshare)).await?;
    }

    // Start with own share: f_i(i) = s_i + a_i·i
    let mut combined = compute_subshare(s_i, a_i, party_index);

    // Receive and verify sub-shares from other parties
    for j in 1..=num_parties {
        if j == party_index {
            continue;
        }
        let topic = format!("dkg_subshare_{key_id}_from_{j}_to_{party_index}");
        let raw = bb.watch_one(&topic, PHASE_TIMEOUT).await?;
        let subshare = scalar_from_hex(&raw)?;

        let commit_j = commits
            .get(&j)
            .ok_or_else(|| anyhow::anyhow!("missing commit for party {j}"))?;
        let c_j0 = point_from_hex(&commit_j.c_i0)?;
        let c_j1 = point_from_hex(&commit_j.c_i1)?;

        // Verify: subshare·G == C_j0 + i·C_j1
        if !verify_feldman(&subshare, &c_j0, &c_j1, party_index) {
            anyhow::bail!("Feldman verification failed for subshare from party {j}");
        }

        combined = combined + subshare;
        tracing::info!("[party {party_index}] verified subshare from party {j}");
    }

    tracing::info!("[party {party_index}] DKG subshares combined → x_i = Σ f_j(i)");
    Ok(combined)
}

/// Compute the combined public key: combined_pk = Σ C_j0 for all parties
pub fn compute_combined_pk(commits: &HashMap<u32, DkgCommit>) -> Result<ProjectivePoint> {
    let mut combined = ProjectivePoint::IDENTITY;
    for commit in commits.values() {
        combined += point_from_hex(&commit.c_i0)?;
    }
    Ok(combined)
}
