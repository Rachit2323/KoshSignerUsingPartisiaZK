use k256::Scalar;
use num_bigint::BigUint;

/// Output of one MtA pair exchange.
pub struct MtAOutput {
    pub counterparty: u32,
    /// Additive share of k_i · x_j (from k·x MtA)
    pub alpha_kx: Scalar,
    /// Masking term for k·x cross (our beta)
    pub beta_kx: Scalar,
    /// Additive share of k_i · gamma_j (from k·gamma MtA)
    pub alpha_kgamma: Scalar,
    /// Masking term for k·gamma cross (our beta)
    pub beta_kgamma: Scalar,
}

/// Paillier key pair (2048-bit).
#[derive(Clone)]
pub struct PaillierPubKey {
    pub n: BigUint,
    pub n2: BigUint,
    pub g: BigUint,
}

/// Paillier private key. BigUint doesn't implement Zeroize, so we drop manually.
#[derive(Clone)]
pub struct PaillierPrivKey {
    pub lambda: BigUint,
    pub mu: BigUint,
}

impl Drop for PaillierPrivKey {
    fn drop(&mut self) {
        // Best-effort clear — BigUint heap data
        self.lambda = BigUint::default();
        self.mu = BigUint::default();
    }
}

/// GG20 per-session state for one party.
pub struct Gg20State {
    pub key_id: u32,
    pub task_id: u32,
    pub party_index: u32,
    pub signing_subset: Vec<u32>,
    pub message_hash: [u8; 32],
    pub tx_tag: String,

    pub k_i: Option<Scalar>,
    pub gamma_i: Option<Scalar>,
    pub big_gamma_i: Option<k256::ProjectivePoint>,
    pub x_i: Option<Scalar>,
    pub delta_i: Option<Scalar>,
    pub sigma_i: Option<Scalar>,
    pub r_scalar: Option<Scalar>,
    pub mta_outputs: Vec<MtAOutput>,
}

impl Gg20State {
    pub fn new(
        key_id: u32,
        task_id: u32,
        party_index: u32,
        signing_subset: Vec<u32>,
        message_hash: [u8; 32],
        tx_tag: String,
    ) -> Self {
        Self {
            key_id,
            task_id,
            party_index,
            signing_subset,
            message_hash,
            tx_tag,
            k_i: None,
            gamma_i: None,
            big_gamma_i: None,
            x_i: None,
            delta_i: None,
            sigma_i: None,
            r_scalar: None,
            mta_outputs: Vec::new(),
        }
    }
}
