use ml_dsa::signature::rand_core::{Infallible, TryCryptoRng, TryRng};
use std::io::Read;

// System RNG adapter — wraps /dev/urandom to satisfy rand_core 0.10 TryRng.
// Used only for ML-DSA key generation and ML-KEM operations.
pub struct SystemRng;

impl TryRng for SystemRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        fill(dest);
        Ok(())
    }
}
impl TryCryptoRng for SystemRng {}

pub fn fill(buf: &mut [u8]) {
    std::fs::File::open("/dev/urandom")
        .expect("cannot open /dev/urandom")
        .read_exact(buf)
        .expect("urandom read failed");
}
