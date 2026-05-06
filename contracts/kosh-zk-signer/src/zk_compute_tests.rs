use crate::signing_state::ShareMetadata;
use crate::zk_compute::{
    add_mod_n, compute_partial_sig, mul_mod_n, reduce_input_mod_n, reinterpret_public_i128_as_u128,
    u256_from_hi_lo_128, u256_to_hi_lo_128,
};
use k256::elliptic_curve::bigint::U256 as UInt256;
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::ops::Reduce;
use k256::Scalar;
use pbc_zk::api::{set_secrets_of_single_type, SecretVarInput};
use pbc_zk::{FromToBits, Sbi128};

fn decode_hex(hex_str: &str) -> [u8; 32] {
    let cleaned = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    assert!(cleaned.len() <= 64, "expected at most 32-byte hex string");
    let mut padded = [b'0'; 64];
    let offset = 64 - cleaned.len();
    padded[offset..].copy_from_slice(cleaned.as_bytes());
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (hex_nibble(padded[i * 2]) << 4) | hex_nibble(padded[i * 2 + 1]);
    }
    out
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => 10 + (b - b'a'),
        b'A'..=b'F' => 10 + (b - b'A'),
        _ => panic!("invalid hex nibble"),
    }
}

fn scalar_from_hex(hex_str: &str) -> Scalar {
    Scalar::from_repr(decode_hex(hex_str).into()).unwrap()
}

fn scalar_from_bytes_mod_n(bytes: [u8; 32]) -> Scalar {
    let fb: k256::FieldBytes = bytes.into();
    Option::<Scalar>::from(Scalar::from_repr(fb))
        .unwrap_or_else(|| <Scalar as Reduce<UInt256>>::reduce(UInt256::from_be_slice(&bytes)))
}

fn split_scalar_halves(bytes: [u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&bytes[..16]);
    lo.copy_from_slice(&bytes[16..]);
    (hi, lo)
}

fn i128_from_be(bytes: [u8; 16]) -> i128 {
    i128::from_be_bytes(bytes)
}

fn scalar_to_i128_halves(scalar: Scalar) -> (i128, i128) {
    let bytes: [u8; 32] = scalar.to_bytes().into();
    let (hi, lo) = split_scalar_halves(bytes);
    (i128_from_be(hi), i128_from_be(lo))
}

fn scalar_from_i128_halves(hi: i128, lo: i128) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&hi.to_be_bytes());
    bytes[16..].copy_from_slice(&lo.to_be_bytes());
    scalar_from_bytes_mod_n(bytes)
}

fn i128_from_sbi(value: Sbi128) -> i128 {
    i128::from_le_bytes(bits_to_bytes_128(value.to_le_bits()))
}

fn bits_to_bytes_128(bits: [bool; 128]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        let mut byte = 0u8;
        for j in 0..8 {
            byte |= (bits[(i << 3) ^ j] as u8) << j;
        }
        bytes[i] = byte;
    }
    bytes
}

fn set_party_secrets(party_index: u8, share: Scalar, kinv: Scalar) {
    let share_bytes: [u8; 32] = share.to_bytes().into();
    let kinv_bytes: [u8; 32] = kinv.to_bytes().into();
    let (share_hi, share_lo) = split_scalar_halves(share_bytes);
    let (kinv_hi, kinv_lo) = split_scalar_halves(kinv_bytes);

    unsafe {
        set_secrets_of_single_type(vec![
            SecretVarInput {
                value: Sbi128::from(i128_from_be(share_hi)),
                metadata: ShareMetadata {
                    key_id: 1,
                    share_index: party_index,
                    is_high_half: true,
                    variable_type: 0,
                },
            },
            SecretVarInput {
                value: Sbi128::from(i128_from_be(share_lo)),
                metadata: ShareMetadata {
                    key_id: 1,
                    share_index: party_index,
                    is_high_half: false,
                    variable_type: 0,
                },
            },
            SecretVarInput {
                value: Sbi128::from(i128_from_be(kinv_hi)),
                metadata: ShareMetadata {
                    key_id: 1,
                    share_index: party_index,
                    is_high_half: true,
                    variable_type: 2,
                },
            },
            SecretVarInput {
                value: Sbi128::from(i128_from_be(kinv_lo)),
                metadata: ShareMetadata {
                    key_id: 1,
                    share_index: party_index,
                    is_high_half: false,
                    variable_type: 2,
                },
            },
        ]);
    }
}

#[test]
fn add_mod_n_wraps_exactly_at_curve_order() {
    let n_minus_one = scalar_from_hex("0xfffffffffffffffffffffffffffffffeBAAEDCE6AF48A03BBFD25E8CD0364140");
    let one = Scalar::ONE;
    let expected = Scalar::ZERO;
    let lhs = reduce_input_mod_n(u256_from_hi_lo_128(
        reinterpret_public_i128_as_u128(scalar_to_i128_halves(n_minus_one).0),
        reinterpret_public_i128_as_u128(scalar_to_i128_halves(n_minus_one).1),
    ));
    let rhs = reduce_input_mod_n(u256_from_hi_lo_128(
        reinterpret_public_i128_as_u128(scalar_to_i128_halves(one).0),
        reinterpret_public_i128_as_u128(scalar_to_i128_halves(one).1),
    ));
    let got = add_mod_n(lhs, rhs);
    let (hi, lo) = u256_to_hi_lo_128(got);
    assert_eq!(scalar_from_i128_halves(i128_from_sbi(hi), i128_from_sbi(lo)), expected);
}

#[test]
fn mul_mod_n_matches_k256_reference() {
    let lhs = scalar_from_hex("0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
    let rhs = scalar_from_hex("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let expected = lhs * rhs;

    let lhs_u = u256_from_hi_lo_128(
        reinterpret_public_i128_as_u128(scalar_to_i128_halves(lhs).0),
        reinterpret_public_i128_as_u128(scalar_to_i128_halves(lhs).1),
    );
    let rhs_u = u256_from_hi_lo_128(
        reinterpret_public_i128_as_u128(scalar_to_i128_halves(rhs).0),
        reinterpret_public_i128_as_u128(scalar_to_i128_halves(rhs).1),
    );
    let got = mul_mod_n(lhs_u, rhs_u);
    let (hi, lo) = u256_to_hi_lo_128(got);
    assert_eq!(scalar_from_i128_halves(i128_from_sbi(hi), i128_from_sbi(lo)), expected);
}

#[test]
fn compute_partial_sig_matches_k256_reference() {
    let party_index = 2u8;
    let r = scalar_from_hex("0x68a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc9d8ac7fa4155f36caed741bb");
    let hmsg = scalar_from_hex("0xc9b03991a1a3fa025eebe1fe2c9186e0a4d1b275f5eb8369e4f4429416655735");
    let share = scalar_from_hex("0x1dce8ced2fcb5a9b1f3d4c5b6a79887766554433221100ffeeddccbbaa998877");
    let kinv = scalar_from_hex("0x3f8e12b441cc0099aa55de671234abcd90ef1234567890abcdeffedcba987654");

    set_party_secrets(party_index, share, kinv);

    let expected = kinv * (hmsg + (r * share));
    let (r_hi, r_lo) = scalar_to_i128_halves(r);
    let (h_hi, h_lo) = scalar_to_i128_halves(hmsg);
    let (sigma_hi, sigma_lo) = compute_partial_sig(party_index as i128, r_hi, r_lo, h_hi, h_lo);

    let got = scalar_from_i128_halves(i128_from_sbi(sigma_hi), i128_from_sbi(sigma_lo));
    assert_eq!(got, expected);
}

#[test]
fn compute_partial_sig_reduces_message_hash_mod_n() {
    let party_index = 1u8;
    let share = scalar_from_hex("0x2");
    let kinv = scalar_from_hex("0x3");
    let r = scalar_from_hex("0x4");
    let high_hash = scalar_from_bytes_mod_n([0xffu8; 32]);

    set_party_secrets(party_index, share, kinv);

    let expected = kinv * (high_hash + (r * share));
    let (r_hi, r_lo) = scalar_to_i128_halves(r);
    let raw_hash_bytes = [0xffu8; 32];
    let (h_hi, h_lo) = split_scalar_halves(raw_hash_bytes);

    let (sigma_hi, sigma_lo) = compute_partial_sig(
        party_index as i128,
        r_hi,
        r_lo,
        i128_from_be(h_hi),
        i128_from_be(h_lo),
    );

    let got = scalar_from_i128_halves(i128_from_sbi(sigma_hi), i128_from_sbi(sigma_lo));
    assert_eq!(got, expected);
}
