use pbc_zk::*;

#[derive(read_write_state_derive::ReadWriteState, Clone)]
struct ShareMetadata {
    key_id: u32,
    share_index: u8,
    is_high_half: bool,
    variable_type: u8,
}

pub(crate) type U256 = [Sbu64; 4];

pub(crate) fn u256_zero() -> U256 {
    [Sbu64::from(0), Sbu64::from(0), Sbu64::from(0), Sbu64::from(0)]
}

pub(crate) fn secp256k1_order() -> U256 {
    [
        Sbu64::from(0xbfd25e8cd0364141u64),
        Sbu64::from(0xbaaedce6af48a03bu64),
        Sbu64::from(0xfffffffffffffffeu64),
        Sbu64::from(0xffffffffffffffffu64),
    ]
}

pub(crate) fn two_pow_256_mod_n() -> U256 {
    [
        Sbu64::from(0x402da1732fc9bebfu64),
        Sbu64::from(0x4551231950b75fc4u64),
        Sbu64::from(0x1u64),
        Sbu64::from(0x0u64),
    ]
}

pub(crate) fn bool_to_u128(bit: Sbu1) -> Sbu128 {
    if bit {
        Sbu128::from(1)
    } else {
        Sbu128::from(0)
    }
}

pub(crate) fn low_u64_from_u128(value: Sbu128) -> Sbu64 {
    let bits = value.to_le_bits();
    let mut out = [false; 64];
    for i in 0..64 {
        out[i] = bits[i];
    }
    Sbu64::from_le_bits(out)
}

pub(crate) fn high_u64_from_u128(value: Sbu128) -> Sbu64 {
    let bits = value.to_le_bits();
    let mut out = [false; 64];
    for i in 0..64 {
        out[i] = bits[i + 64];
    }
    Sbu64::from_le_bits(out)
}

pub(crate) fn reinterpret_i128_as_u128(value: Sbi128) -> Sbu128 {
    Sbu128::from_le_bits(value.to_le_bits())
}

pub(crate) fn reinterpret_public_i128_as_u128(value: i128) -> Sbu128 {
    reinterpret_i128_as_u128(Sbi128::from(value))
}

pub(crate) fn u256_from_hi_lo_128(hi: Sbu128, lo: Sbu128) -> U256 {
    [
        low_u64_from_u128(lo),
        high_u64_from_u128(lo),
        low_u64_from_u128(hi),
        high_u64_from_u128(hi),
    ]
}

pub(crate) fn u256_to_hi_lo_128(value: U256) -> (Sbi128, Sbi128) {
    let lo_u128 = Sbu128::from(value[0]) | (Sbu128::from(value[1]) << 64);
    let hi_u128 = Sbu128::from(value[2]) | (Sbu128::from(value[3]) << 64);
    (
        Sbi128::from_le_bits(hi_u128.to_le_bits()),
        Sbi128::from_le_bits(lo_u128.to_le_bits()),
    )
}

pub(crate) fn cmp_ge_u256(lhs: U256, rhs: U256) -> Sbu1 {
    let mut gt = false;
    let mut lt = false;
    for i in 0..4 {
        let idx = 3 - i;
        if !gt && !lt {
            if lhs[idx] > rhs[idx] {
                gt = true;
            } else if lhs[idx] < rhs[idx] {
                lt = true;
            }
        }
    }
    gt || !lt
}

pub(crate) fn add_u256_sum(lhs: U256, rhs: U256) -> U256 {
    let mut out = u256_zero();
    let mut carry = false;
    for i in 0..4 {
        let sum = Sbu128::from(lhs[i]) + Sbu128::from(rhs[i]) + bool_to_u128(carry);
        out[i] = low_u64_from_u128(sum);
        carry = high_u64_from_u128(sum) > Sbu64::from(0);
    }
    out
}

pub(crate) fn add_u256_carry(lhs: U256, rhs: U256) -> Sbu1 {
    let mut carry = false;
    for i in 0..4 {
        let sum = Sbu128::from(lhs[i]) + Sbu128::from(rhs[i]) + bool_to_u128(carry);
        carry = high_u64_from_u128(sum) > Sbu64::from(0);
    }
    carry
}

pub(crate) fn sub_u256_diff(lhs: U256, rhs: U256) -> U256 {
    let mut out = u256_zero();
    let mut borrow = false;
    for i in 0..4 {
        let lhs_wide = Sbu128::from(lhs[i]);
        let rhs_wide = Sbu128::from(rhs[i]) + bool_to_u128(borrow);
        let limb_borrow = lhs_wide < rhs_wide;
        let diff = if limb_borrow {
            (lhs_wide + (Sbu128::from(1u128) << 64)) - rhs_wide
        } else {
            lhs_wide - rhs_wide
        };
        out[i] = low_u64_from_u128(diff);
        borrow = limb_borrow;
    }
    out
}

pub(crate) fn reduce_input_mod_n(value: U256) -> U256 {
    let modulus = secp256k1_order();
    if cmp_ge_u256(value, modulus) {
        sub_u256_diff(value, modulus)
    } else {
        value
    }
}

pub(crate) fn add_mod_n(lhs: U256, rhs: U256) -> U256 {
    let modulus = secp256k1_order();
    let correction = two_pow_256_mod_n();
    let lhs_reduced = reduce_input_mod_n(lhs);
    let rhs_reduced = reduce_input_mod_n(rhs);
    let sum = add_u256_sum(lhs_reduced, rhs_reduced);
    let carry = add_u256_carry(lhs_reduced, rhs_reduced);
    if carry {
        add_u256_sum(sum, correction)
    } else if cmp_ge_u256(sum, modulus) {
        sub_u256_diff(sum, modulus)
    } else {
        sum
    }
}

pub(crate) fn bits_le_u256(value: U256) -> [Sbu1; 256] {
    let mut bits = [false; 256];
    for limb_idx in 0..4 {
        let limb_bits = value[limb_idx].to_le_bits();
        for bit_idx in 0..64 {
            bits[limb_idx * 64 + bit_idx] = limb_bits[bit_idx];
        }
    }
    bits
}

pub(crate) fn mul_mod_n(lhs: U256, rhs: U256) -> U256 {
    let mut result = u256_zero();
    let mut acc = reduce_input_mod_n(lhs);
    let rhs_reduced = reduce_input_mod_n(rhs);
    let rhs_bits = bits_le_u256(rhs_reduced);

    for bit in rhs_bits {
        if bit {
            result = add_mod_n(result, acc);
        }
        acc = add_mod_n(acc, acc);
    }

    result
}

pub fn compute_partial_sig(
    party_index: i128,
    r_hi: i128,
    r_lo: i128,
    hmsg_hi: i128,
    hmsg_lo: i128,
) -> (Sbi128, Sbi128) {
    let target: u8 = party_index as u8;

    let mut s_hi = Sbi128::from(0);
    let mut s_lo = Sbi128::from(0);
    let mut kinv_hi = Sbi128::from(0);
    let mut kinv_lo = Sbi128::from(0);

    for var_id in secret_variable_ids() {
        let meta = load_metadata::<ShareMetadata>(var_id);
        if meta.share_index == target {
            if meta.variable_type == 0u8 {
                if meta.is_high_half {
                    s_hi = load_sbi::<Sbi128>(var_id);
                } else {
                    s_lo = load_sbi::<Sbi128>(var_id);
                }
            } else if meta.variable_type == 2u8 {
                if meta.is_high_half {
                    kinv_hi = load_sbi::<Sbi128>(var_id);
                } else {
                    kinv_lo = load_sbi::<Sbi128>(var_id);
                }
            }
        }
    }

    let r = reduce_input_mod_n(u256_from_hi_lo_128(
        reinterpret_public_i128_as_u128(r_hi),
        reinterpret_public_i128_as_u128(r_lo),
    ));
    let hmsg = reduce_input_mod_n(u256_from_hi_lo_128(
        reinterpret_public_i128_as_u128(hmsg_hi),
        reinterpret_public_i128_as_u128(hmsg_lo),
    ));
    let s_share = reduce_input_mod_n(u256_from_hi_lo_128(
        reinterpret_i128_as_u128(s_hi),
        reinterpret_i128_as_u128(s_lo),
    ));
    let k_inv = reduce_input_mod_n(u256_from_hi_lo_128(
        reinterpret_i128_as_u128(kinv_hi),
        reinterpret_i128_as_u128(kinv_lo),
    ));

    let rs = mul_mod_n(r, s_share);
    let inner = add_mod_n(hmsg, rs);
    let sigma = mul_mod_n(k_inv, inner);

    u256_to_hi_lo_128(sigma)
}
