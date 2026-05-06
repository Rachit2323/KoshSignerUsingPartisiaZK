use pbc_zk::*;

struct ShareMetadata {
    key_id: u32,
    share_index: u8,
    is_high_half: bool,
    variable_type: u8,
}

type U256 = [Sbi32; 9];

fn zero_i1() -> Sbi1 {
    let zero = Sbi32::from(0);
    let bits = zero.to_le_bits();
    let bit = bits[0];
    bit
}

fn one_i1() -> Sbi1 {
    let one = Sbi32::from(1);
    let bits = one.to_le_bits();
    let bit = bits[0];
    bit
}

fn zero31() -> Sbi32 {
    Sbi32::from(0)
}

fn zero64() -> Sbi64 {
    Sbi64::from(0)
}

fn one64() -> Sbi64 {
    Sbi64::from(1)
}

fn base31() -> Sbi64 {
    Sbi64::from(2147483648i64)
}

fn order_n() -> U256 {
    [
        Sbi32::from(1345732929i32),
        Sbi32::from(2141502745i32),
        Sbi32::from(1025671406i32),
        Sbi32::from(1433855797i32),
        Sbi32::from(2147483627i32),
        Sbi32::from(2147483647i32),
        Sbi32::from(2147483647i32),
        Sbi32::from(2147483647i32),
        Sbi32::from(255i32),
    ]
}

fn two_pow_256_mod_n() -> U256 {
    [
        Sbi32::from(801750719i32),
        Sbi32::from(5980902i32),
        Sbi32::from(1121812241i32),
        Sbi32::from(713627850i32),
        Sbi32::from(20i32),
        Sbi32::from(0i32),
        Sbi32::from(0i32),
        Sbi32::from(0i32),
        Sbi32::from(0i32),
    ]
}

fn sbi32_from_31_bits(bits: [Sbi1; 31]) -> Sbi32 {
    let mut wide = [zero_i1(); 32];
    for i in 0u32..31u32 {
        wide[i as usize] = bits[i as usize];
    }
    let out = Sbi32::from_le_bits(wide);
    out
}

fn low31_from_sbi64(value: Sbi64) -> Sbi32 {
    let bits = value.to_le_bits();
    let mut out = [zero_i1(); 31];
    for i in 0u32..31u32 {
        out[i as usize] = bits[i as usize];
    }
    let reduced = sbi32_from_31_bits(out);
    reduced
}

fn carry31_from_sbi64(value: Sbi64) -> Sbi64 {
    let bits = value.to_le_bits();
    let mut carry = zero_i1();
    for i in 31u32..64u32 {
        if bits[i as usize] {
            carry = one_i1();
        }
    }
    let mut out = zero64();
    if carry {
        out = one64();
    }
    out
}

fn load_31_bits_from_128(bits: [Sbi1; 128], start: u32, len: u32) -> [Sbi1; 31] {
    let mut out = [zero_i1(); 31];
    for i in 0u32..31u32 {
        if i < len {
            out[i as usize] = bits[(start + i) as usize];
        }
    }
    out
}

fn u256_from_hi_lo_128(hi: Sbi128, lo: Sbi128) -> U256 {
    let hi_bits = hi.to_le_bits();
    let lo_bits = lo.to_le_bits();
    let lo0_bits = load_31_bits_from_128(lo_bits, 0u32, 31u32);
    let lo1_bits = load_31_bits_from_128(lo_bits, 31u32, 31u32);
    let lo2_bits = load_31_bits_from_128(lo_bits, 62u32, 31u32);
    let lo3_bits = load_31_bits_from_128(lo_bits, 93u32, 31u32);
    let hi0_bits = load_31_bits_from_128(hi_bits, 0u32, 31u32);
    let hi1_bits = load_31_bits_from_128(hi_bits, 31u32, 31u32);
    let hi2_bits = load_31_bits_from_128(hi_bits, 62u32, 31u32);
    let hi3_bits = load_31_bits_from_128(hi_bits, 93u32, 31u32);
    let hi4_bits = load_31_bits_from_128(hi_bits, 124u32, 4u32);

    let mut out = [zero31(); 9];
    out[0] = sbi32_from_31_bits(lo0_bits);
    out[1] = sbi32_from_31_bits(lo1_bits);
    out[2] = sbi32_from_31_bits(lo2_bits);
    out[3] = sbi32_from_31_bits(lo3_bits);
    out[4] = sbi32_from_31_bits(hi0_bits);
    out[5] = sbi32_from_31_bits(hi1_bits);
    out[6] = sbi32_from_31_bits(hi2_bits);
    out[7] = sbi32_from_31_bits(hi3_bits);
    out[8] = sbi32_from_31_bits(hi4_bits);
    out
}

fn limb31_bits(value: Sbi32) -> [Sbi1; 31] {
    let bits = value.to_le_bits();
    let mut out = [zero_i1(); 31];
    for i in 0u32..31u32 {
        out[i as usize] = bits[i as usize];
    }
    out
}

fn cmp_ge_u256(lhs: U256, rhs: U256) -> Sbi1 {
    let mut gt = zero_i1();
    let mut lt = zero_i1();
    for i in 0u32..9u32 {
        let idx = (8u32 - i) as usize;
        if !gt && !lt {
            if lhs[idx] > rhs[idx] {
                gt = one_i1();
            } else if lhs[idx] < rhs[idx] {
                lt = one_i1();
            }
        }
    }
    let ge = gt || !lt;
    ge
}

fn widen_sbi32(value: Sbi32) -> Sbi64 {
    let bits = value.to_le_bits();
    let mut wide = [zero_i1(); 64];
    for i in 0u32..32u32 {
        wide[i as usize] = bits[i as usize];
    }
    let wide_value = Sbi64::from_le_bits(wide);
    wide_value
}

fn add_u256_sum(lhs: U256, rhs: U256) -> U256 {
    let mut out = [zero31(); 9];
    let mut carry = zero64();
    for i in 0u32..9u32 {
        let idx = i as usize;
        let lhs_wide = widen_sbi32(lhs[idx]);
        let rhs_wide = widen_sbi32(rhs[idx]);
        let partial = lhs_wide + rhs_wide;
        let sum = partial + carry;
        let reduced = low31_from_sbi64(sum);
        let next_carry = carry31_from_sbi64(sum);
        out[idx] = reduced;
        carry = next_carry;
    }
    out
}

fn add_u256_carry(lhs: U256, rhs: U256) -> Sbi1 {
    let mut carry = zero64();
    for i in 0u32..9u32 {
        let idx = i as usize;
        let lhs_wide = widen_sbi32(lhs[idx]);
        let rhs_wide = widen_sbi32(rhs[idx]);
        let partial = lhs_wide + rhs_wide;
        let sum = partial + carry;
        let next_carry = carry31_from_sbi64(sum);
        carry = next_carry;
    }
    let overflow = carry > zero64();
    overflow
}

fn sub_u256_diff(lhs: U256, rhs: U256) -> U256 {
    let mut out = [zero31(); 9];
    let mut borrow = zero_i1();
    for i in 0u32..9u32 {
        let idx = i as usize;
        let lhs_wide = widen_sbi32(lhs[idx]);
        let mut rhs_wide = widen_sbi32(rhs[idx]);
        if borrow {
            rhs_wide = rhs_wide + one64();
        }
        let limb_borrow = lhs_wide < rhs_wide;
        let mut diff = lhs_wide - rhs_wide;
        if limb_borrow {
            diff = lhs_wide + base31() - rhs_wide;
        }
        let reduced = low31_from_sbi64(diff);
        out[idx] = reduced;
        borrow = limb_borrow;
    }
    out
}

fn reduce_input_mod_n(value: U256) -> U256 {
    let modulus = order_n();
    let reduced = sub_u256_diff(value, modulus);
    let ge = cmp_ge_u256(value, modulus);
    let mut out = value;
    for i in 0u32..9u32 {
        let idx = i as usize;
        if ge {
            out[idx] = reduced[idx];
        }
    }
    out
}

fn add_mod_n(lhs: U256, rhs: U256) -> U256 {
    let modulus = order_n();
    let correction = two_pow_256_mod_n();
    let lhs_reduced = reduce_input_mod_n(lhs);
    let rhs_reduced = reduce_input_mod_n(rhs);
    let sum = add_u256_sum(lhs_reduced, rhs_reduced);
    let carry = add_u256_carry(lhs_reduced, rhs_reduced);
    let corrected = add_u256_sum(sum, correction);
    let reduced = sub_u256_diff(sum, modulus);
    let ge = cmp_ge_u256(sum, modulus);

    let mut out = sum;
    for i in 0u32..9u32 {
        let idx = i as usize;
        if ge {
            out[idx] = reduced[idx];
        }
        if carry {
            out[idx] = corrected[idx];
        }
    }
    out
}

fn bits_le_u256(value: U256) -> [Sbi1; 279] {
    let mut bits = [zero_i1(); 279];
    for limb_idx in 0u32..8u32 {
        let limb_bits = limb31_bits(value[limb_idx as usize]);
        for bit_idx in 0u32..31u32 {
            bits[(limb_idx * 31u32 + bit_idx) as usize] = limb_bits[bit_idx as usize];
        }
    }
    let last_bits = limb31_bits(value[8]);
    for bit_idx in 0u32..4u32 {
        bits[(248u32 + bit_idx) as usize] = last_bits[bit_idx as usize];
    }
    bits
}

fn mul_mod_n(lhs: U256, rhs: U256) -> U256 {
    let mut result = [zero31(); 9];
    let mut acc = reduce_input_mod_n(lhs);
    let rhs_reduced = reduce_input_mod_n(rhs);
    let rhs_bits = bits_le_u256(rhs_reduced);
    for bit_idx in 0u32..279u32 {
        if rhs_bits[bit_idx as usize] {
            result = add_mod_n(result, acc);
        }
        acc = add_mod_n(acc, acc);
    }
    result
}

#[zk_compute(shortname = 0x61)]
pub fn compute_partial_sig(
    party_index: i128,
    r_hi: i128,
    r_lo: i128,
    hmsg_hi: i128,
    hmsg_lo: i128,
) -> (Sbi128, Sbi128) {
    let target = party_index as u8;

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

    let r_hi_sbi = Sbi128::from(r_hi);
    let r_lo_sbi = Sbi128::from(r_lo);
    let r_u256 = u256_from_hi_lo_128(r_hi_sbi, r_lo_sbi);
    let r = reduce_input_mod_n(r_u256);

    let hmsg_hi_sbi = Sbi128::from(hmsg_hi);
    let hmsg_lo_sbi = Sbi128::from(hmsg_lo);
    let hmsg_u256 = u256_from_hi_lo_128(hmsg_hi_sbi, hmsg_lo_sbi);
    let hmsg = reduce_input_mod_n(hmsg_u256);

    let s_share_u256 = u256_from_hi_lo_128(s_hi, s_lo);
    let s_share = reduce_input_mod_n(s_share_u256);

    let k_inv_u256 = u256_from_hi_lo_128(kinv_hi, kinv_lo);
    let k_inv = reduce_input_mod_n(k_inv_u256);

    let rs = mul_mod_n(r, s_share);
    let inner = add_mod_n(hmsg, rs);
    let sigma = mul_mod_n(k_inv, inner);

    let mut lo_bits = [zero_i1(); 128];
    let mut hi_bits = [zero_i1(); 128];
    let sigma0_bits = limb31_bits(sigma[0]);
    let sigma1_bits = limb31_bits(sigma[1]);
    let sigma2_bits = limb31_bits(sigma[2]);
    let sigma3_bits = limb31_bits(sigma[3]);
    let sigma4_bits = limb31_bits(sigma[4]);
    let sigma5_bits = limb31_bits(sigma[5]);
    let sigma6_bits = limb31_bits(sigma[6]);
    let sigma7_bits = limb31_bits(sigma[7]);
    let sigma8_bits = limb31_bits(sigma[8]);

    for i in 0u32..31u32 {
        lo_bits[i as usize] = sigma0_bits[i as usize];
        lo_bits[(31u32 + i) as usize] = sigma1_bits[i as usize];
        lo_bits[(62u32 + i) as usize] = sigma2_bits[i as usize];
        lo_bits[(93u32 + i) as usize] = sigma3_bits[i as usize];
        hi_bits[i as usize] = sigma4_bits[i as usize];
        hi_bits[(31u32 + i) as usize] = sigma5_bits[i as usize];
        hi_bits[(62u32 + i) as usize] = sigma6_bits[i as usize];
        hi_bits[(93u32 + i) as usize] = sigma7_bits[i as usize];
        if i < 4u32 {
            hi_bits[(124u32 + i) as usize] = sigma8_bits[i as usize];
        }
    }

    let hi_out = Sbi128::from_le_bits(hi_bits);
    let lo_out = Sbi128::from_le_bits(lo_bits);
    (hi_out, lo_out)
}
