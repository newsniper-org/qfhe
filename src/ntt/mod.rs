#![allow(dead_code)]

use crate::core::{SimdPolynomial, QfheParameters};
use std::simd::{Simd, u64x4};
use crypto_bigint::{U256, U512, Limb};

pub mod qntt;

// --- SIMD 연산을 위한 준비 ---
const LANES: usize = 4;

#[derive(Copy, Clone)]
struct Simd128x4 {
    lo: u64x4,
    hi: u64x4,
}

// --- 바렛 감산법 구조체 ---
pub struct BarrettReducer {
    m: u128,
    m_inv: U256,
    m_simd: Simd128x4,
}

impl BarrettReducer {
    pub fn new(m: u128) -> Self {
        let numerator: U512 = U512::ONE << (128 * 2);
        let m_inv = numerator.div_rem(&crypto_bigint::NonZero::new(U512::from_u128(m)).unwrap()).0.resize();
        Self {
            m,
            m_inv,
            m_simd: Simd128x4 {
                lo: u64x4::splat(m as u64),
                hi: u64x4::splat((m >> 64) as u64),
            },
        }
    }

    #[inline(always)]
    pub fn reduce(&self, x: U256) -> u128 {
        let q: U256 = x.widening_mul(&self.m_inv).resize();
        let r = x.wrapping_sub(&q.widening_mul(&U256::from_u128(self.m)).resize());
        let mut result = r.as_limbs()[0].0 as u128;
        while result >= self.m { result -= self.m; }
        result
    }
}

// --- 기본 헬퍼 함수 ---
fn power(mut a: u128, mut b: u128, m: u128) -> u128 {
    let mut res = 1;
    a %= m;
    while b > 0 {
        if b % 2 == 1 { res = (res * a) % m; }
        b >>= 1;
        a = (a * a) % m;
    }
    res
}

fn primitive_root(p: u128) -> u128 {
    match p {
        1152921504606846883 => 3,
        1180591620717411303423 => 5,
        340282366920938463463374607431768211293 => 7,
        _ => panic!("Primitive root for modulus {} is not defined in the LUT.", p),
    }
}

fn bit_reverse_permutation_simd(arr: &mut [u128]) {
    let n = arr.len();
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while (j & bit) != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j { arr.swap(i, j); }
    }
}

// --- SIMD 저수준 연산 ---
#[inline(always)]
fn add_mod_simd(a: Simd128x4, b: Simd128x4, m: Simd128x4) -> Simd128x4 {
    let mut res_lo = u64x4::splat(0);
    let mut res_hi = u64x4::splat(0);
    for i in 0..LANES {
        let val_a = (a.hi[i] as u128) << 64 | a.lo[i] as u128;
        let val_b = (b.hi[i] as u128) << 64 | b.lo[i] as u128;
        let m_val = (m.hi[i] as u128) << 64 | m.lo[i] as u128;
        let res = (val_a + val_b) % m_val;
        res_lo[i] = res as u64;
        res_hi[i] = (res >> 64) as u64;
    }
    Simd128x4 { lo: res_lo, hi: res_hi }
}

#[inline(always)]
fn sub_mod_simd(a: Simd128x4, b: Simd128x4, m: Simd128x4) -> Simd128x4 {
    let mut res_lo = u64x4::splat(0);
    let mut res_hi = u64x4::splat(0);
    for i in 0..LANES {
        let val_a = (a.hi[i] as u128) << 64 | a.lo[i] as u128;
        let val_b = (b.hi[i] as u128) << 64 | b.lo[i] as u128;
        let m_val = (m.hi[i] as u128) << 64 | m.lo[i] as u128;
        let res = (val_a + m_val - val_b) % m_val;
        res_lo[i] = res as u64;
        res_hi[i] = (res >> 64) as u64;
    }
    Simd128x4 { lo: res_lo, hi: res_hi }
}

#[inline(always)]
fn mul_mod_simd(a: Simd128x4, b: Simd128x4, reducer: &BarrettReducer) -> Simd128x4 {
    let mut res_lo = u64x4::splat(0);
    let mut res_hi = u64x4::splat(0);
    for i in 0..LANES {
        let val_a = (a.hi[i] as u128) << 64 | a.lo[i] as u128;
        let val_b = (b.hi[i] as u128) << 64 | b.lo[i] as u128;
        let product = U256::from_u128(val_a).widening_mul(&U256::from_u128(val_b));
        let reduced = reducer.reduce(product.resize());
        res_lo[i] = reduced as u64;
        res_hi[i] = (reduced >> 64) as u64;
    }
    Simd128x4 { lo: res_lo, hi: res_hi }
}

#[inline(always)]
fn load_simd128x4(slice: &[u128]) -> Simd128x4 {
    let mut lo = [0u64; LANES];
    let mut hi = [0u64; LANES];
    for i in 0..LANES {
        lo[i] = slice[i] as u64;
        hi[i] = (slice[i] >> 64) as u64;
    }
    Simd128x4 { lo: u64x4::from_array(lo), hi: u64x4::from_array(hi) }
}

#[inline(always)]
fn store_simd128x4(slice: &mut [u128], val: Simd128x4) {
    for i in 0..LANES {
        slice[i] = (val.hi[i] as u128) << 64 | val.lo[i] as u128;
    }
}

// --- NTT 구현 (SIMD 적용 완료) ---
pub trait Ntt {
    fn ntt_forward(&self, params: &QfheParameters) -> Self;
    fn ntt_inverse(&self, params: &QfheParameters) -> Self;
}

impl Ntt for SimdPolynomial {
    fn ntt_forward(&self, params: &QfheParameters) -> Self {
        let n = params.polynomial_degree;
        let q = params.modulus_q;
        let reducer = BarrettReducer::new(q);
        let q_simd = reducer.m_simd;

        let root = primitive_root(q);
        let w_primitive = power(root, (q - 1) / n as u128, q);

        let mut result = self.clone();
        for comp in [&mut result.w, &mut result.x, &mut result.y, &mut result.z] {
            bit_reverse_permutation_simd(comp);
            let mut len = 2;
            while len <= n {
                let w_len = power(w_primitive, (n / len) as u128, q);
                for i in (0..n).step_by(len) {
                    let mut w_j: u128 = 1;
                    // [버그 수정] len/2가 LANES보다 작을 경우 스칼라 연산 수행
                    if len / 2 < LANES {
                        for j in 0..(len / 2) {
                            let u = comp[i + j];
                            let v = reducer.reduce(U256::from_u128(comp[i + j + len / 2]).widening_mul(&U256::from_u128(w_j)).resize());
                            comp[i + j] = (u + v) % q;
                            comp[i + j + len / 2] = (u + q - v) % q;
                            w_j = reducer.reduce(U256::from_u128(w_j).widening_mul(&U256::from_u128(w_len)).resize());
                        }
                    } else { // 데이터가 충분할 때만 SIMD 연산 수행
                        for j in (0..len / 2).step_by(LANES) {
                            let w_j_vec = [
                                w_j, (w_j * w_len) % q,
                                (w_j * w_len % q * w_len) % q,
                                (w_j * w_len % q * w_len % q * w_len) % q,
                            ];
                            let w_simd = load_simd128x4(&w_j_vec);
                            let u = load_simd128x4(&comp[i + j..]);
                            let v_raw = load_simd128x4(&comp[i + j + len / 2..]);
                            let v = mul_mod_simd(v_raw, w_simd, &reducer);
                            let res1 = add_mod_simd(u, v, q_simd);
                            let res2 = sub_mod_simd(u, v, q_simd);
                            store_simd128x4(&mut comp[i + j..], res1);
                            store_simd128x4(&mut comp[i + j + len / 2..], res2);
                            w_j = reducer.reduce(U256::from_u128(w_j).widening_mul(&U256::from_u128(power(w_len, LANES as u128, q))).resize());
                        }
                    }
                }
                len *= 2;
            }
        }
        result
    }

    fn ntt_inverse(&self, params: &QfheParameters) -> Self {
        let n = params.polynomial_degree;
        let q = params.modulus_q;
        let n_inv = power(n as u128, q - 2, q);
        let reducer = BarrettReducer::new(q);
        let q_simd = reducer.m_simd;
        
        let root = primitive_root(q);
        let w_primitive = power(root, (q - 1) / n as u128, q);
        let w_inv_primitive = power(w_primitive, q - 2, q);

        let mut result = self.clone();
        for comp in [&mut result.w, &mut result.x, &mut result.y, &mut result.z] {
            bit_reverse_permutation_simd(comp);
            let mut len = 2;
            while len <= n {
                let w_len = power(w_inv_primitive, (n / len) as u128, q);
                for i in (0..n).step_by(len) {
                    // [버그 수정] ntt_forward와 동일하게 스칼라/SIMD 경로 분리
                    let mut w_j: u128 = 1;
                    if len / 2 < LANES {
                         for j in 0..(len / 2) {
                            let u = comp[i + j];
                            let v = reducer.reduce(U256::from_u128(comp[i + j + len / 2]).widening_mul(&U256::from_u128(w_j)).resize());
                            comp[i + j] = (u + v) % q;
                            comp[i + j + len / 2] = (u + q - v) % q;
                            w_j = reducer.reduce(U256::from_u128(w_j).widening_mul(&U256::from_u128(w_len)).resize());
                        }
                    } else {
                        for j in (0..len / 2).step_by(LANES) {
                            let w_j_vec = [
                                w_j, (w_j * w_len) % q,
                                (w_j * w_len % q * w_len) % q,
                                (w_j * w_len % q * w_len % q * w_len) % q,
                            ];
                            let w_simd = load_simd128x4(&w_j_vec);
                            let u = load_simd128x4(&comp[i + j..]);
                            let v_raw = load_simd128x4(&comp[i + j + len / 2..]);
                            let v = mul_mod_simd(v_raw, w_simd, &reducer);
                            let res1 = add_mod_simd(u, v, q_simd);
                            let res2 = sub_mod_simd(u, v, q_simd);
                            store_simd128x4(&mut comp[i + j..], res1);
                            store_simd128x4(&mut comp[i + j + len / 2..], res2);
                            w_j = reducer.reduce(U256::from_u128(w_j).widening_mul(&U256::from_u128(power(w_len, LANES as u128, q))).resize());
                        }
                    }
                }
                len *= 2;
            }
        }
        
        let n_inv_simd = Simd128x4 { lo: u64x4::splat(n_inv as u64), hi: u64x4::splat((n_inv >> 64) as u64) };
        for comp in [&mut result.w, &mut result.x, &mut result.y, &mut result.z] {
            for chunk in comp.chunks_mut(LANES) {
                if chunk.len() == LANES { // 마지막 청크가 LANES보다 작을 수 있음
                    let val = load_simd128x4(chunk);
                    let scaled_val = mul_mod_simd(val, n_inv_simd, &reducer);
                    store_simd128x4(chunk, scaled_val);
                } else { // 스칼라 처리
                    for val in chunk.iter_mut() {
                        *val = reducer.reduce(U256::from_u128(*val).widening_mul(&U256::from_u128(n_inv)).resize());
                    }
                }
            }
        }
        result
    }
}
