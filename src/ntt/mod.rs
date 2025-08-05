// newsniper-org/qfhe/qfhe-wip-cpu-simple/src/ntt/mod.rs

use crate::core::{Polynomial, Quaternion, QfheParameters, SafeModuloArith};

use crate::core::wide_arith::{WideningSimdMul, OverflowingSimdAdd, OverflowingSimdSub};
use rayon::prelude::*;

pub mod qntt;
use crate::core::concat64x2;

pub(crate) mod simd_utils;
pub(crate) use crate::ntt::simd_utils::reduce_simd;

use crate::core::consts::LANES;

use std::simd::{Simd, u64x8, cmp::*};


// [수정] u64 연산을 위한 BarrettReducer
#[derive(Debug, Clone, Copy)]
pub struct BarrettReducer64 {
    m: u64,
    m_inv: u128, // m_inv = floor(2^128 / m)
}

impl BarrettReducer64 {
    pub const fn new(m: u64) -> Self {
        Self {
            m,
            m_inv: Self::get_m_inv(m),
        }
    }

    #[inline(always)]
    const fn get_m_inv(m: u64) -> u128 {
        let max_u128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128;
        let (q, r) = (max_u128 / m as u128, max_u128 % m as u128);
        if (r+1) == (m as u128) {
            q+1
        } else {
            q
        }
    }

    
    // [버그 수정] u128 전체 정밀도로 뺄셈을 수행하도록 수정
    #[inline(always)]
    pub fn reduce(&self, x: u128) -> u64 {
        let q = x.widening_mul(self.m_inv).1; // q는 u128
        let r = x.wrapping_sub(q.wrapping_mul(self.m as u128));
        let mut result = r as u64; // 뺄셈 후에 u64로 변환

        // 근사 오차 보정
        while result >= self.m {
            result -= self.m;
        }
        result
    }
}

pub(crate) fn power(mut a: u64, mut b: u64, m: u64) -> u64 {
    let mut res = 1;
    a %= m;
    while b > 0 {
        if b % 2 == 1 { res = res.safe_mul_mod(a, m); }
        b >>= 1;
        a = a.safe_mul_mod(a, m);
    }
    res
}

// 각 RNS 모듈러스에 대한 원시근(primitive root) LUT
pub(crate) fn primitive_root(p: u64) -> u64 {
    match p {
        1152921504606584833 => 3,
        9223372036854775783 => 5,
        13835058055282163713 => 3,
        18446744073709551557 => 3,
        _ => panic!("Primitive root for modulus {} is not defined in the LUT.", p),
    }
}

/// Radix-4 Cooley-Tukey NTT 알고리즘 [SIMD 최적화]
fn ntt_cooley_tukey_radix4(data: &mut [u64], n: usize, q: u64, w_primitive: u64, reducer: &BarrettReducer64) {
    
    // 1. Bit-reversal (순서 재배치)
    let log4_n = n.trailing_zeros() / 2;
    for i in 0..n {
        let mut j = 0; let mut t = i;
        for _ in 0..log4_n { j = (j << 2) | (t & 3); t >>= 2; }
        if i < j { data.swap(i, j); }
    }

    let im_factor = power(w_primitive, (n / 4) as u64, q);
    let q_simd = u64x8::splat(q);
    let im_factor_simd = u64x8::splat(im_factor);

    // 2. 버터플라이 연산
    let mut len = 4;
    while len <= n {
        let w_len = power(w_primitive, (n / len) as u64, q);
        
        data.par_chunks_mut(len).for_each(|chunk| {
            let mut w1: u64 = 1;
            let group_size = len / 4;

            // --- SIMD 메인 루프 ---
            let main_loop_len = group_size - (group_size % LANES);
            for j in (0..main_loop_len).step_by(LANES) {
                // 8개의 트위들 팩터(w1, w2, w3)를 미리 계산
                let mut w1_arr = [0u64; LANES];
                let mut w2_arr = [0u64; LANES];
                let mut w3_arr = [0u64; LANES];
                let mut current_w1 = w1;
                for i in 0..LANES {
                    let w2 = reducer.reduce(current_w1 as u128 * current_w1 as u128);
                    w1_arr[i] = current_w1;
                    w2_arr[i] = w2;
                    w3_arr[i] = reducer.reduce(current_w1 as u128 * w2 as u128);
                    current_w1 = reducer.reduce(current_w1 as u128 * w_len as u128);
                }
                
                let w1_simd = u64x8::from_array(w1_arr);
                let w2_simd = u64x8::from_array(w2_arr);
                let w3_simd = u64x8::from_array(w3_arr);

                // 8개의 계수 그룹을 SIMD 벡터로 로드
                let u0 = u64x8::from_slice(&chunk[j..j + LANES]);
                let u1 = u64x8::from_slice(&chunk[j + group_size..j + group_size + LANES]);
                let u2 = u64x8::from_slice(&chunk[j + 2 * group_size..j + 2 * group_size + LANES]);
                let u3 = u64x8::from_slice(&chunk[j + 3 * group_size..j + 3 * group_size + LANES]);
                
                // 트위들 팩터 곱셈
                let u1_mul = reduce_simd(u1.widening_mul(w1_simd), reducer);
                let u2_mul = reduce_simd(u2.widening_mul(w2_simd), reducer);
                let u3_mul = reduce_simd(u3.widening_mul(w3_simd), reducer);

                // 버터플라이 연산
                let t0 = (u0 + u2_mul).overflowing_add(q_simd).0 % q_simd;
                let t1 = (u1_mul + u3_mul).overflowing_add(q_simd).0 % q_simd;
                let t2 = (u0 + q_simd - u2_mul).overflowing_add(q_simd).0 % q_simd;
                let t3 = (u1_mul + q_simd - u3_mul).overflowing_add(q_simd).0 % q_simd;

                let t3_times_im = reduce_simd(t3.widening_mul(im_factor_simd), reducer);
                
                // 결과 계산 및 저장
                chunk[j..j + LANES].copy_from_slice(&((t0 + t1) % q_simd).to_array());
                chunk[j + group_size..j + group_size + LANES].copy_from_slice(&((t2 + q_simd - t3_times_im) % q_simd).to_array());
                chunk[j + 2 * group_size..j + 2 * group_size + LANES].copy_from_slice(&((t0 + q_simd - t1) % q_simd).to_array());
                chunk[j + 3 * group_size..j + 3 * group_size + LANES].copy_from_slice(&((t2 + t3_times_im) % q_simd).to_array());

                w1 = current_w1;
            }

            // --- 스칼라 나머지 루프 ---
            for j in main_loop_len..group_size {
                let w2 = reducer.reduce(w1 as u128 * w1 as u128);
                let w3 = reducer.reduce(w1 as u128 * w2 as u128);
                
                let idx0 = j; let idx1 = idx0 + group_size;
                let idx2 = idx1 + group_size; let idx3 = idx2 + group_size;

                let u0 = chunk[idx0];
                let u1_mul = reducer.reduce(chunk[idx1] as u128 * w1 as u128);
                let u2_mul = reducer.reduce(chunk[idx2] as u128 * w2 as u128);
                let u3_mul = reducer.reduce(chunk[idx3] as u128 * w3 as u128);

                let t0 = (u0 + u2_mul) % q; let t1 = (u1_mul + u3_mul) % q;
                let t2 = (u0 + q - u2_mul) % q; let t3 = (u1_mul + q - u3_mul) % q;
                let t3_times_im = reducer.reduce(t3 as u128 * im_factor as u128);

                chunk[idx0] = (t0 + t1) % q;
                chunk[idx1] = (t2 + q - t3_times_im) % q;
                chunk[idx2] = (t0 + q - t1) % q;
                chunk[idx3] = (t2 + t3_times_im) % q;

                w1 = reducer.reduce(w1 as u128 * w_len as u128);
            }
        });
        len *= 4;
    }
}


// --- AoS <-> SoA 변환을 위한 구조체 및 함수 ---
// 이 부분은 RNS NTT 구현 방식 변경으로 인해 qntt.rs로 이동하거나 재설계될 수 있습니다.
// AoS <-> SoA 변환을 위한 구조체 및 함수
struct SoaPolynomial {
    w: Vec<Vec<u64>>,
    x: Vec<Vec<u64>>,
    y: Vec<Vec<u64>>,
    z: Vec<Vec<u64>>,
}

impl SoaPolynomial {
    fn from_aos(p: &Polynomial, rns_basis_size: usize) -> Self {
        let n = p.coeffs.len();
        let mut w = vec![vec![0; n]; rns_basis_size];
        let mut x = vec![vec![0; n]; rns_basis_size];
        let mut y = vec![vec![0; n]; rns_basis_size];
        let mut z = vec![vec![0; n]; rns_basis_size];

        for i in 0..n {
            for j in 0..rns_basis_size {
                w[j][i] = p.coeffs[i].w[j];
                x[j][i] = p.coeffs[i].x[j];
                y[j][i] = p.coeffs[i].y[j];
                z[j][i] = p.coeffs[i].z[j];
            }
        }
        Self { w, x, y, z }
    }

    fn to_aos(&self, n: usize, rns_basis_size: usize) -> Polynomial {
        let mut p = Polynomial::zero(n, rns_basis_size);
        for i in 0..n {
            for j in 0..rns_basis_size {
                p.coeffs[i].w[j] = self.w[j][i];
                p.coeffs[i].x[j] = self.x[j][i];
                p.coeffs[i].y[j] = self.y[j][i];
                p.coeffs[i].z[j] = self.z[j][i];
            }
        }
        p
    }
}

pub trait Ntt<'a, 'b, 'c> {
    fn ntt_forward(&mut self, params: &QfheParameters<'a, 'b, 'c>);
    fn ntt_inverse(&mut self, params: &QfheParameters<'a, 'b, 'c>);
}

impl<'a, 'b, 'c> Ntt<'a, 'b, 'c> for Polynomial {
    fn ntt_forward(&mut self, params: &QfheParameters<'a, 'b, 'c>) {
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();

        let mut soa_poly = SoaPolynomial::from_aos(self, rns_basis_size);

        rayon::scope(|s| {
            s.spawn(|_| {
                soa_poly.w.par_iter_mut().enumerate().for_each(|(i, w_plane)| {
                    let q = params.modulus_q[i];
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    ntt_cooley_tukey_radix4(w_plane, n, q, w_primitive, &params.reducers[i]);
                });
            });
            s.spawn(|_| {
                soa_poly.x.par_iter_mut().enumerate().for_each(|(i, x_plane)| {
                    let q = params.modulus_q[i];
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    ntt_cooley_tukey_radix4(x_plane, n, q, w_primitive, &params.reducers[i]);
                });
            });
            s.spawn(|_| {
                soa_poly.y.par_iter_mut().enumerate().for_each(|(i, y_plane)| {
                    let q = params.modulus_q[i];
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    ntt_cooley_tukey_radix4(y_plane, n, q, w_primitive, &params.reducers[i]);
                });
            });
            s.spawn(|_| {
                soa_poly.z.par_iter_mut().enumerate().for_each(|(i, z_plane)| {
                    let q = params.modulus_q[i];
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    ntt_cooley_tukey_radix4(z_plane, n, q, w_primitive, &params.reducers[i]);
                });
            });
        });

        *self = soa_poly.to_aos(n, rns_basis_size);
    }

    fn ntt_inverse(&mut self, params: &QfheParameters<'a, 'b, 'c>) {
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();

        let mut soa_poly = SoaPolynomial::from_aos(self, rns_basis_size);

        rayon::scope(|s| {
            s.spawn(|_| {
                soa_poly.w.par_iter_mut().enumerate().for_each(|(i, w_plane)| {
                    let q = params.modulus_q[i];
                    let reducer = BarrettReducer64::new(q);
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    let w_inv_primitive = power(w_primitive, q - 2, q);
                    ntt_cooley_tukey_radix4(w_plane, n, q, w_inv_primitive, &reducer);
                });
            });
            s.spawn(|_| {
                soa_poly.x.par_iter_mut().enumerate().for_each(|(i, x_plane)| {
                    let q = params.modulus_q[i];
                    let reducer = BarrettReducer64::new(q);
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    let w_inv_primitive = power(w_primitive, q - 2, q);
                    ntt_cooley_tukey_radix4(x_plane, n, q, w_inv_primitive, &reducer);
                });
            });
            s.spawn(|_| {
                soa_poly.y.par_iter_mut().enumerate().for_each(|(i, y_plane)| {
                    let q = params.modulus_q[i];
                    let reducer = BarrettReducer64::new(q);
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    let w_inv_primitive = power(w_primitive, q - 2, q);
                    ntt_cooley_tukey_radix4(y_plane, n, q, w_inv_primitive, &reducer);
                });
            });
            s.spawn(|_| {
                soa_poly.z.par_iter_mut().enumerate().for_each(|(i, z_plane)| {
                    let q = params.modulus_q[i];
                    let reducer = BarrettReducer64::new(q);
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    let w_inv_primitive = power(w_primitive, q - 2, q);
                    ntt_cooley_tukey_radix4(z_plane, n, q, w_inv_primitive, &reducer);
                });
            });
        });
        
        *self = soa_poly.to_aos(n, rns_basis_size);

        // Final scaling
        self.coeffs.par_iter_mut().for_each(|coeff| {
            for i in 0..rns_basis_size {
                let q = params.modulus_q[i];
                let n_inv = power(n as u64, q - 2, q);
                coeff.w[i] = (coeff.w[i].safe_mul_mod(n_inv, q));
                coeff.x[i] = (coeff.x[i].safe_mul_mod(n_inv, q));
                coeff.y[i] = (coeff.y[i].safe_mul_mod(n_inv, q));
                coeff.z[i] = (coeff.z[i].safe_mul_mod(n_inv, q));
            }
        });
    }
}

