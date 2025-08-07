// newsniper-org/qfhe/qfhe-wip-cpu-simple/src/ntt/mod.rs

use crate::core::{Polynomial, Quaternion, QfheParameters, SafeModuloArith};
use crate::core::wide_arith::WideningArith;
use rayon::prelude::*;

use crate::core::consts::ntt_tables::{n2048, n4096, n8192};

pub mod qntt;
use crate::core::concat64x2;


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

// ntt_cooley_tukey_radix4 함수가 u64 슬라이스를 처리합니다.
fn ntt_cooley_tukey_radix4(data: &mut [u64], n: usize, q: u64, w_primitive: u64, reducer: &BarrettReducer64) {
    let log4_n = n.trailing_zeros() / 2;
    for i in 0..n {
        let mut j = 0;
        let mut t = i;
        for _ in 0..log4_n {
            j = (j << 2) | (t & 3);
            t >>= 2;
        }
        if i < j {
            data.swap(i, j);
        }
    }

    let im_factor = power(w_primitive, (n / 4) as u64, q);

    let mut len = 4;
    while len <= n {
        let w_len = power(w_primitive, (n / len) as u64, q);
        for i in (0..n).step_by(len) {
            let chunk = &mut data[i..i+len];
            let mut w1: u64 = 1;
            for j in 0..(len / 4) {
                let w2 = reducer.reduce((w1 as u128) * (w1 as u128));
                let w3 = reducer.reduce((w1 as u128) * (w2 as u128));

                let idx0 = j;
                let idx1 = idx0 + len / 4;
                let idx2 = idx1 + len / 4;
                let idx3 = idx2 + len / 4;

                let u0 = chunk[idx0];
                let u1 = reducer.reduce((chunk[idx1] as u128) * (w1 as u128));
                let u2 = reducer.reduce((chunk[idx2] as u128) * (w2 as u128));
                let u3 = reducer.reduce((chunk[idx3] as u128) * (w3 as u128));

                // --- ❗❗❗ 핵심 버그 수정: 안전한 모듈러 연산으로 최종 변경 ❗❗❗ ---
                let t0 = u0.safe_add_mod(u2, q);
                let t1 = u1.safe_add_mod(u3, q);
                let t2 = u0.safe_sub_mod(u2, q);
                let t3 = u1.safe_sub_mod(u3, q);
                
                let t3_times_im = t3.safe_mul_mod(im_factor, q);

                chunk[idx0] = t0.safe_add_mod(t1, q);
                chunk[idx1] = t2.safe_sub_mod(t3_times_im, q);
                chunk[idx2] = t0.safe_sub_mod(t1, q);
                chunk[idx3] = t2.safe_add_mod(t3_times_im, q);

                w1 = w1.safe_mul_mod(w_len, q);
            }
        }
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

pub trait Ntt<'a> {
    fn ntt_forward(&mut self, params: &QfheParameters<'a>);
    fn ntt_inverse(&mut self, params: &QfheParameters<'a>);
}

impl<'a> Ntt<'a> for Polynomial {
    fn ntt_forward(&mut self, params: &QfheParameters<'a>) {
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();

        let mut soa_poly = SoaPolynomial::from_aos(self, rns_basis_size);

        let process_plane = |plane: &mut Vec<Vec<u64>>, w_primitives: &[u64]| {
            plane.par_iter_mut().enumerate().for_each(|(i, p)| {
                ntt_cooley_tukey_radix4(p, n, params.modulus_q[i], w_primitives[i], &params.reducers[i]);
            });
        };

        match n {
            2048 => rayon::scope(|s| {
                s.spawn(|_| {
                    process_plane(&mut soa_poly.w, &[n2048::W_PRIMITIVE_0, n2048::W_PRIMITIVE_1]);
                });
                s.spawn(|_| {
                    process_plane(&mut soa_poly.x, &[n2048::W_PRIMITIVE_0, n2048::W_PRIMITIVE_1]);
                });
                s.spawn(|_| {
                    process_plane(&mut soa_poly.y, &[n2048::W_PRIMITIVE_0, n2048::W_PRIMITIVE_1]);
                });
                s.spawn(|_| {
                    process_plane(&mut soa_poly.z, &[n2048::W_PRIMITIVE_0, n2048::W_PRIMITIVE_1]);
                });
            }),
            4096 => {
                s.spawn(|_| {
                    process_plane(&mut soa_poly.w, &[n4096::W_PRIMITIVE_0, n4096::W_PRIMITIVE_1, n4096::W_PRIMITIVE_2, n4096::W_PRIMITIVE_3]);
                });
                s.spawn(|_| {
                    process_plane(&mut soa_poly.x, &[n4096::W_PRIMITIVE_0, n4096::W_PRIMITIVE_1, n4096::W_PRIMITIVE_2, n4096::W_PRIMITIVE_3]);
                });
                s.spawn(|_| {
                    process_plane(&mut soa_poly.y, &[n4096::W_PRIMITIVE_0, n4096::W_PRIMITIVE_1, n4096::W_PRIMITIVE_2, n4096::W_PRIMITIVE_3]);
                });
                s.spawn(|_| {
                    process_plane(&mut soa_poly.z, &[n4096::W_PRIMITIVE_0, n4096::W_PRIMITIVE_1, n4096::W_PRIMITIVE_2, n4096::W_PRIMITIVE_3]);
                });
            },
            8192 => {
                s.spawn(|_| {
                    process_plane(&mut soa_poly.w, &[n8192::W_PRIMITIVE_0, n8192::W_PRIMITIVE_1, n8192::W_PRIMITIVE_2, n8192::W_PRIMITIVE_3, n8192::W_PRIMITIVE_4, n8192::W_PRIMITIVE_5, n8192::W_PRIMITIVE_6, n8192::W_PRIMITIVE_7]);
                });
                s.spawn(|_| {
                    process_plane(&mut soa_poly.x, &[n8192::W_PRIMITIVE_0, n8192::W_PRIMITIVE_1, n8192::W_PRIMITIVE_2, n8192::W_PRIMITIVE_3, n8192::W_PRIMITIVE_4, n8192::W_PRIMITIVE_5, n8192::W_PRIMITIVE_6, n8192::W_PRIMITIVE_7]);
                });
                s.spawn(|_| {
                    process_plane(&mut soa_poly.y, &[n8192::W_PRIMITIVE_0, n8192::W_PRIMITIVE_1, n8192::W_PRIMITIVE_2, n8192::W_PRIMITIVE_3, n8192::W_PRIMITIVE_4, n8192::W_PRIMITIVE_5, n8192::W_PRIMITIVE_6, n8192::W_PRIMITIVE_7]);
                });
                s.spawn(|_| {
                    process_plane(&mut soa_poly.z, &[n8192::W_PRIMITIVE_0, n8192::W_PRIMITIVE_1, n8192::W_PRIMITIVE_2, n8192::W_PRIMITIVE_3, n8192::W_PRIMITIVE_4, n8192::W_PRIMITIVE_5, n8192::W_PRIMITIVE_6, n8192::W_PRIMITIVE_7]);
                });
            },
            _ => unimplemented!("NTT is not supported for polynomial degree: {}", n),
        }

        *self = soa_poly.to_aos(n, rns_basis_size);
    }

    fn ntt_inverse(&mut self, params: &QfheParameters<'a>) {
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();

        let mut soa_poly = SoaPolynomial::from_aos(self, rns_basis_size);

        let process_plane_inv = |plane: &mut Vec<Vec<u64>>, w_inv_primitives: &[u64]| {
            plane.par_iter_mut().enumerate().for_each(|(i, p)| {
                ntt_cooley_tukey_radix4(p, n, params.modulus_q[i], w_inv_primitives[i], &params.reducers[i]);
            });
        };

        match n {
            2048 => rayon::scope(|s| {
                s.spawn(|_| {
                    process_plane_inv(&mut soa_poly.w, &[n2048::W_INV_PRIMITIVE_0, n2048::W_INV_PRIMITIVE_1]);
                });
                s.spawn(|_| {
                    process_plane_inv(&mut soa_poly.x, &[n2048::W_INV_PRIMITIVE_0, n2048::W_INV_PRIMITIVE_1]);
                });
                s.spawn(|_| {
                    process_plane_inv(&mut soa_poly.y, &[n2048::W_INV_PRIMITIVE_0, n2048::W_INV_PRIMITIVE_1]);
                });
                s.spawn(|_| {
                    process_plane_inv(&mut soa_poly.z, &[n2048::W_INV_PRIMITIVE_0, n2048::W_INV_PRIMITIVE_1]);
                });
            }),
            4096 => rayon::scope(|s| {
                s.spawn(|_| {
                    process_plane_inv(&mut soa_poly.w, &[n4096::W_INV_PRIMITIVE_0, n4096::W_INV_PRIMITIVE_1, n4096::W_INV_PRIMITIVE_2, n4096::W_INV_PRIMITIVE_3]);
                });
                s.spawn(|_| {
                    process_plane_inv(&mut soa_poly.x, &[n4096::W_INV_PRIMITIVE_0, n4096::W_INV_PRIMITIVE_1, n4096::W_INV_PRIMITIVE_2, n4096::W_INV_PRIMITIVE_3]);
                });
                s.spawn(|_| {
                    process_plane_inv(&mut soa_poly.y, &[n4096::W_INV_PRIMITIVE_0, n4096::W_INV_PRIMITIVE_1, n4096::W_INV_PRIMITIVE_2, n4096::W_INV_PRIMITIVE_3]);
                });
                s.spawn(|_| {
                    process_plane_inv(&mut soa_poly.z, &[n4096::W_INV_PRIMITIVE_0, n4096::W_INV_PRIMITIVE_1, n4096::W_INV_PRIMITIVE_2, n4096::W_INV_PRIMITIVE_3]);
                });
            }),
            8192 => rayon::scope(|s| {
                s.spawn(|_| {
                    process_plane_inv(&mut soa_poly.w, &[n8192::W_INV_PRIMITIVE_0, n8192::W_INV_PRIMITIVE_1, n8192::W_INV_PRIMITIVE_2, n8192::W_INV_PRIMITIVE_3, n8192::W_INV_PRIMITIVE_4, n8192::W_INV_PRIMITIVE_5, n8192::W_INV_PRIMITIVE_6, n8192::W_INV_PRIMITIVE_7]);
                });
                s.spawn(|_| {
                    process_plane_inv(&mut soa_poly.x, &[n8192::W_INV_PRIMITIVE_0, n8192::W_INV_PRIMITIVE_1, n8192::W_INV_PRIMITIVE_2, n8192::W_INV_PRIMITIVE_3, n8192::W_INV_PRIMITIVE_4, n8192::W_INV_PRIMITIVE_5, n8192::W_INV_PRIMITIVE_6, n8192::W_INV_PRIMITIVE_7]);
                });
                s.spawn(|_| {
                    process_plane_inv(&mut soa_poly.y, &[n8192::W_INV_PRIMITIVE_0, n8192::W_INV_PRIMITIVE_1, n8192::W_INV_PRIMITIVE_2, n8192::W_INV_PRIMITIVE_3, n8192::W_INV_PRIMITIVE_4, n8192::W_INV_PRIMITIVE_5, n8192::W_INV_PRIMITIVE_6, n8192::W_INV_PRIMITIVE_7]);
                });
                s.spawn(|_| {
                    process_plane_inv(&mut soa_poly.z, &[n8192::W_INV_PRIMITIVE_0, n8192::W_INV_PRIMITIVE_1, n8192::W_INV_PRIMITIVE_2, n8192::W_INV_PRIMITIVE_3, n8192::W_INV_PRIMITIVE_4, n8192::W_INV_PRIMITIVE_5, n8192::W_INV_PRIMITIVE_6, n8192::W_INV_PRIMITIVE_7]);
                });
            }),
            _ => unimplemented!("NTT is not supported for polynomial degree: {}", n),
        }
        
        
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

