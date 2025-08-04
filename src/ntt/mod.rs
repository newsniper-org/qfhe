// newsniper-org/qfhe/qfhe-wip-cpu-simple/src/ntt/mod.rs

use crate::core::{Polynomial, Quaternion, QfheParameters, widening_mul_mod};
use crate::core::wide_arith::WideningArith;
use rayon::prelude::*;

pub mod qntt;


// [수정] u64 연산을 위한 BarrettReducer
pub struct BarrettReducer64 {
    m: u64,
    m_inv: u128, // m_inv = floor(2^128 / m)
}

impl BarrettReducer64 {
    pub fn new(m: u64) -> Self {
        Self {
            m,
            m_inv: Self::get_m_inv(m),
        }
    }

    #[inline(always)]
    fn get_m_inv(m: u64) -> u128 {
        let max_u128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128;
        let (q, r) = (max_u128 / m as u128, max_u128 % m as u128);
        if (r+1) == m {
            q+1
        } else {
            q
        }
    }

    #[inline(always)]
    pub fn reduce(&self, x: u128) -> u64 {
        let q = x.widening_mul(self.m_inv).1 as u64;
        let r = x as u64 - q.wrapping_mul(self.m);
        if r >= self.m { r - self.m } else { r }
    }
}

pub(crate) fn power(mut a: u64, mut b: u64, m: u64) -> u64 {
    let mut res = 1;
    a %= m;
    while b > 0 {
        if b % 2 == 1 { res = (res as u128 * a as u128 % m as u128) as u64; }
        b >>= 1;
        a = (a as u128 * a as u128 % m as u128) as u64;
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
    // 4진수 자릿수 역순 정렬
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
        data.chunks_mut(len).for_each(|chunk| {
            let mut w1: u64 = 1;
            for j in 0..(len / 4) {
                let w2 = reducer.reduce(w1 as u128 * w1 as u128);
                let w3 = reducer.reduce(w1 as u128 * w2 as u128);

                let idx0 = j;
                let idx1 = idx0 + len / 4;
                let idx2 = idx1 + len / 4;
                let idx3 = idx2 + len / 4;

                let u0 = chunk[idx0];
                let u1 = reducer.reduce(chunk[idx1] as u128 * w1 as u128);
                let u2 = reducer.reduce(chunk[idx2] as u128 * w2 as u128);
                let u3 = reducer.reduce(chunk[idx3] as u128 * w3 as u128);

                let t0 = (u0 + u2) % q;
                let t1 = (u1 + u3) % q;
                let t2 = (u0 + q - u2) % q;
                let t3 = (u1 + q - u3) % q;
                
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

pub trait Ntt {
    fn ntt_forward(&self, params: &QfheParameters) -> Self;
    fn ntt_inverse(&self, params: &QfheParameters) -> Self;
}

impl<'a> Ntt for Polynomial {
    fn ntt_forward(&mut self, params: &QfheParameters<'a>) {
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
                    ntt_cooley_tukey_radix4(w_plane, n, q, w_primitive, &reducer);
                });
            });
            s.spawn(|_| {
                soa_poly.x.par_iter_mut().enumerate().for_each(|(i, x_plane)| {
                    let q = params.modulus_q[i];
                    let reducer = BarrettReducer64::new(q);
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    ntt_cooley_tukey_radix4(x_plane, n, q, w_primitive, &reducer);
                });
            });
            s.spawn(|_| {
                soa_poly.y.par_iter_mut().enumerate().for_each(|(i, y_plane)| {
                    let q = params.modulus_q[i];
                    let reducer = BarrettReducer64::new(q);
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    ntt_cooley_tukey_radix4(y_plane, n, q, w_primitive, &reducer);
                });
            });
            s.spawn(|_| {
                soa_poly.z.par_iter_mut().enumerate().for_each(|(i, z_plane)| {
                    let q = params.modulus_q[i];
                    let reducer = BarrettReducer64::new(q);
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    ntt_cooley_tukey_radix4(z_plane, n, q, w_primitive, &reducer);
                });
            });
        });

        *self = soa_poly.to_aos(n, rns_basis_size);
    }

    fn ntt_inverse(&mut self, params: &QfheParameters<'a>) {
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
                soa_poly.x.par_iter_mut().enumerate().for_each(|(i, x_plane)| {
                    let q = params.modulus_q[i];
                    let reducer = BarrettReducer64::new(q);
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    let w_inv_primitive = power(w_primitive, q - 2, q);
                    ntt_cooley_tukey_radix4(x_plane, n, q, w_inv_primitive, &reducer);
                });
                soa_poly.y.par_iter_mut().enumerate().for_each(|(i, y_plane)| {
                    let q = params.modulus_q[i];
                    let reducer = BarrettReducer64::new(q);
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    let w_inv_primitive = power(w_primitive, q - 2, q);
                    ntt_cooley_tukey_radix4(y_plane, n, q, w_inv_primitive, &reducer);
                });
                soa_poly.z.par_iter_mut().enumerate().for_each(|(i, z_plane)| {
                    let q = params.modulus_q[i];
                    let reducer = BarrettReducer64::new(q);
                    let root = primitive_root(q);
                    let w_primitive = power(root, (q - 1) / n as u64, q);
                    let w_inv_primitive = power(w_primitive, q - 2, q);
                    ntt_cooley_tukey_radix4(z_plane, n, q, w_inv_primitive, &reducer);
                });
            });
            // ... (x, y, z components similarly) ...
        });
        
        *self = soa_poly.to_aos(n, rns_basis_size);

        // Final scaling
        self.coeffs.par_iter_mut().for_each(|coeff| {
            for i in 0..rns_basis_size {
                let q = params.modulus_q[i];
                let n_inv = power(n as u64, q - 2, q);
                coeff.w[i] = (widening_mul_mod(coeff.w[i], n_inv, q));
                coeff.x[i] = (widening_mul_mod(coeff.x[i], n_inv, q));
                coeff.y[i] = (widening_mul_mod(coeff.y[i], n_inv, q));
                coeff.z[i] = (widening_mul_mod(coeff.z[i], n_inv, q));
            }
        });
    }
}

