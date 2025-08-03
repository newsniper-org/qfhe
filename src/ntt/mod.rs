use crate::core::{Polynomial, Quaternion, QfheParameters};
use crypto_bigint::{Limb, U128, U256, U512};

use crate::core::wide_arith::WideningArith;
use std::simd::{u64x4, Simd};

use rayon::prelude::*;

pub mod qntt;

// --- 바렛 감산법 및 기본 헬퍼 함수 ---
pub struct BarrettReducer {
    m: u128,
    m_inv: U256,
}

impl BarrettReducer {
    pub fn new(m: u128) -> Self {
        let numerator: U512 = U512::ONE << (128 * 2);
        let m_inv = numerator.div_rem(&crypto_bigint::NonZero::new(U512::from_u128(m)).unwrap()).0.resize();
        Self { m, m_inv }
    }

    #[inline(always)]
    pub fn reduce(&self, x: U256) -> u128 {
        let q: U256 = x.widening_mul(&self.m_inv).resize();
        let r: U256 = x.wrapping_sub(&q.widening_mul(&U256::from_u128(self.m)).resize());
        let mut result = r.as_limbs()[0].0 as u128;
        while result >= self.m { result -= self.m; }
        result
    }

    #[inline(always)]
    pub fn reduce_from_pair(&self, low: u128, high: u128) -> u128 {
        self.reduce(U256::from_words([low as u64, (low >> 64) as u64, high as u64, (high >> 64) as u64]))
    }
}

pub(crate) fn power(mut a: u128, mut b: u128, m: u128) -> u128 {
    let mut res = 1;
    a %= m;
    while b > 0 {
        if b % 2 == 1 { res = (res * a) % m; }
        b >>= 1;
        a = (a * a) % m;
    }
    res
}

pub(crate) fn primitive_root(p: u128) -> u128 {
    // 각 보안 레벨에서 사용하는 NTT 친화 소수(modulus)에 대해
    // 미리 계산된 원시근(primitive root)을 반환합니다.
    match p {
        // L128
        1152921504606846883 => 3,
        // L160, L192
        1180591620717411303423 => 5,
        // L224, L256
        340282366920938463463374607431768211293 => 7,
        _ => panic!("Primitive root for modulus {} is not defined in the LUT.", p),
    }
}

// --- AoS <-> SoA 변환을 위한 구조체 및 함수 ---
struct SoaPolynomial {
    w: Vec<u128>, x: Vec<u128>, y: Vec<u128>, z: Vec<u128>,
}

impl SoaPolynomial {
    fn from_aos(p: &Polynomial) -> Self {
        let n = p.coeffs.len();
        let mut w = Vec::with_capacity(n);
        let mut x = Vec::with_capacity(n);
        let mut y = Vec::with_capacity(n);
        let mut z = Vec::with_capacity(n);
        for coeff in &p.coeffs {
            w.push(coeff.w);
            x.push(coeff.x);
            y.push(coeff.y);
            z.push(coeff.z);
        }
        Self { w, x, y, z }
    }

    fn to_aos(&self, n: usize) -> Polynomial {
        let mut coeffs = Vec::with_capacity(n);
        for i in 0..n {
            coeffs.push(Quaternion {
                w: self.w[i], x: self.x[i], y: self.y[i], z: self.z[i],
            });
        }
        Polynomial { coeffs }
    }
}

// [리팩터링] 회전 인자 LUT를 생성하는 헬퍼 함수
pub(crate) fn create_twiddle_lut(n: usize, w_primitive: u128, reducer: &BarrettReducer) -> Vec<u128> {
    let mut lut: Vec<u128> = Vec::with_capacity(n);
    lut.push(1);
    for i in 1..n {
        let prev = lut[i-1];
        let (low, high) = prev.widening_mul(w_primitive);
        lut.push(reducer.reduce_from_pair(low, high));
    }
    lut
}

// --- 최종 NTT 구현 (Radix-4 + Six-Step + Pre-calculated LUT) ---
pub trait Ntt {
    fn ntt_forward(&self, params: &QfheParameters) -> Self;
    fn ntt_inverse(&self, params: &QfheParameters) -> Self;
}

// Radix-4 나비 연산을 수행하는 내부 함수
fn ntt_cooley_tukey_radix4(data: &mut [u128], n: usize, q: u128, w_primitive: u128, reducer: &BarrettReducer) {
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

    let im_factor = power(w_primitive, (n / 4) as u128, q);

    let mut len = 4;
    while len <= n {
        let w_len = power(w_primitive, (n / len) as u128, q);
        for i in (0..n).step_by(len) {
            let mut w1: u128 = 1;
            for j in 0..(len / 4) {
                let (low2, high2) = w1.widening_mul(w1);
                let w2 = reducer.reduce_from_pair(low2, high2);
                let (low3, high3) = w1.widening_mul(w2);
                let w3 = reducer.reduce_from_pair(low3, high3);

                let idx0 = i + j;
                let idx1 = idx0 + len / 4;
                let idx2 = idx1 + len / 4;
                let idx3 = idx2 + len / 4;

                let u0 = data[idx0];
                let (u1_l, u1_h) = data[idx1].widening_mul(w1);
                let u1 = reducer.reduce_from_pair(u1_l, u1_h);
                let (u2_l, u2_h) = data[idx2].widening_mul(w2);
                let u2 = reducer.reduce_from_pair(u2_l, u2_h);
                let (u3_l, u3_h) = data[idx3].widening_mul(w3);
                let u3 = reducer.reduce_from_pair(u3_l, u3_h);

                let t0 = (u0 + u2) % q;
                let t1 = (u1 + u3) % q;
                let t2 = (u0 + q - u2) % q;
                let t3 = (u1 + q - u3) % q;
                
                let (t3_im_l, t3_im_h) = t3.widening_mul(im_factor);
                let t3_times_im = reducer.reduce_from_pair(t3_im_l, t3_im_h);

                data[idx0] = (t0 + t1) % q;
                data[idx1] = (t2 + q - t3_times_im) % q;
                data[idx2] = (t0 + q - t1) % q;
                data[idx3] = (t2 + t3_times_im) % q;

                let (w1_l, w1_h) = w1.widening_mul(w_len);
                w1 = reducer.reduce_from_pair(w1_l, w1_h);
            }
        }
        len *= 4;
    }
}

impl Ntt for Polynomial {
    fn ntt_forward(&self, params: &QfheParameters) -> Self {
        let n = params.polynomial_degree;
        let q = params.modulus_q;
        let reducer = BarrettReducer::new(q);
        let root = primitive_root(q);
        let w_primitive = power(root, (q - 1) / n as u128, q);

        let mut soa_poly = SoaPolynomial::from_aos(self);

        // rayon::scope를 사용하여 4개의 NTT 연산을 병렬로 실행
        rayon::scope(|s| {
            s.spawn(|_| ntt_cooley_tukey_radix4(&mut soa_poly.w, n, q, w_primitive, &reducer));
            s.spawn(|_| ntt_cooley_tukey_radix4(&mut soa_poly.x, n, q, w_primitive, &reducer));
            s.spawn(|_| ntt_cooley_tukey_radix4(&mut soa_poly.y, n, q, w_primitive, &reducer));
            s.spawn(|_| ntt_cooley_tukey_radix4(&mut soa_poly.z, n, q, w_primitive, &reducer));
        });

        soa_poly.to_aos(n)
    }

    fn ntt_inverse(&self, params: &QfheParameters) -> Self {
        let n = params.polynomial_degree;
        let q = params.modulus_q;
        let reducer = BarrettReducer::new(q);
        let n_inv = power(n as u128, q - 2, q);
        let root = primitive_root(q);
        let w_primitive = power(root, (q - 1) / n as u128, q);
        let w_inv_primitive = power(w_primitive, q - 2, q);

        let mut soa_poly = SoaPolynomial::from_aos(self);

        // 역 NTT 연산도 병렬로 실행
        rayon::scope(|s| {
            s.spawn(|_| ntt_cooley_tukey_radix4(&mut soa_poly.w, n, q, w_inv_primitive, &reducer));
            s.spawn(|_| ntt_cooley_tukey_radix4(&mut soa_poly.x, n, q, w_inv_primitive, &reducer));
            s.spawn(|_| ntt_cooley_tukey_radix4(&mut soa_poly.y, n, q, w_inv_primitive, &reducer));
            s.spawn(|_| ntt_cooley_tukey_radix4(&mut soa_poly.z, n, q, w_inv_primitive, &reducer));
        });
        
        let mut result_poly = soa_poly.to_aos(n);

        // 최종 스케일링 루프를 병렬로 실행
        result_poly.coeffs.par_iter_mut().for_each(|coeff| {
            let (l, h) = coeff.w.widening_mul(n_inv);
            coeff.w = reducer.reduce_from_pair(l, h);
            let (l, h) = coeff.x.widening_mul(n_inv);
            coeff.x = reducer.reduce_from_pair(l, h);
            let (l, h) = coeff.y.widening_mul(n_inv);
            coeff.y = reducer.reduce_from_pair(l, h);
            let (l, h) = coeff.z.widening_mul(n_inv);
            coeff.z = reducer.reduce_from_pair(l, h);
        });
        
        result_poly
    }
}
