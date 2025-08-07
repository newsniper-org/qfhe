// newsniper-org/qfhe/qfhe-0.0.3-fix/src/ntt/qntt.rs

use crate::core::{Polynomial, Quaternion, QfheParameters};
use super::{Ntt, BarrettReducer64};
use crypto_bigint::{U256, U512, Limb};

use crate::core::num::{SafeModuloArith, concat64x2};

use rayon::prelude::*;

pub struct SplitPolynomial {
    pub c1: Polynomial,
    pub c2: Polynomial,
}

/// Polynomial을 두 개의 복소수 형태 다항식으로 분해합니다.
pub fn split(p: &Polynomial) -> SplitPolynomial {
    let n = p.coeffs.len();
    let rns_basis_size = if n > 0 { p.coeffs[0].w.len() } else { 0 };
    let mut c1 = Polynomial::zero(n, rns_basis_size);
    let mut c2 = Polynomial::zero(n, rns_basis_size);

    for i in 0..n {
        c1.coeffs[i].w = p.coeffs[i].w.clone();
        c1.coeffs[i].x = p.coeffs[i].x.clone();
        c2.coeffs[i].w = p.coeffs[i].y.clone();
        c2.coeffs[i].x = p.coeffs[i].z.clone();
    }
    SplitPolynomial { c1, c2 }
}

/// 분해된 두 다항식을 다시 하나의 쿼터니언 다항식으로 결합합니다.
pub fn merge(sp: &SplitPolynomial) -> Polynomial {
    let n = sp.c1.coeffs.len();
    let rns_basis_size = if n > 0 { sp.c1.coeffs[0].w.len() } else { 0 };
    let mut p = Polynomial::zero(n, rns_basis_size);

    for i in 0..n {
        p.coeffs[i].w = sp.c1.coeffs[i].w.clone();
        p.coeffs[i].x = sp.c1.coeffs[i].x.clone();
        p.coeffs[i].y = sp.c2.coeffs[i].w.clone();
        p.coeffs[i].z = sp.c2.coeffs[i].x.clone();
    }
    p
}

/// QNTT 순방향 변환
pub fn qntt_forward(p: &mut Polynomial, params: &QfheParameters) {
    p.ntt_forward(params);
}

/// QNTT 역방향 변환
pub fn qntt_inverse(p: &mut Polynomial, params: &QfheParameters) {
    p.ntt_inverse(params);
}

/// 변환된 공간에서 RNS 기반 점별 곱셈
pub fn qntt_pointwise_mul(p1: &mut Polynomial, p2: &Polynomial, params: &QfheParameters) {
    let n = params.polynomial_degree;
    let rns_basis_size = params.modulus_q.len();

    // [버그 수정] RNS 기저가 아닌, 다항식의 계수(coefficient)를 병렬로 처리합니다.
    p1.coeffs.par_iter_mut().zip(p2.coeffs.par_iter()).for_each(|(p1_coeff, p2_coeff)| {
        for i in 0..rns_basis_size {
            let q = params.modulus_q[i];
            let reducer = &params.reducers[i];
            
            // c1a, c2a, c1b, c2b (split)
            let c1a_w = p1_coeff.w[i];
            let c1a_x = p1_coeff.x[i];
            let c2a_w = p1_coeff.y[i];
            let c2a_x = p1_coeff.z[i];

            let c1b_w = p2_coeff.w[i];
            let c1b_x = p2_coeff.x[i];
            let c2b_w = p2_coeff.y[i];
            let c2b_x = p2_coeff.z[i];

            // 켤레 복소수 계산
            let c1b_conj_x = q - c1b_x;
            let c2b_conj_x = q - c2b_x;

            // --- ❗❗❗ 핵심 버그 수정: 모든 연산을 안전한 모듈러 연산으로 교체 ❗❗❗ ---
            // term1 = c1a * c1b
            let t1_w_a = reducer.reduce((c1a_w as u128) * (c1b_w as u128));
            let t1_w_b = reducer.reduce((c1a_x as u128) * (c1b_x as u128));
            let term1_w = t1_w_a.safe_sub_mod(t1_w_b, q);
            
            let t1_x_a = reducer.reduce((c1a_w as u128) * (c1b_x as u128));
            let t1_x_b = reducer.reduce((c1a_x as u128) * (c1b_w as u128));
            let term1_x = t1_x_a.safe_add_mod(t1_x_b, q);

            // term2 = c2a * c2b_conj
            let t2_w_a = reducer.reduce((c2a_w as u128) * (c2b_w as u128));
            let t2_w_b = reducer.reduce((c2a_x as u128) * (c2b_conj_x as u128));
            let term2_w = t2_w_a.safe_sub_mod(t2_w_b, q);
            
            let t2_x_a = reducer.reduce((c2a_w as u128) * (c2b_conj_x as u128));
            let t2_x_b = reducer.reduce((c2a_x as u128) * (c2b_w as u128));
            let term2_x = t2_x_a.safe_add_mod(t2_x_b, q);

            let res_c1_w = term1_w.safe_sub_mod(term2_w, q);
            let res_c1_x = term1_x.safe_sub_mod(term2_x, q);
            
            // term3 = c1a * c2b
            let t3_w_a = reducer.reduce((c1a_w as u128) * (c2b_w as u128));
            let t3_w_b = reducer.reduce((c1a_x as u128) * (c2b_x as u128));
            let term3_w = t3_w_a.safe_sub_mod(t3_w_b, q);

            let t3_x_a = reducer.reduce((c1a_w as u128) * (c2b_x as u128));
            let t3_x_b = reducer.reduce((c1a_x as u128) * (c2b_w as u128));
            let term3_x = t3_x_a.safe_add_mod(t3_x_b, q);

            // term4 = c2a * c1b_conj
            let t4_w_a = reducer.reduce((c2a_w as u128) * (c1b_w as u128));
            let t4_w_b = reducer.reduce((c2a_x as u128) * (c1b_conj_x as u128));
            let term4_w = t4_w_a.safe_sub_mod(t4_w_b, q);

            let t4_x_a = reducer.reduce((c2a_w as u128) * (c1b_conj_x as u128));
            let t4_x_b = reducer.reduce((c2a_x as u128) * (c1b_w as u128));
            let term4_x = t4_x_a.safe_add_mod(t4_x_b, q);

            let res_c2_w = term3_w.safe_add_mod(term4_w, q);
            let res_c2_x = term3_x.safe_add_mod(term4_x, q);

            // 결과(merge)를 p1에 다시 저장
            p1_coeff.w[i] = res_c1_w;
            p1_coeff.x[i] = res_c1_x;
            p1_coeff.y[i] = res_c2_w;
            p1_coeff.z[i] = res_c2_x;
        }
    });
}