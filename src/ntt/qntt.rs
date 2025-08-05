// newsniper-org/qfhe/qfhe-0.0.3-fix/src/ntt/qntt.rs

use crate::core::{Polynomial, Quaternion, QfheParameters};
use super::{Ntt, BarrettReducer64};
use crypto_bigint::{U256, U512, Limb};

use crate::core::num::{SafeModuloArith, concat64x2};

use crate::core::consts::LANES;

use crate::core::wide_arith::{WideningSimdMul, OverflowingSimdAdd, OverflowingSimdSub};

use super::simd_utils::{reduce_simd, element_wise_add};

// SIMD 연산을 위해 추가
use std::simd::{Simd, u64x8};

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



/// 변환된 공간에서 RNS 기반 점별 곱셈 [SIMD 최적화]
pub fn qntt_pointwise_mul(p1: &mut Polynomial, p2: &Polynomial, params: &QfheParameters) {
    // AVX512를 가정하여 8개의 u64를 한 번에 처리
    const LANES: usize = 8;

    // 다항식 계수들을 LANES 크기의 청크로 나누어 병렬 처리
    p1.coeffs.par_chunks_mut(LANES).zip(p2.coeffs.par_chunks(LANES)).for_each(|(p1_chunk, p2_chunk)| {
        if p1_chunk.len() != LANES {
            // 마지막 청크가 LANES보다 작을 경우 스칼라 연산으로 처리 (또는 패딩)
            // 여기서는 간단하게 스칼라 처리
            for i in 0..p1_chunk.len() {
                let p1_coeff = &mut p1_chunk[i];
                let p2_coeff = &p2_chunk[i];
                for j in 0..params.modulus_q.len() {
                    let q = params.modulus_q[j];
                    let reducer = &params.reducers[j];
                    // 기존 스칼라 로직...
                    let c1a_w = p1_coeff.w[j]; let c1a_x = p1_coeff.x[j];
                    let c2a_w = p1_coeff.y[j]; let c2a_x = p1_coeff.z[j];
                    let c1b_w = p2_coeff.w[j]; let c1b_x = p2_coeff.x[j];
                    let c2b_w = p2_coeff.y[j]; let c2b_x = p2_coeff.z[j];
                    let c1b_conj_x = q - c1b_x; let c2b_conj_x = q - c2b_x;
                    let t1_w_a = reducer.reduce(concat64x2(c1a_w.widening_mul(c1b_w)));
                    let t1_w_b = reducer.reduce(concat64x2(c1a_x.widening_mul(c1b_x)));
                    let term1_w = (t1_w_a + q - t1_w_b) % q;
                    let term1_x = reducer.reduce(concat64x2(c1a_w.widening_mul(c1b_x)) + concat64x2(c1a_x.widening_mul(c1b_w)));
                    let t2_w_a = reducer.reduce(concat64x2(c2a_w.widening_mul(c2b_w)));
                    let t2_w_b = reducer.reduce(concat64x2(c2a_x.widening_mul(c2b_conj_x)));
                    let term2_w = (t2_w_a + q - t2_w_b) % q;
                    let term2_x = reducer.reduce(concat64x2(c2a_w.widening_mul(c2b_conj_x)) + concat64x2(c2a_x.widening_mul(c2b_w)));
                    p1_coeff.w[j] = term1_w.safe_sub_mod(term2_w, q);
                    p1_coeff.x[j] = term1_x.safe_sub_mod(term2_x, q);
                    let t3_w_a = reducer.reduce(concat64x2(c1a_w.widening_mul(c2b_w)));
                    let t3_w_b = reducer.reduce(concat64x2(c1a_x.widening_mul(c2b_x)));
                    let term3_w = (t3_w_a + q - t3_w_b) % q;
                    let term3_x = reducer.reduce(concat64x2(c1a_w.widening_mul(c2b_x)) + concat64x2(c1a_x.widening_mul(c2b_w)));
                    let t4_w_a = reducer.reduce(concat64x2(c2a_w.widening_mul(c1b_w)));
                    let t4_w_b = reducer.reduce(concat64x2(c2a_x.widening_mul(c1b_conj_x)));
                    let term4_w = (t4_w_a + q - t4_w_b) % q;
                    let term4_x = reducer.reduce(concat64x2(c2a_w.widening_mul(c1b_conj_x)) + concat64x2(c2a_x.widening_mul(c1b_w)));
                    p1_coeff.y[j] = term3_w.safe_add_mod(term4_w, q);
                    p1_coeff.z[j] = term3_x.safe_add_mod(term4_x, q);
                }
            }
            return;
        }

        // 각 RNS 기저에 대해 연산
        for j in 0..params.modulus_q.len() {
            let q = params.modulus_q[j];
            let q_simd = u64x8::splat(q);
            let reducer = &params.reducers[j];

            // 1. 데이터 로드 (AoS -> SoA)
            let mut c1a_w = [0; LANES]; let mut c1a_x = [0; LANES];
            let mut c2a_w = [0; LANES]; let mut c2a_x = [0; LANES];
            let mut c1b_w = [0; LANES]; let mut c1b_x = [0; LANES];
            let mut c2b_w = [0; LANES]; let mut c2b_x = [0; LANES];

            for i in 0..LANES {
                c1a_w[i] = p1_chunk[i].w[j]; c1a_x[i] = p1_chunk[i].x[j];
                c2a_w[i] = p1_chunk[i].y[j]; c2a_x[i] = p1_chunk[i].z[j];
                c1b_w[i] = p2_chunk[i].w[j]; c1b_x[i] = p2_chunk[i].x[j];
                c2b_w[i] = p2_chunk[i].y[j]; c2b_x[i] = p2_chunk[i].z[j];
            }

            let c1a_w = u64x8::from_array(c1a_w); let c1a_x = u64x8::from_array(c1a_x);
            let c2a_w = u64x8::from_array(c2a_w); let c2a_x = u64x8::from_array(c2a_x);
            let c1b_w = u64x8::from_array(c1b_w); let c1b_x = u64x8::from_array(c1b_x);
            let c2b_w = u64x8::from_array(c2b_w); let c2b_x = u64x8::from_array(c2b_x);
            
            // 2. SIMD 연산
            let c1b_conj_x = q_simd - c1b_x;
            let c2b_conj_x = q_simd - c2b_x;

            // term1 = c1a * c1b
            let t1_w_a = reduce_simd(c1a_w.widening_mul(c1b_w), reducer);
            let t1_w_b = reduce_simd(c1a_x.widening_mul(c1b_x), reducer);
            let term1_w = (t1_w_a + q_simd - t1_w_b) % q_simd;
            let term1_x = reduce_simd(element_wise_add(c1a_w.widening_mul(c1b_x), c1a_x.widening_mul(c1b_w)), reducer);

            // term2 = c2a * c2b_conj
            let t2_w_a = reduce_simd(c2a_w.widening_mul(c2b_w), reducer);
            let t2_w_b = reduce_simd(c2a_x.widening_mul(c2b_conj_x), reducer);
            let term2_w = (t2_w_a + q_simd - t2_w_b) % q_simd;
            let term2_x = reduce_simd(element_wise_add(c2a_w.widening_mul(c2b_conj_x), c2a_x.widening_mul(c2b_w)), reducer);

            let res_c1_w = (term1_w + q_simd - term2_w) % q_simd;
            let res_c1_x = (term1_x + q_simd - term2_x) % q_simd;
            
            // term3 = c1a * c2b
            let t3_w_a = reduce_simd(c1a_w.widening_mul(c2b_w), reducer);
            let t3_w_b = reduce_simd(c1a_x.widening_mul(c2b_x), reducer);
            let term3_w = (t3_w_a + q_simd - t3_w_b) % q_simd;
            let term3_x = reduce_simd(element_wise_add(c1a_w.widening_mul(c2b_x), c1a_x.widening_mul(c2b_w)),reducer);
            
            // term4 = c2a * c1b_conj
            let t4_w_a = reduce_simd(c2a_w.widening_mul(c1b_w), reducer);
            let t4_w_b = reduce_simd(c2a_x.widening_mul(c1b_conj_x), reducer);
            let term4_w = (t4_w_a + q_simd - t4_w_b) % q_simd;
            let term4_x = reduce_simd(element_wise_add(c2a_w.widening_mul(c1b_conj_x), c2a_x.widening_mul(c1b_w)), reducer);

            let res_c2_w = (term3_w + term4_w) % q_simd;
            let res_c2_x = (term3_x + term4_x) % q_simd;
            
            // 3. 결과 저장 (SoA -> AoS)
            for i in 0..LANES {
                p1_chunk[i].w[j] = res_c1_w[i];
                p1_chunk[i].x[j] = res_c1_x[i];
                p1_chunk[i].y[j] = res_c2_w[i];
                p1_chunk[i].z[j] = res_c2_x[i];
            }
        }
    });
}