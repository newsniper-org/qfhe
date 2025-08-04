// newsniper-org/qfhe/qfhe-0.0.3-fix/src/ntt/qntt.rs

use crate::core::{Polynomial, Quaternion, QfheParameters};
use super::{Ntt, BarrettReducer64};
use crypto_bigint::{U256, U512, Limb};

use crate::core::num::{SafeModuloArith, concat64x2};

pub struct SplitPolynomial {
    pub c1: Polynomial,
    pub c2: Polynomial,
}

pub fn split(p: &Polynomial) -> SplitPolynomial {
    let n = p.coeffs.len();
    let mut c1_coeffs = Vec::with_capacity(n);
    let mut c2_coeffs = Vec::with_capacity(n);
    for q in &p.coeffs {
        c1_coeffs.push(Quaternion { w: q.w, x: q.x, y: 0, z: 0 });
        c2_coeffs.push(Quaternion { w: q.y, x: q.z, y: 0, z: 0 });
    }
    SplitPolynomial {
        c1: Polynomial { coeffs: c1_coeffs },
        c2: Polynomial { coeffs: c2_coeffs },
    }
}

pub fn merge(sp: &SplitPolynomial) -> Polynomial {
    let n = sp.c1.coeffs.len();
    let mut q_coeffs = Vec::with_capacity(n);
    for i in 0..n {
        q_coeffs.push(Quaternion {
            w: sp.c1.coeffs[i].w, x: sp.c1.coeffs[i].x,
            y: sp.c2.coeffs[i].w, z: sp.c2.coeffs[i].x,
        });
    }
    Polynomial { coeffs: q_coeffs }
}

pub fn qntt_forward(p: &Polynomial, params: &QfheParameters) -> SplitPolynomial {
    let sp = split(p);
    SplitPolynomial {
        c1: sp.c1.ntt_forward(params),
        c2: sp.c2.ntt_forward(params),
    }
}

pub fn qntt_inverse(sp: &SplitPolynomial, params: &QfheParameters) -> Polynomial {
    let inv_sp = SplitPolynomial {
        c1: sp.c1.ntt_inverse(params),
        c2: sp.c2.ntt_inverse(params),
    };
    merge(&inv_sp)
}

pub fn qntt_pointwise_mul(p1: &mut Polynomial, p2: &Polynomial, params: &QfheParameters) {
    let n = params.polynomial_degree;
    let rns_basis_size = params.modulus_q.len();

    // 각 RNS 모듈러스에 대해 병렬로 점별 곱셈 수행
    (0..rns_basis_size).into_par_iter().for_each(|i| {
        let q = params.modulus_q[i];
        let reducer = BarrettReducer64::new(q);
        for j in 0..n {
            // c1a, c2a, c1b, c2b (split)
            let c1a_w = p1.coeffs[j].w[i];
            let c1a_x = p1.coeffs[j].x[i];
            let c2a_w = p1.coeffs[j].y[i];
            let c2a_x = p1.coeffs[j].z[i];

            let c1b_w = p2.coeffs[j].w[i];
            let c1b_x = p2.coeffs[j].x[i];
            let c2b_w = p2.coeffs[j].y[i];
            let c2b_x = p2.coeffs[j].z[i];

            // 켤레 복소수 계산
            let c1b_conj_x = q - c1b_x;
            let c2b_conj_x = q - c2b_x;

            // c1_res = c1a*c1b - c2a*c2b_conj
            let term1_w = reducer.reduce(concat64x2(c1a_w.widening_mul(c1b_w)) + (q as u128) - concat64x2(c1a_x.widening_mul(c1b_x)));
            let term1_x = reducer.reduce(concat64x2(c1a_w.widening_mul(c1b_x)) + (concat64x2(c1a_x.widening_mul(c1b_w))));
            // [버그 수정] c1b -> c2b_conj
            let term2_w = reducer.reduce(concat64x2(c2a_w.widening_mul(c2b_w)) + (q as u128) - concat64x2(c2a_x.widening_mul(c2b_conj_x)));
            let term2_x = reducer.reduce(concat64x2(c2a_w.widening_mul(c2b_conj_x)) + concat64x2(c2a_x.widening_mul(c2b_w)));
            
            let res_c1_w = term1_w.safe_sub_mod(term2_w, q);
            let res_c1_x = term1_x.safe_sub_mod(term2_x, q);
            
            // c2_res = c1a*c2b + c2a*c1b_conj
            let term3_w = reducer.reduce(concat64x2(c1a_w.widening_mul(c2b_w)) + (q as u128) - concat64x2(c1a_x.widening_mul(c2b_x)));
            let term3_x = reducer.reduce(concat64x2(c1a_w.widening_mul(c2b_x)) + concat64x2(c1a_x.widening_mul(c2b_w)));
            // [버그 수정] c1b -> c1b_conj
            let term4_w = reducer.reduce(concat64x2(c2a_w.widening_mul(c1b_w)) + (q as u128) - concat64x2(c2a_x.widening_mul(c1b_conj_x)));
            let term4_x = reducer.reduce(concat64x2(c2a_w.widening_mul(c1b_conj_x)) + concat64x2(c2a_x.widening_mul(c1b_w)));

            let res_c2_w = term3_w.safe_add_mod(term4_w, q);
            let res_c2_x = term3_x.safe_add_mod(term4_x, q);

            // 결과(merge)를 p1에 다시 저장
            p1.coeffs[j].w[i] = res_c1_w;
            p1.coeffs[j].x[i] = res_c1_x;
            p1.coeffs[j].y[i] = res_c2_w;
            p1.coeffs[j].z[i] = res_c2_x;
        }
    });
}