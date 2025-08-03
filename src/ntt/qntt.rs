// newsniper-org/qfhe/qfhe-0.0.3-fix/src/ntt/qntt.rs

use crate::core::{Polynomial, Quaternion, QfheParameters};
use super::{Ntt, BarrettReducer};
use crypto_bigint::{U256, U512, Limb};

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

pub fn qntt_pointwise_mul(p1: &SplitPolynomial, p2: &SplitPolynomial, params: &QfheParameters) -> SplitPolynomial {
    let n = p1.c1.coeffs.len();
    let q = params.modulus_q;
    let q_u256: U256 = U256::from_u128(q);
    let q_times_2_u512: U512 = U512::from_u128(q) << 1;
    let mut res_c1 = Polynomial::zero(n);
    let mut res_c2 = Polynomial::zero(n);

    let reducer = BarrettReducer::new(q);

    for i in 0..n {
        let c1a_w = U256::from_u128(p1.c1.coeffs[i].w);
        let c1a_x = U256::from_u128(p1.c1.coeffs[i].x);
        let c2a_w = U256::from_u128(p1.c2.coeffs[i].w);
        let c2a_x = U256::from_u128(p1.c2.coeffs[i].x);

        let c1b_w = U256::from_u128(p2.c1.coeffs[i].w);
        let c1b_x = U256::from_u128(p2.c1.coeffs[i].x);
        let c2b_w = U256::from_u128(p2.c2.coeffs[i].w);
        let c2b_x = U256::from_u128(p2.c2.coeffs[i].x);

        // --- 켤레 복소수 계산 (conjugate) ---
        let c1b_conj_w = c1b_w;
        let c1b_conj_x = q_u256.sub_mod(&c1b_x, &q_u256);
        let c2b_conj_w = c2b_w;
        let c2b_conj_x = q_u256.sub_mod(&c2b_x, &q_u256);

        // --- c1_res = c1a*c1b - c2a*c2b_conj 계산 ---
        // term1 = c1a * c1b
        let t1_w_full = c1a_w.widening_mul(&c1b_w);
        let t1_x_full = c1a_x.widening_mul(&c1b_x);
        let term1_w = reducer.reduce(t1_w_full.wrapping_add(&q_times_2_u512).wrapping_sub(&t1_x_full).resize());
        let term1_x = reducer.reduce(c1a_w.widening_mul(&c1b_x).wrapping_add(&c1a_x.widening_mul(&c1b_w)).resize());

        // term2 = c2a * c2b_conj
        let t2_w_full = c2a_w.widening_mul(&c2b_conj_w);
        let t2_x_full = c2a_x.widening_mul(&c2b_conj_x);
        let term2_w = reducer.reduce(t2_w_full.wrapping_add(&q_times_2_u512).wrapping_sub(&t2_x_full).resize());
        let term2_x = reducer.reduce(c2a_w.widening_mul(&c2b_conj_x).wrapping_add(&c2a_x.widening_mul(&c2b_conj_w)).resize());
        
        res_c1.coeffs[i].w = (term1_w + q - term2_w) % q;
        res_c1.coeffs[i].x = (term1_x + q - term2_x) % q;

        // --- c2_res = c1a*c2b + c2a*c1b_conj 계산 ---
        // term3 = c1a * c2b
        let t3_w_full = c1a_w.widening_mul(&c2b_w);
        let t3_x_full = c1a_x.widening_mul(&c2b_x);
        let term3_w = reducer.reduce(t3_w_full.wrapping_add(&q_times_2_u512).wrapping_sub(&t3_x_full).resize());
        let term3_x = reducer.reduce(c1a_w.widening_mul(&c2b_x).wrapping_add(&c1a_x.widening_mul(&c2b_w)).resize());

        // term4 = c2a * c1b_conj
        let t4_w_full = c2a_w.widening_mul(&c1b_conj_w);
        let t4_x_full = c2a_x.widening_mul(&c1b_conj_x);
        let term4_w = reducer.reduce(t4_w_full.wrapping_add(&q_times_2_u512).wrapping_sub(&t4_x_full).resize());
        let term4_x = reducer.reduce(c2a_w.widening_mul(&c1b_conj_x).wrapping_add(&c2a_x.widening_mul(&c1b_conj_w)).resize());
        
        res_c2.coeffs[i].w = (term3_w + term4_w) % q;
        res_c2.coeffs[i].x = (term3_x + term4_x) % q;
    }
    
    SplitPolynomial { c1: res_c1, c2: res_c2 }
}
