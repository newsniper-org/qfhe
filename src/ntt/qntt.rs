use crate::core::{SimdPolynomial, QfheParameters};
use super::{Ntt, BarrettReducer};
use crypto_bigint::{U256, U512, Limb};

pub struct SplitSimdPolynomial {
    pub c1: SimdPolynomial,
    pub c2: SimdPolynomial,
}

pub fn split(p: &SimdPolynomial) -> SplitSimdPolynomial {
    let n = p.w.len();
    let c1 = SimdPolynomial {
        w: p.w.clone(), x: p.x.clone(),
        y: vec![0; n], z: vec![0; n],
    };
    let c2 = SimdPolynomial {
        w: p.y.clone(), x: p.z.clone(),
        y: vec![0; n], z: vec![0; n],
    };
    SplitSimdPolynomial { c1, c2 }
}

pub fn merge(sp: &SplitSimdPolynomial) -> SimdPolynomial {
    SimdPolynomial {
        w: sp.c1.w.clone(), x: sp.c1.x.clone(),
        y: sp.c2.w.clone(), z: sp.c2.x.clone(),
    }
}

pub fn qntt_forward(p: &SimdPolynomial, params: &QfheParameters) -> SplitSimdPolynomial {
    let sp = split(p);
    SplitSimdPolynomial {
        c1: sp.c1.ntt_forward(params),
        c2: sp.c2.ntt_forward(params),
    }
}

pub fn qntt_inverse(sp: &SplitSimdPolynomial, params: &QfheParameters) -> SimdPolynomial {
    let inv_sp = SplitSimdPolynomial {
        c1: sp.c1.ntt_inverse(params),
        c2: sp.c2.ntt_inverse(params),
    };
    merge(&inv_sp)
}

pub fn qntt_pointwise_mul(p1: &SplitSimdPolynomial, p2: &SplitSimdPolynomial, params: &QfheParameters) -> SplitSimdPolynomial {
    let n = p1.c1.w.len();
    let q = params.modulus_q;
    let q_u256 = U256::from_u128(q);
    let q_times_2_u512: U512 = (U512::from_u128(q) << 1);
    let mut res_c1 = SimdPolynomial::zero(n);
    let mut res_c2 = SimdPolynomial::zero(n);
    let reducer = BarrettReducer::new(q);

    for i in 0..n {
        let c1a_w = U256::from_u128(p1.c1.w[i]);
        let c1a_x = U256::from_u128(p1.c1.x[i]);
        let c2a_w = U256::from_u128(p1.c2.w[i]);
        let c2a_x = U256::from_u128(p1.c2.x[i]);
        let c1b_w = U256::from_u128(p2.c1.w[i]);
        let c1b_x = U256::from_u128(p2.c1.x[i]);
        let c2b_w = U256::from_u128(p2.c2.w[i]);
        let c2b_x = U256::from_u128(p2.c2.x[i]);

        let c1b_conj_x = q_u256.sub_mod(&c1b_x, &q_u256);
        let c2b_conj_x = q_u256.sub_mod(&c2b_x, &q_u256);

        let t1w = c1a_w.widening_mul(&c1b_w);
        let t1x = c1a_x.widening_mul(&c1b_x);
        let r1w = reducer.reduce(t1w.wrapping_add(&q_times_2_u512).wrapping_sub(&t1x).resize());
        let r1x = reducer.reduce(c1a_w.widening_mul(&c1b_x).wrapping_add(&c1a_x.widening_mul(&c1b_w)).resize());
        
        let t2w = c2a_w.widening_mul(&c1b_w);
        let t2x = c2a_x.widening_mul(&c1b_conj_x);
        let r2w = reducer.reduce(t2w.wrapping_add(&q_times_2_u512).wrapping_sub(&t2x).resize());
        let r2x = reducer.reduce(c2a_w.widening_mul(&c1b_conj_x).wrapping_add(&c2a_x.widening_mul(&c1b_w)).resize());
        
        res_c1.w[i] = (r1w + q - r2w) % q;
        res_c1.x[i] = (r1x + q - r2x) % q;

        let t3w = c1a_w.widening_mul(&c2b_w);
        let t3x = c1a_x.widening_mul(&c2b_x);
        let r3w = reducer.reduce(t3w.wrapping_add(&q_times_2_u512).wrapping_sub(&t3x).resize());
        let r3x = reducer.reduce(c1a_w.widening_mul(&c2b_x).wrapping_add(&c1a_x.widening_mul(&c2b_w)).resize());

        let t4w = c2a_w.widening_mul(&c1b_w);
        let t4x = c2a_x.widening_mul(&c1b_conj_x);
        let r4w = reducer.reduce(t4w.wrapping_add(&q_times_2_u512).wrapping_sub(&t4x).resize());
        let r4x = reducer.reduce(c2a_w.widening_mul(&c1b_conj_x).wrapping_add(&c2a_x.widening_mul(&c1b_w)).resize());

        res_c2.w[i] = (r3w + r4w) % q;
        res_c2.x[i] = (r3x + r4x) % q;
    }
    SplitSimdPolynomial { c1: res_c1, c2: res_c2 }
}
