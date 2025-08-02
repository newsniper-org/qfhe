#![allow(unused_variables)]

use crate::core::{
    Ciphertext, SimdPolynomial, SecretKey, QfheParameters, RelinearizationKey,
    KeySwitchingKey, BootstrapKey, GgswCiphertext
};
use super::HardwareBackend;
use rand::Rng;
use rand_distr::{Normal, Distribution};
use crypto_bigint::U256;

use crate::ntt::BarrettReducer;
use crate::ntt::qntt::{qntt_forward, qntt_inverse, qntt_pointwise_mul};
use crate::ntt::Ntt;

pub struct CpuBackend;

fn sample_discrete_gaussian(noise_std_dev: f64) -> i128 {
    rand::thread_rng().sample(Normal::new(0.0, noise_std_dev).unwrap()).round() as i128
}

fn encrypt_poly(msg_poly: &SimdPolynomial, params: &QfheParameters, secret_key: &SecretKey) -> Ciphertext {
    let mut rng = rand::thread_rng();
    let k = params.module_dimension_k;
    let n = params.polynomial_degree;
    let a_vec = (0..k).map(|_| {
        let w = (0..n).map(|_| rng.gen_range(0..params.modulus_q)).collect();
        SimdPolynomial { w, x: vec![0;n], y: vec![0;n], z: vec![0;n] }
    }).collect::<Vec<_>>();
    let e_poly = {
        let w = (0..n).map(|_| sample_discrete_gaussian(params.noise_std_dev).rem_euclid(params.modulus_q as i128) as u128).collect();
        SimdPolynomial { w, x: vec![0;n], y: vec![0;n], z: vec![0;n] }
    };
    let backend = CpuBackend;
    let mut as_poly = SimdPolynomial::zero(n);
    for i in 0..k {
        as_poly = backend.polynomial_add(&as_poly, &backend.polynomial_mul(&a_vec[i], &secret_key.0[i], params), params);
    }
    let b_poly = backend.polynomial_add(&backend.polynomial_add(&as_poly, &e_poly, params), msg_poly, params);
    Ciphertext { a_vec, b: b_poly }
}

fn polynomial_scalar_mul(p: &SimdPolynomial, scalar: u128, params: &QfheParameters) -> SimdPolynomial {
    let n = params.polynomial_degree;
    let q = params.modulus_q;
    let reducer = BarrettReducer::new(q);
    let mut res = SimdPolynomial::zero(n);
    for i in 0..n {
        res.w[i] = reducer.reduce(U256::from_u128(p.w[i]).widening_mul(&U256::from_u128(scalar)).resize());
        res.x[i] = reducer.reduce(U256::from_u128(p.x[i]).widening_mul(&U256::from_u128(scalar)).resize());
        res.y[i] = reducer.reduce(U256::from_u128(p.y[i]).widening_mul(&U256::from_u128(scalar)).resize());
        res.z[i] = reducer.reduce(U256::from_u128(p.z[i]).widening_mul(&U256::from_u128(scalar)).resize());
    }
    res
}

impl HardwareBackend for CpuBackend {
    fn encrypt(&self, message: u64, params: &QfheParameters, secret_key: &SecretKey) -> Ciphertext {
        let n = params.polynomial_degree;
        let k = params.module_dimension_k;
        let a_vec = (0..k).map(|_| {
            let w = (0..n).map(|_| rand::thread_rng().gen_range(0..params.modulus_q)).collect();
            SimdPolynomial { w, x: vec![0;n], y: vec![0;n], z: vec![0;n] }
        }).collect::<Vec<_>>();
        let e_poly = {
            let w = (0..n).map(|_| sample_discrete_gaussian(params.noise_std_dev).rem_euclid(params.modulus_q as i128) as u128).collect();
            SimdPolynomial { w, x: vec![0;n], y: vec![0;n], z: vec![0;n] }
        };
        let mut scaled_m_poly = SimdPolynomial::zero(n);
        scaled_m_poly.w[0] = ((message as u128) & (params.plaintext_modulus - 1)) * params.scaling_factor_delta;
        let mut as_poly = SimdPolynomial::zero(n);
        for i in 0..k {
            as_poly = self.polynomial_add(&as_poly, &self.polynomial_mul(&a_vec[i], &secret_key.0[i], params), params);
        }
        let b_poly = self.polynomial_add(&self.polynomial_add(&as_poly, &e_poly, params), &scaled_m_poly, params);
        Ciphertext { a_vec, b: b_poly }
    }

    fn decrypt(&self, ciphertext: &Ciphertext, params: &QfheParameters, secret_key: &SecretKey) -> u64 {
        let n = params.polynomial_degree;
        let k = params.module_dimension_k;
        let mut as_poly = SimdPolynomial::zero(n);
        for i in 0..k {
            as_poly = self.polynomial_add(&as_poly, &self.polynomial_mul(&ciphertext.a_vec[i], &secret_key.0[i], params), params);
        }
        let m_prime_poly = self.polynomial_sub(&ciphertext.b, &as_poly, params);
        let noisy_message = m_prime_poly.w[0];
        let rounded_val = (noisy_message + params.scaling_factor_delta / 2) % params.modulus_q;
        (rounded_val / params.scaling_factor_delta) as u64
    }

    fn polynomial_add(&self, p1: &SimdPolynomial, p2: &SimdPolynomial, params: &QfheParameters) -> SimdPolynomial {
        let n = params.polynomial_degree;
        let q = params.modulus_q;
        let mut res = SimdPolynomial::zero(n);
        for i in 0..n {
            res.w[i] = (p1.w[i] + p2.w[i]) % q;
            res.x[i] = (p1.x[i] + p2.x[i]) % q;
            res.y[i] = (p1.y[i] + p2.y[i]) % q;
            res.z[i] = (p1.z[i] + p2.z[i]) % q;
        }
        res
    }

    fn polynomial_sub(&self, p1: &SimdPolynomial, p2: &SimdPolynomial, params: &QfheParameters) -> SimdPolynomial {
        let n = params.polynomial_degree;
        let q = params.modulus_q;
        let mut res = SimdPolynomial::zero(n);
        for i in 0..n {
            res.w[i] = (p1.w[i] + q - p2.w[i]) % q;
            res.x[i] = (p1.x[i] + q - p2.x[i]) % q;
            res.y[i] = (p1.y[i] + q - p2.y[i]) % q;
            res.z[i] = (p1.z[i] + q - p2.z[i]) % q;
        }
        res
    }

    fn polynomial_mul(&self, p1: &SimdPolynomial, p2: &SimdPolynomial, params: &QfheParameters) -> SimdPolynomial {
        let p1_ntt = qntt_forward(p1, params);
        let p2_ntt = qntt_forward(p2, params);
        let result_ntt = qntt_pointwise_mul(&p1_ntt, &p2_ntt, params);
        qntt_inverse(&result_ntt, params)
    }

    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters) -> Ciphertext {
        let k = params.module_dimension_k;
        let a_vec_add = (0..k).map(|i| self.polynomial_add(&ct1.a_vec[i], &ct2.a_vec[i], params)).collect();
        let b_add = self.polynomial_add(&ct1.b, &ct2.b, params);
        Ciphertext { a_vec: a_vec_add, b: b_add }
    }

    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters) -> Ciphertext {
        let k = params.module_dimension_k;
        let a_vec_sub = (0..k).map(|i| self.polynomial_sub(&ct1.a_vec[i], &ct2.a_vec[i], params)).collect();
        let b_sub = self.polynomial_sub(&ct1.b, &ct2.b, params);
        Ciphertext { a_vec: a_vec_sub, b: b_sub }
    }
    
    fn generate_relinearization_key(&self, secret_key: &SecretKey, params: &QfheParameters) -> RelinearizationKey {
        let k = params.module_dimension_k;
        let mut key_vec = Vec::with_capacity(k);
        for i in 0..k {
            key_vec.push(encrypt_poly(&self.polynomial_mul(&secret_key.0[i], &secret_key.0[i], params), params, secret_key));
        }
        RelinearizationKey(key_vec)
    }

    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext, rlk: &RelinearizationKey, params: &QfheParameters) -> Ciphertext {
        ct1.clone()
    }

    fn generate_keyswitching_key(&self, old_key: &SecretKey, new_key: &SecretKey, params: &QfheParameters) -> KeySwitchingKey {
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let mut ksk_outer_vec = Vec::with_capacity(k * n);
        for poly in &old_key.0 {
            for i in 0..n {
                let mut p = SimdPolynomial::zero(n);
                p.w[0] = poly.w[i];
                ksk_outer_vec.push(vec![encrypt_poly(&p, params, new_key)]);
            }
        }
        KeySwitchingKey { key: ksk_outer_vec }
    }

    fn generate_bootstrap_key(&self, secret_key: &SecretKey, params: &QfheParameters) -> BootstrapKey {
        let n = params.polynomial_degree;
        let mut bsk_ggsw_vector = Vec::new();
        for poly in &secret_key.0 {
            for i in 0..n {
                let mut p = SimdPolynomial::zero(n);
                p.w[0] = poly.w[i];
                bsk_ggsw_vector.push(GgswCiphertext { levels: vec![encrypt_poly(&p, params, secret_key)] });
            }
        }
        BootstrapKey { ggsw_vector: bsk_ggsw_vector }
    }

    fn modulus_switch(&self, ct: &Ciphertext, params: &QfheParameters) -> Ciphertext {
        let new_modulus = *params.modulus_chain.last().unwrap_or(&params.modulus_q);
        if new_modulus >= params.modulus_q { return ct.clone(); }
        let scale_vec = |vec: &[u128]| -> Vec<u128> {
            let reducer = BarrettReducer::new(new_modulus);
            vec.iter().map(|&val| {
                let scaled_val = (U256::from_u128(val) * U256::from_u128(new_modulus) + (U256::from_u128(params.modulus_q) >> 1)) / U256::from_u128(params.modulus_q);
                reducer.reduce(scaled_val) as u128
            }).collect()
        };
        let mut new_ct = ct.clone();
        new_ct.b.w = scale_vec(&ct.b.w);
        new_ct.b.x = scale_vec(&ct.b.x);
        new_ct.b.y = scale_vec(&ct.b.y);
        new_ct.b.z = scale_vec(&ct.b.z);
        for a_poly in &mut new_ct.a_vec {
            a_poly.w = scale_vec(&a_poly.w);
            a_poly.x = scale_vec(&a_poly.x);
            a_poly.y = scale_vec(&a_poly.y);
            a_poly.z = scale_vec(&a_poly.z);
        }
        new_ct
    }

    fn keyswitch(&self, ct: &Ciphertext, ksk: &KeySwitchingKey, params: &QfheParameters) -> Ciphertext {
        let n = params.polynomial_degree;
        let k = params.module_dimension_k;
        let base = params.gadget_base_b;
        let levels = params.gadget_levels_l;
        let mut new_ct = Ciphertext {
            a_vec: vec![SimdPolynomial::zero(n); k],
            b: ct.b.clone(),
        };
        for i in 0..ct.a_vec.len() {
            let a_poly = &ct.a_vec[i];
            for j in 0..n {
                let mut a_coeff = a_poly.w[j];
                for l in 0..levels {
                    let decomposed_val = a_coeff % base;
                    a_coeff /= base;
                    if decomposed_val == 0 { continue; }
                    let ksk_index = (i * n + j) * levels + l;
                    if ksk_index >= ksk.key.len() { continue; }
                    let ksk_ct = &ksk.key[ksk_index][0];
                    let term_b = polynomial_scalar_mul(&ksk_ct.b, decomposed_val, params);
                    let term_a_vec: Vec<SimdPolynomial> = ksk_ct.a_vec.iter().map(|p| polynomial_scalar_mul(p, decomposed_val, params)).collect();
                    new_ct.b = self.polynomial_sub(&new_ct.b, &term_b, params);
                    for m in 0..k {
                        new_ct.a_vec[m] = self.polynomial_sub(&new_ct.a_vec[m], &term_a_vec[m], params);
                    }
                }
            }
        }
        new_ct
    }

    fn bootstrap(&self, ct: &Ciphertext, test_poly: &SimdPolynomial, bsk: &BootstrapKey, ksk: &KeySwitchingKey, params: &QfheParameters) -> Ciphertext {
        let n = params.polynomial_degree;
        let temp_params = QfheParameters {
            modulus_chain: vec![2 * n as u128],
            ..params.clone()
        };
        let switched_ct = self.modulus_switch(ct, &temp_params);
        let scaled_phase = switched_ct.b.w[0];
        let accumulator_ct = encrypt_poly(test_poly, params, &SecretKey(vec![]));
        self.keyswitch(&accumulator_ct, ksk, params)
    }
}
