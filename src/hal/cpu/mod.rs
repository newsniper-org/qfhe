// src/hal/cpu/mod.rs

mod ntt;

use crate::core::{
    Ciphertext, Polynomial, Quaternion, SecretKey, QfheParameters, RelinearizationKey
};
use super::HardwareBackend;
use rand::Rng;
use rand_distr::{Normal, Distribution};
use num_complex::Complex;
use self::ntt::{NttOperator, forward_ntt, inverse_ntt, multiply_pointwise};

pub struct CpuBackend {
    ntt_op: NttOperator,
}

impl CpuBackend {
    pub fn new(params: &QfheParameters) -> Self {
        Self {
            ntt_op: NttOperator::new(params),
        }
    }
}

// --- Helper Functions ---
fn add_mod(a: u128, b: u128, m: u128) -> u128 { (a + b) % m }
fn sub_mod(a: u128, b: u128, m: u128) -> u128 { (a + m - (b % m)) % m }
fn mul_mod(a: u128, b: u128, m: u128) -> u128 { ((a as u128 * b as u128) % m) as u128 }
fn sample_discrete_gaussian(noise_std_dev: f64) -> i128 {
    Normal::new(0.0, noise_std_dev).unwrap().sample(&mut rand::thread_rng()).round() as i128
}
fn power(mut a: u128, mut b: u128, m: u128) -> u128 {
    let mut res = 1; a %= m;
    while b > 0 {
        if b & 1 == 1 { res = mul_mod(res, a, m); }
        a = mul_mod(a, a, m); b >>= 1;
    }
    res
}
fn mod_inverse(n: u128, modulus: u128) -> u128 { power(n, modulus - 2, modulus) }


impl HardwareBackend for CpuBackend {
    // --- 암호화 / 복호화 ---
    fn encrypt(&self, message: u64, params: &QfheParameters, secret_key: &SecretKey) -> Ciphertext {
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let q = params.modulus_q;
        let mut rng = rand::thread_rng();

        let a_vec = (0..k).map(|_| {
            Polynomial { coeffs: (0..n).map(|_| Quaternion::random(&mut rng, q)).collect() }
        }).collect::<Vec<_>>();

        let e_poly = Polynomial { coeffs: (0..n).map(|_| Quaternion::new(sample_discrete_gaussian(params.noise_std_dev).rem_euclid(q as i128) as u128, 0, 0, 0)).collect() };
        
        let mut scaled_m_coeffs = vec![Quaternion::zero(); n];
        scaled_m_coeffs[0] = Quaternion::from_scalar(mul_mod(message as u128, params.scaling_factor_delta, q));
        let scaled_m_poly = Polynomial { coeffs: scaled_m_coeffs };

        let mut as_poly = Polynomial::zero(n);
        for i in 0..k {
            as_poly = self.polynomial_add(&as_poly, &self.polynomial_mul(&a_vec[i], &secret_key.s[i], params), params);
        }

        let b_poly = self.polynomial_add(&self.polynomial_sub(&scaled_m_poly, &as_poly, params), &e_poly, params);

        Ciphertext { a_vec, b: b_poly }
    }

    fn decrypt(&self, ciphertext: &Ciphertext, params: &QfheParameters, secret_key: &SecretKey) -> u64 {
        let mut as_poly = Polynomial::zero(params.polynomial_degree);
        for i in 0..params.module_dimension_k {
            as_poly = self.polynomial_add(&as_poly, &self.polynomial_mul(&ciphertext.a_vec[i], &secret_key.s[i], params), params);
        }
        let m_prime_poly = self.polynomial_add(&ciphertext.b, &as_poly, params);
        let noisy_message = m_prime_poly.coeffs[0].w;
        let half_q = params.modulus_q / 2;
        let val = if noisy_message > half_q { params.modulus_q - noisy_message } else { noisy_message };
        ((val as f64 / params.scaling_factor_delta as f64).round() as u64)
    }

    // --- 다항식 연산 ---
    fn polynomial_add(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters) -> Polynomial {
        let q = params.modulus_q;
        Polynomial { coeffs: p1.coeffs.iter().zip(p2.coeffs.iter()).map(|(c1, c2)| Quaternion {
            w: add_mod(c1.w, c2.w, q), x: add_mod(c1.x, c2.x, q),
            y: add_mod(c1.y, c2.y, q), z: add_mod(c1.z, c2.z, q),
        }).collect() }
    }

    fn polynomial_sub(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters) -> Polynomial {
        let q = params.modulus_q;
        Polynomial { coeffs: p1.coeffs.iter().zip(p2.coeffs.iter()).map(|(c1, c2)| Quaternion {
            w: sub_mod(c1.w, c2.w, q), x: sub_mod(c1.x, c2.x, q),
            y: sub_mod(c1.y, c2.y, q), z: sub_mod(c1.z, c2.z, q),
        }).collect() }
    }

    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters) -> Polynomial {
        let q_u128 = params.modulus_q;
        let q_u64 = q_u128 as u64;

        let (mut a1, mut a2) = p1.to_complex_polynomials();
        let (mut b1, mut b2) = p2.to_complex_polynomials();

        forward_ntt(&self.ntt_op, &mut a1);
        forward_ntt(&self.ntt_op, &mut a2);
        forward_ntt(&self.ntt_op, &mut b1);
        forward_ntt(&self.ntt_op, &mut b2);
        
        let mut b1_conj = b1.clone();
        for i in 1..b1.len()/2 { b1_conj.swap(i, b1.len() - i); }
        let mut b2_conj = b2.clone();
        for i in 1..b2.len()/2 { b2_conj.swap(i, b2.len() - i); }

        let c1_term1 = multiply_pointwise(&a1, &b1, q_u64);
        let c1_term2 = multiply_pointwise(&a2, &b2_conj, q_u64);
        let c2_term1 = multiply_pointwise(&a1, &b2, q_u64);
        let c2_term2 = multiply_pointwise(&a2, &b1_conj, q_u64);
        
        let mut c1: Vec<Complex<u64>> = c1_term1.iter().zip(c1_term2.iter()).map(|(t1, t2)| Complex::new(sub_mod(t1.re as u128, t2.re as u128, q_u128) as u64, 0)).collect();
        let mut c2: Vec<Complex<u64>> = c2_term1.iter().zip(c2_term2.iter()).map(|(t1, t2)| Complex::new(add_mod(t1.re as u128, t2.re as u128, q_u128) as u64, 0)).collect();

        inverse_ntt(&self.ntt_op, &mut c1);
        inverse_ntt(&self.ntt_op, &mut c2);
        Polynomial::from_complex_polynomials(&c1, &c2)
    }

    // --- 동형 연산 (로직 수정) ---
    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext, rlk: &RelinearizationKey, params: &QfheParameters) -> Ciphertext {
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let q = params.modulus_q;
        let delta = params.scaling_factor_delta;

        let d0 = self.polynomial_mul(&ct1.b, &ct2.b, params);
        let d1 = (0..k).map(|i| self.polynomial_add(&self.polynomial_mul(&ct1.a_vec[i], &ct2.b, params), &self.polynomial_mul(&ct1.b, &ct2.a_vec[i], params), params)).collect::<Vec<_>>();
        let d2 = self.polynomial_mul(&ct1.a_vec[0], &ct2.a_vec[0], params); // Simplified for k=2

        // Relinearization
        let rlk_c0 = &rlk.0[0].b;
        let rlk_c1 = &rlk.0[0].a_vec;
        
        let d2_p0 = self.polynomial_mul(&d2, rlk_c0, params);
        let c0 = self.polynomial_add(&d0, &d2_p0, params);

        let mut c1 = Vec::with_capacity(k);
        for i in 0..k {
            let d2_p1 = self.polynomial_mul(&d2, &rlk_c1[i], params);
            c1.push(self.polynomial_add(&d1[i], &d2_p1, params));
        }

        // Rescaling
        let inv_delta = mod_inverse(delta, q);
        let rescale_poly = |p: &Polynomial| -> Polynomial {
            Polynomial { coeffs: p.coeffs.iter().map(|c| {
                let w = mul_mod(c.w, inv_delta, q);
                let x = mul_mod(c.x, inv_delta, q);
                let y = mul_mod(c.y, inv_delta, q);
                let z = mul_mod(c.z, inv_delta, q);
                Quaternion::new(w, x, y, z)
            }).collect() }
        };

        Ciphertext {
            b: rescale_poly(&c0),
            a_vec: c1.iter().map(rescale_poly).collect(),
        }
    }
    
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters) -> Ciphertext {
        Ciphertext { a_vec: (0..params.module_dimension_k).map(|i| self.polynomial_add(&ct1.a_vec[i], &ct2.a_vec[i], params)).collect(), b: self.polynomial_add(&ct1.b, &ct2.b, params) }
    }

    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters) -> Ciphertext {
        Ciphertext { a_vec: (0..params.module_dimension_k).map(|i| self.polynomial_sub(&ct1.a_vec[i], &ct2.a_vec[i], params)).collect(), b: self.polynomial_sub(&ct1.b, &ct2.b, params) }
    }

    fn gen_relinearization_key(&self, secret_key: &SecretKey, params: &QfheParameters) -> RelinearizationKey {
        let k = params.module_dimension_k;
        let mut rng = rand::thread_rng();

        let s_sq = self.polynomial_mul(&secret_key.s[0], &secret_key.s[0], params);
        let mut rlk_ct_a = Vec::with_capacity(k);
        for _ in 0..k {
            rlk_ct_a.push(Polynomial { coeffs: (0..params.polynomial_degree).map(|_| Quaternion::random(&mut rng, params.modulus_q)).collect() });
        }

        let mut a_s = Polynomial::zero(params.polynomial_degree);
        for i in 0..k {
            a_s = self.polynomial_add(&a_s, &self.polynomial_mul(&rlk_ct_a[i], &secret_key.s[i], params), params);
        }

        let e = Polynomial { coeffs: (0..params.polynomial_degree).map(|_| Quaternion::new(sample_discrete_gaussian(params.noise_std_dev).rem_euclid(params.modulus_q as i128) as u128, 0, 0, 0)).collect() };
        let b_term = self.polynomial_add(&self.polynomial_sub(&s_sq, &a_s, params), &e, params);

        RelinearizationKey(vec![Ciphertext { b: b_term, a_vec: rlk_ct_a }])
    }
}