// src/hal/cpu_backend.rs

use crate::core::{Ciphertext, Polynomial, Quaternion, SecretKey, NOISE_STD_DEV, N_DIM, Q_MOD, SCALING_FACTOR_DELTA};
use super::HardwareBackend;
use rand::Rng;
use rand_distr::{Normal, Distribution};

// CPU 백엔드 구조체
pub struct CpuBackend;

/// 이산 가우시안 분포에서 오차를 샘플링하는 함수
fn sample_discrete_gaussian() -> i64 {
    let mut rng = rand::rng();
    let normal = Normal::new(0.0, NOISE_STD_DEV).unwrap();
    normal.sample(&mut rng).round() as i64
}

impl HardwareBackend for CpuBackend {
    // --- 암호화/복호화 구현 ---
    fn encrypt(&self, message: u64, secret_key: &SecretKey) -> Ciphertext {
        let mut rng = rand::rng();

        let a_coeffs: Vec<Quaternion> = (0..N_DIM).map(|_| {
            Quaternion {
                w: rng.random_range(0..Q_MOD),
                x: rng.random_range(0..Q_MOD),
                y: rng.random_range(0..Q_MOD),
                z: rng.random_range(0..Q_MOD),
            }
        }).collect();
        let a_poly = Polynomial { coeffs: a_coeffs };

        let e_coeffs: Vec<Quaternion> = (0..N_DIM).map(|_| {
            Quaternion {
                w: sample_discrete_gaussian().rem_euclid(Q_MOD as i64) as u64,
                x: sample_discrete_gaussian().rem_euclid(Q_MOD as i64) as u64,
                y: sample_discrete_gaussian().rem_euclid(Q_MOD as i64) as u64,
                z: sample_discrete_gaussian().rem_euclid(Q_MOD as i64) as u64,
            }
        }).collect();
        let e_poly = Polynomial { coeffs: e_coeffs };
        
        let mut scaled_m_coeffs = vec![Quaternion::zero(); N_DIM];
        scaled_m_coeffs[0] = Quaternion::from_scalar((message % 16) * SCALING_FACTOR_DELTA);
        let scaled_m_poly = Polynomial { coeffs: scaled_m_coeffs };

        let as_poly = self.polynomial_mul(&a_poly, &secret_key.0);
        let b_poly = self.polynomial_add(&as_poly, &e_poly);
        let b_poly = self.polynomial_add(&b_poly, &scaled_m_poly);

        Ciphertext { polynomials: vec![a_poly, b_poly] }
    }

    fn decrypt(&self, ciphertext: &Ciphertext, secret_key: &SecretKey) -> u64 {
        if ciphertext.polynomials.len() < 2 { return 0; }
        let a_poly = &ciphertext.polynomials[0];
        let b_poly = &ciphertext.polynomials[1];

        let as_poly = self.polynomial_mul(a_poly, &secret_key.0);
        let m_prime_poly = self.polynomial_sub(b_poly, &as_poly);
        let noisy_message = m_prime_poly.coeffs[0].w;

        let half_delta = SCALING_FACTOR_DELTA / 2;
        let rounded_val = (noisy_message + half_delta) % Q_MOD;
        let decrypted_message = rounded_val / SCALING_FACTOR_DELTA;
        
        decrypted_message
    }

    // --- 다항식 연산 구현 ---
    fn polynomial_add(&self, p1: &Polynomial, p2: &Polynomial) -> Polynomial {
        let mut result_coeffs = Vec::with_capacity(N_DIM);
        let zero = Quaternion::zero();
        for i in 0..N_DIM {
            let q1 = p1.coeffs.get(i).unwrap_or(&zero);
            let q2 = p2.coeffs.get(i).unwrap_or(&zero);
            result_coeffs.push(Quaternion {
                w: (q1.w + q2.w) % Q_MOD,
                x: (q1.x + q2.x) % Q_MOD,
                y: (q1.y + q2.y) % Q_MOD,
                z: (q1.z + q2.z) % Q_MOD,
            });
        }
        Polynomial { coeffs: result_coeffs }
    }

    fn polynomial_sub(&self, p1: &Polynomial, p2: &Polynomial) -> Polynomial {
        let mut result_coeffs = Vec::with_capacity(N_DIM);
        let zero = Quaternion::zero();
        for i in 0..N_DIM {
            let q1 = p1.coeffs.get(i).unwrap_or(&zero);
            let q2 = p2.coeffs.get(i).unwrap_or(&zero);
            result_coeffs.push(Quaternion {
                w: (q1.w.wrapping_sub(q2.w)) % Q_MOD,
                x: (q1.x.wrapping_sub(q2.x)) % Q_MOD,
                y: (q1.y.wrapping_sub(q2.y)) % Q_MOD,
                z: (q1.z.wrapping_sub(q2.z)) % Q_MOD,
            });
        }
        Polynomial { coeffs: result_coeffs }
    }

    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial) -> Polynomial {
        let mut result = Polynomial::zero(N_DIM);
        for i in 0..N_DIM {
            for j in 0..N_DIM {
                let index = (i + j) % N_DIM;
                let val = (p1.coeffs[i].w as u128 * p2.coeffs[j].w as u128) % Q_MOD as u128;
                result.coeffs[index].w = (result.coeffs[index].w + val as u64) % Q_MOD;
            }
        }
        result
    }
    
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        if ct1.polynomials.len() < 2 || ct2.polynomials.len() < 2 {
            panic!("Invalid ciphertext format for homomorphic addition");
        }
        let a1 = &ct1.polynomials[0];
        let b1 = &ct1.polynomials[1];
        let a2 = &ct2.polynomials[0];
        let b2 = &ct2.polynomials[1];
        let a_add = self.polynomial_add(a1, a2);
        let b_add = self.polynomial_add(b1, b2);
        Ciphertext { polynomials: vec![a_add, b_add] }
    }

    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        if ct1.polynomials.len() < 2 || ct2.polynomials.len() < 2 {
            panic!("Invalid ciphertext format for homomorphic addition");
        }
        let a1 = &ct1.polynomials[0];
        let b1 = &ct1.polynomials[1];
        let a2 = &ct2.polynomials[0];
        let b2 = &ct2.polynomials[1];
        let a_add = self.polynomial_add(a1, a2);
        let b_add = self.polynomial_add(b1, b2);
        Ciphertext { polynomials: vec![a_add, b_add] }
    }
}
