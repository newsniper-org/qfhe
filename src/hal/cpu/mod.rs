use crate::core::{
    Ciphertext, Polynomial, Quaternion, SecretKey, QfheParameters
};
use super::HardwareBackend;
use rand::Rng;
use rand_distr::{Normal, Distribution};

pub struct CpuBackend;

fn sample_discrete_gaussian(noise_std_dev: f64) -> i128 {
    let mut rng = rand::rng();
    let normal = Normal::new(0.0, noise_std_dev).unwrap();
    normal.sample(&mut rng).round() as i128
}

// u128 덧셈/곱셈의 오버플로우를 원천적으로 방지하는 가장 안전한 모듈러 연산 함수
fn add_mod(a: u128, b: u128, m: u128) -> u128 {
    // (a + b) % m
    // a + b가 m을 초과하는지 확인하여 오버플로우 없이 덧셈을 수행합니다.
    let tmp_a = a%m;
    let tmp_b = b%m;
    let cutline = 1u128 << 127;
    match (tmp_a >= cutline, tmp_b >= cutline, m >= cutline) {
        (_, _, false) | (false, false, true)=> (tmp_a + tmp_b)%m,
        (true, false, true) => {
            if (tmp_a - cutline) + tmp_b >= (m - cutline) {
                (tmp_a - cutline) + tmp_b - (m - cutline)
            } else {
                let tmp_c = (m - cutline) - ((tmp_a - cutline) + tmp_b);
                m - tmp_c
            }
        },
        (false, true, true) => {
            if (tmp_b - cutline) + tmp_a >= (m - cutline) {
                (tmp_b - cutline) + tmp_a - (m - cutline)
            } else {
                let tmp_c = (m - cutline) - (tmp_b - cutline) - tmp_a;
                m - tmp_c
            }
        },
        (true, true, true) => {
            // tmp_a >= (m - tmp_a), tmp_b >= (m - tmp_b)
            let tmp_sum = (tmp_a - cutline) + (tmp_b - cutline);
            let tmp_m = m - cutline;
            // tmp_m > (tmp_sum - tmp_m)
            let tmp_c = (tmp_m + tmp_m) - tmp_sum;
            m - tmp_c
        }  
    }
}

fn mul_mod(mut a: u128, mut b: u128, m: u128) -> u128 {
    // 이진 곱셈(Binary Multiplication)을 사용하여 오버플로우를 방지합니다.
    let mut res: u128 = 0;
    a %= m;
    while b > 0 {
        if b & 1 == 1 {
            res = add_mod(res, a, m); // 안전한 모듈러 덧셈 사용
        }
        a = add_mod(a, a, m); // 안전한 모듈러 덧셈으로 두 배 연산
        b >>= 1;
    }
    res
}


impl HardwareBackend for CpuBackend {
    fn encrypt(&self, message: u64, params: &QfheParameters, secret_key: &SecretKey) -> Ciphertext {
        let mut rng = rand::rng();
        let k = params.module_dimension_k;

        // 1. a_vec: k개의 무작위 다항식 벡터 생성
        let a_vec = (0..k).map(|_| {
            let coeffs = (0..params.polynomial_degree).map(|_| Quaternion {
                w: rng.random_range(0..params.modulus_q), x: 0, y: 0, z: 0,
            }).collect();
            Polynomial { coeffs }
        }).collect::<Vec<_>>();

        // 2. e: 작은 오차 다항식 생성
        let e_coeffs = (0..params.polynomial_degree).map(|_| Quaternion {
            w: sample_discrete_gaussian(params.noise_std_dev).rem_euclid(params.modulus_q as i128) as u128,
            x: 0, y: 0, z: 0,
        }).collect();
        let e_poly = Polynomial { coeffs: e_coeffs };
        
        // 3. m: 메시지 인코딩
        let mut scaled_m_coeffs = vec![Quaternion::zero(); params.polynomial_degree];
        let plaintext_mask = params.plaintext_modulus - 1;
        scaled_m_coeffs[0] = Quaternion::from_scalar(((message as u128) & plaintext_mask) * params.scaling_factor_delta);
        let scaled_m_poly = Polynomial { coeffs: scaled_m_coeffs };

        // 4. b = <a, s> + e + m 계산
        let mut as_poly = Polynomial::zero(params.polynomial_degree);
        for i in 0..k {
            let product = self.polynomial_mul(&a_vec[i], &secret_key.0[i], params);
            as_poly = self.polynomial_add(&as_poly, &product, params);
        }
        
        let b_poly = self.polynomial_add(&as_poly, &e_poly, params);
        let b_poly = self.polynomial_add(&b_poly, &scaled_m_poly, params);

        Ciphertext { a_vec, b: b_poly }
    }

    fn decrypt(&self, ciphertext: &Ciphertext, params: &QfheParameters, secret_key: &SecretKey) -> u64 {
        let k = params.module_dimension_k;
        
        // 1. <a, s> 계산
        let mut as_poly = Polynomial::zero(params.polynomial_degree);
        for i in 0..k {
            let product = self.polynomial_mul(&ciphertext.a_vec[i], &secret_key.0[i], params);
            as_poly = self.polynomial_add(&as_poly, &product, params);
        }

        // 2. m' = b - <a, s>
        let m_prime_poly = self.polynomial_sub(&ciphertext.b, &as_poly, params);
        let noisy_message = m_prime_poly.coeffs[0].w;

        // 3. 디코딩
        let half_delta = params.scaling_factor_delta / 2;
        let rounded_val = add_mod(noisy_message, half_delta, params.modulus_q);
        (rounded_val / params.scaling_factor_delta) as u64
    }

    fn polynomial_add(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters) -> Polynomial {
        let mut result_coeffs = Vec::with_capacity(params.polynomial_degree);
        let zero = Quaternion::zero();
        for i in 0..params.polynomial_degree {
            let q1 = p1.coeffs.get(i).unwrap_or(&zero);
            let q2 = p2.coeffs.get(i).unwrap_or(&zero);
            result_coeffs.push(Quaternion {
                w: add_mod(q1.w, q2.w, params.modulus_q), x: add_mod(q1.x, q2.x, params.modulus_q),
                y: add_mod(q1.y, q2.y, params.modulus_q), z: add_mod(q1.z, q2.z, params.modulus_q),
            });
        }
        Polynomial { coeffs: result_coeffs }
    }

    fn polynomial_sub(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters) -> Polynomial {
        let mut result_coeffs = Vec::with_capacity(params.polynomial_degree);
        let zero = Quaternion::zero();
        for i in 0..params.polynomial_degree {
            let q1 = p1.coeffs.get(i).unwrap_or(&zero);
            let q2 = p2.coeffs.get(i).unwrap_or(&zero);
            let w = add_mod(q1.w, params.modulus_q - q2.w, params.modulus_q);
            let x = add_mod(q1.x, params.modulus_q - q2.x, params.modulus_q);
            let y = add_mod(q1.y, params.modulus_q - q2.y, params.modulus_q);
            let z = add_mod(q1.z, params.modulus_q - q2.z, params.modulus_q);
            result_coeffs.push(Quaternion { w, x, y, z });
        }
        Polynomial { coeffs: result_coeffs }
    }

    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters) -> Polynomial {
        let mut result = Polynomial::zero(params.polynomial_degree);
        for i in 0..params.polynomial_degree {
            for j in 0..params.polynomial_degree {
                if p1.coeffs[i].w == 0 { continue; }
                let index = (i + j) % params.polynomial_degree;
                let val = mul_mod(p1.coeffs[i].w, p2.coeffs[j].w, params.modulus_q);
                result.coeffs[index].w = add_mod(result.coeffs[index].w, val, params.modulus_q);
            }
        }
        result
    }
    
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters) -> Ciphertext {
        let k = params.module_dimension_k;
        let a_vec_add = (0..k)
            .map(|i| self.polynomial_add(&ct1.a_vec[i], &ct2.a_vec[i], params))
            .collect();
        let b_add = self.polynomial_add(&ct1.b, &ct2.b, params);
        Ciphertext { a_vec: a_vec_add, b: b_add }
    }

    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters) -> Ciphertext {
        let k = params.module_dimension_k;
        let a_vec_sub = (0..k)
            .map(|i| self.polynomial_sub(&ct1.a_vec[i], &ct2.a_vec[i], params))
            .collect();
        let b_sub = self.polynomial_sub(&ct1.b, &ct2.b, params);
        Ciphertext { a_vec: a_vec_sub, b: b_sub }
    }
}
