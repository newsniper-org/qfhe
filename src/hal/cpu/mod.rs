use crate::core::{
    Ciphertext, Polynomial, Quaternion, SecretKey,
    POLYNOMIAL_DEGREE, MODULUS_Q, SCALING_FACTOR_DELTA, NOISE_STD_DEV
};
use super::HardwareBackend;
use rand::Rng;
use rand_distr::{Normal, Distribution};

pub struct CpuBackend;

fn sample_discrete_gaussian() -> i128 {
    let mut rng = rand::rng();
    let normal = Normal::new(0.0, NOISE_STD_DEV).unwrap();
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
    fn encrypt(&self, message: u64, secret_key: &SecretKey) -> Ciphertext {
        let mut rng = rand::rng();
        let a_coeffs = (0..POLYNOMIAL_DEGREE).map(|_| Quaternion {
            w: rng.random_range(0..MODULUS_Q), x: rng.random_range(0..MODULUS_Q),
            y: rng.random_range(0..MODULUS_Q), z: rng.random_range(0..MODULUS_Q),
        }).collect();
        let a_poly = Polynomial { coeffs: a_coeffs };

        let e_coeffs = (0..POLYNOMIAL_DEGREE).map(|_| Quaternion {
            w: sample_discrete_gaussian().rem_euclid(MODULUS_Q as i128) as u128,
            x: sample_discrete_gaussian().rem_euclid(MODULUS_Q as i128) as u128,
            y: sample_discrete_gaussian().rem_euclid(MODULUS_Q as i128) as u128,
            z: sample_discrete_gaussian().rem_euclid(MODULUS_Q as i128) as u128,
        }).collect();
        let e_poly = Polynomial { coeffs: e_coeffs };
        
        let mut scaled_m_coeffs = vec![Quaternion::zero(); POLYNOMIAL_DEGREE];
        // 64비트 메시지를 u128로 변환하여 스케일링
        scaled_m_coeffs[0] = Quaternion::from_scalar((message as u128) * SCALING_FACTOR_DELTA);
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
        let rounded_val = (noisy_message + half_delta) % MODULUS_Q;
        // u128 결과를 u64로 변환하여 반환
        (rounded_val / SCALING_FACTOR_DELTA) as u64
    }

    fn polynomial_add(&self, p1: &Polynomial, p2: &Polynomial) -> Polynomial {
        let mut result_coeffs = Vec::with_capacity(POLYNOMIAL_DEGREE);
        let zero = Quaternion::zero();
        for i in 0..POLYNOMIAL_DEGREE {
            let q1 = p1.coeffs.get(i).unwrap_or(&zero);
            let q2 = p2.coeffs.get(i).unwrap_or(&zero);
            result_coeffs.push(Quaternion {
                w: add_mod(q1.w, q2.w,MODULUS_Q), x: add_mod(q1.x, q2.x,MODULUS_Q),
                y: add_mod(q1.y, q2.y, MODULUS_Q), z: add_mod(q1.z, q2.z, MODULUS_Q)
            });
        }
        Polynomial { coeffs: result_coeffs }
    }

    fn polynomial_sub(&self, p1: &Polynomial, p2: &Polynomial) -> Polynomial {
        let mut result_coeffs = Vec::with_capacity(POLYNOMIAL_DEGREE);
        let zero = Quaternion::zero();
        for i in 0..POLYNOMIAL_DEGREE {
            let q1 = p1.coeffs.get(i).unwrap_or(&zero);
            let q2 = p2.coeffs.get(i).unwrap_or(&zero);
            // 더 안전한 모듈러 뺄셈: (a - b) mod m = (a + (m - b)) mod m
            let w = add_mod(q1.w, MODULUS_Q - q2.w,MODULUS_Q);
            let x = add_mod(q1.x, MODULUS_Q - q2.x,MODULUS_Q);
            let y = add_mod(q1.y, MODULUS_Q - q2.y,MODULUS_Q);
            let z = add_mod(q1.z, MODULUS_Q - q2.z,MODULUS_Q);
            result_coeffs.push(Quaternion { w, x, y, z });
        }
        Polynomial { coeffs: result_coeffs }
    }

    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial) -> Polynomial {
        let mut result = Polynomial::zero(POLYNOMIAL_DEGREE);
        for i in 0..POLYNOMIAL_DEGREE {
            for j in 0..POLYNOMIAL_DEGREE {
                if p1.coeffs[i].w == 0 { continue; } // p2 계수가 0인 경우는 mul_mod에서 처리되므로 논외
                let index = (i + j) % POLYNOMIAL_DEGREE;
                let val = mul_mod(p1.coeffs[i].w, p2.coeffs[j].w, MODULUS_Q);
                if result.coeffs[index].w > (MODULUS_Q - val) {
                    result.coeffs[index].w = result.coeffs[index].w - (MODULUS_Q - val);
                } else {
                    result.coeffs[index].w = result.coeffs[index].w + val;
                }
            }
        }
        result
    }
    
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        if ct1.polynomials.len() < 2 || ct2.polynomials.len() < 2 {
            panic!("Invalid ciphertext format");
        }
        let a1 = &ct1.polynomials[0]; let b1 = &ct1.polynomials[1];
        let a2 = &ct2.polynomials[0]; let b2 = &ct2.polynomials[1];
        let a_add = self.polynomial_add(a1, a2);
        let b_add = self.polynomial_add(b1, b2);
        Ciphertext { polynomials: vec![a_add, b_add] }
    }
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        if ct1.polynomials.len() < 2 || ct2.polynomials.len() < 2 {
            panic!("Invalid ciphertext format");
        }
        let a1 = &ct1.polynomials[0]; let b1 = &ct1.polynomials[1];
        let a2 = &ct2.polynomials[0]; let b2 = &ct2.polynomials[1];
        let a_add = self.polynomial_sub(a1, a2);
        let b_add = self.polynomial_sub(b1, b2);
        Ciphertext { polynomials: vec![a_add, b_add] }
    }
}
