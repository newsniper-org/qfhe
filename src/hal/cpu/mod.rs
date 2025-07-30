use crate::core::{
    Ciphertext, Polynomial, Quaternion, SecretKey, QfheParameters, RelinearizationKey
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

fn sub_mod(a: u128, b: u128, m: u128) -> u128 {
    add_mod(a,m-(b%m),m)
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
    // --- 암호화/복호화 ---
    fn encrypt(&self, message: u64, params: &QfheParameters, secret_key: &SecretKey) -> Ciphertext {
        let mut rng = rand::rng();
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;

        let a_vec = (0..k).map(|_| {
            let coeffs = (0..n).map(|_| Quaternion {
                w: rng.random_range(0..params.modulus_q), x: rng.random_range(0..params.modulus_q),
                y: rng.random_range(0..params.modulus_q), z: rng.random_range(0..params.modulus_q),
            }).collect();
            Polynomial { coeffs }
        }).collect::<Vec<_>>();

        let e_coeffs = (0..n).map(|_| Quaternion {
            w: sample_discrete_gaussian(params.noise_std_dev).rem_euclid(params.modulus_q as i128) as u128,
            x: sample_discrete_gaussian(params.noise_std_dev).rem_euclid(params.modulus_q as i128) as u128,
            y: sample_discrete_gaussian(params.noise_std_dev).rem_euclid(params.modulus_q as i128) as u128,
            z: sample_discrete_gaussian(params.noise_std_dev).rem_euclid(params.modulus_q as i128) as u128,
        }).collect();
        let e_poly = Polynomial { coeffs: e_coeffs };
        
        let mut scaled_m_coeffs = vec![Quaternion::zero(); n];
        scaled_m_coeffs[0] = Quaternion::from_scalar((message as u128) * params.scaling_factor_delta);
        let scaled_m_poly = Polynomial { coeffs: scaled_m_coeffs };

        let mut as_poly = Polynomial::zero(n);
        for i in 0..k {
            let product = self.polynomial_mul(&a_vec[i], &secret_key.s[i], params);
            as_poly = self.polynomial_add(&as_poly, &product, params);
        }
        
        let b_poly = self.polynomial_add(&as_poly, &e_poly, params);
        let b_poly = self.polynomial_add(&b_poly, &scaled_m_poly, params);

        Ciphertext { a_vec, b: b_poly }
    }

    fn decrypt(&self, ciphertext: &Ciphertext, params: &QfheParameters, secret_key: &SecretKey) -> u64 {
        let k = params.module_dimension_k;
        let mut as_poly = Polynomial::zero(params.polynomial_degree);
        for i in 0..k {
            let product = self.polynomial_mul(&ciphertext.a_vec[i], &secret_key.s[i], params);
            as_poly = self.polynomial_add(&as_poly, &product, params);
        }
        let m_prime_poly = self.polynomial_sub(&ciphertext.b, &as_poly, params);
        let noisy_message = m_prime_poly.coeffs[0].w;
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

    // --- 다항식 곱셈 (안정적인 교과서 방식으로 교체 및 오류 수정) ---
    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters) -> Polynomial {
        let n = params.polynomial_degree;
        let q = params.modulus_q;
        let mut full_prod_coeffs = vec![Quaternion::zero(); 2 * n - 1];

        // 1. 일반 다항식 곱셈 수행 (결과는 2n-2차)
        for i in 0..n {
            for j in 0..n {
                let q1 = p1.coeffs[i];
                let q2 = p2.coeffs[j];

                // 4원수 곱셈 (모든 연산은 모듈러 함수로만 수행)
                let w = sub_mod(sub_mod(sub_mod(mul_mod(q1.w, q2.w, q), mul_mod(q1.x, q2.x, q), q), mul_mod(q1.y, q2.y, q), q), mul_mod(q1.z, q2.z, q), q);
                let x = add_mod(add_mod(add_mod(mul_mod(q1.w, q2.x, q), mul_mod(q1.x, q2.w, q), q), mul_mod(q1.y, q2.z, q), q), sub_mod(0, mul_mod(q1.z, q2.y, q), q), q);
                let y = add_mod(add_mod(sub_mod(mul_mod(q1.w, q2.y, q), mul_mod(q1.x, q2.z, q), q), mul_mod(q1.y, q2.w, q), q), mul_mod(q1.z, q2.x, q), q);
                let z = add_mod(add_mod(add_mod(mul_mod(q1.w, q2.z, q), mul_mod(q1.x, q2.y, q), q), sub_mod(0, mul_mod(q1.y, q2.x, q), q), q), mul_mod(q1.z, q2.w, q), q);
                let product = Quaternion { w, x, y, z };

                full_prod_coeffs[i + j].w = add_mod(full_prod_coeffs[i + j].w, product.w, q);
                full_prod_coeffs[i + j].x = add_mod(full_prod_coeffs[i + j].x, product.x, q);
                full_prod_coeffs[i + j].y = add_mod(full_prod_coeffs[i + j].y, product.y, q);
                full_prod_coeffs[i + j].z = add_mod(full_prod_coeffs[i + j].z, product.z, q);
            }
        }
        
        // 2. 순환 구조(x^n = -1)를 적용하여 n차 다항식으로 축소
        let mut final_coeffs = vec![Quaternion::zero(); n];
        for i in 0..n {
            final_coeffs[i] = full_prod_coeffs[i];
        }
        for i in 0..(n - 1) {
            final_coeffs[i].w = sub_mod(final_coeffs[i].w, full_prod_coeffs[i + n].w, q);
            final_coeffs[i].x = sub_mod(final_coeffs[i].x, full_prod_coeffs[i + n].x, q);
            final_coeffs[i].y = sub_mod(final_coeffs[i].y, full_prod_coeffs[i + n].y, q);
            final_coeffs[i].z = sub_mod(final_coeffs[i].z, full_prod_coeffs[i + n].z, q);
        }
        
        Polynomial { coeffs: final_coeffs }
    }

    // --- 동형 곱셈 (재선형화 -> 리스케일링 순서 및 로직 수정) ---
    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext, rlk: &RelinearizationKey, params: &QfheParameters) -> Ciphertext {
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let delta = params.scaling_factor_delta;

        // Step 1: 암호문 곱셈 (Tensor Product)
        let d0_prime = self.polynomial_mul(&ct1.b, &ct2.b, params);

        let mut d1_prime = vec![Polynomial::zero(n); k];
        for i in 0..k {
            let term1 = self.polynomial_mul(&ct1.a_vec[i], &ct2.b, params);
            let term2 = self.polynomial_mul(&ct1.b, &ct2.a_vec[i], params);
            d1_prime[i] = self.polynomial_add(&term1, &term2, params);
        }
        
        let d2_prime: Vec<Polynomial> = (0..k).flat_map(|i| {
            (0..k).map(move |j| self.polynomial_mul(&ct1.a_vec[i], &ct2.a_vec[j], params))
        }).collect();

        // Step 2: 재선형화 (Relinearization)
        let d2_decomposed: Vec<Vec<Polynomial>> = d2_prime.iter().map(|p| p.decompose(params.relin_key_base, params.relin_key_len, params)).collect();
        
        let mut relin_b_part = Polynomial::zero(n);
        let mut relin_a_part = vec![Polynomial::zero(n); k];

        for i in 0..(k * k) {
            for j in 0..params.relin_key_len {
                let rlk_ct = &rlk.0[i * params.relin_key_len + j];
                let decomposed_poly = &d2_decomposed[i][j];
                
                let term_b = self.polynomial_mul(decomposed_poly, &rlk_ct.b, params);
                relin_b_part = self.polynomial_add(&relin_b_part, &term_b, params);

                for l in 0..k {
                    let term_a = self.polynomial_mul(decomposed_poly, &rlk_ct.a_vec[l], params);
                    relin_a_part[l] = self.polynomial_add(&relin_a_part[l], &term_a, params);
                }
            }
        }

        let final_b_unscaled = self.polynomial_add(&d0_prime, &relin_b_part, params);
        let mut final_a_unscaled = vec![Polynomial::zero(n); k];
        for i in 0..k {
            final_a_unscaled[i] = self.polynomial_add(&d1_prime[i], &relin_a_part[i], params);
        }
        
        // Step 3: 리스케일링 (Rescaling)
        let rescale = |p: &Polynomial| -> Polynomial {
            let delta_half = delta / 2;
            Polynomial {
                coeffs: p.coeffs.iter().map(|c| {
                    Quaternion::new(
                        (c.w + delta_half) / delta, (c.x + delta_half) / delta,
                        (c.y + delta_half) / delta, (c.z + delta_half) / delta
                    )
                }).collect()
            }
        };
        
        let result_b = rescale(&final_b_unscaled);
        let result_a = final_a_unscaled.iter().map(rescale).collect();

        Ciphertext { b: result_b, a_vec: result_a }
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

    // --- 재선형화 키 생성 (Delta 스케일링 오류 수정) ---
    fn gen_relinearization_key(&self, secret_key: &SecretKey, params: &QfheParameters) -> RelinearizationKey {
        let mut rng = rand::rng();
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let l = params.relin_key_len;
        let base = params.relin_key_base;
        let q = params.modulus_q;
        let delta = params.scaling_factor_delta;
        let mut rlk_vec = Vec::new();

        for i in 0..(k * k) {
            for j in 0..l {
                // 암호화할 메시지: base^j * s_i * s_j
                let mut message_poly = secret_key.s_squared[i].clone();
                let scale_factor = base.pow(j as u32);
                for coeff in &mut message_poly.coeffs {
                    coeff.w = mul_mod(coeff.w, scale_factor, q);
                    coeff.x = mul_mod(coeff.x, scale_factor, q);
                    coeff.y = mul_mod(coeff.y, scale_factor, q);
                    coeff.z = mul_mod(coeff.z, scale_factor, q);
                }

                // 표준 암호화 절차 시작
                let a_vec = (0..k).map(|_| {
                    Polynomial { coeffs: (0..n).map(|_| Quaternion::random(&mut rng, q)).collect() }
                }).collect::<Vec<_>>();

                let e = Polynomial { 
                    coeffs: (0..n).map(|_| Quaternion {
                        w: sample_discrete_gaussian(params.noise_std_dev).rem_euclid(q as i128) as u128,
                        x: sample_discrete_gaussian(params.noise_std_dev).rem_euclid(q as i128) as u128,
                        y: sample_discrete_gaussian(params.noise_std_dev).rem_euclid(q as i128) as u128,
                        z: sample_discrete_gaussian(params.noise_std_dev).rem_euclid(q as i128) as u128,
                    }).collect() 
                };
                
                let mut as_poly = Polynomial::zero(n);
                for m in 0..k {
                    let product = self.polynomial_mul(&a_vec[m], &secret_key.s[m], params);
                    as_poly = self.polynomial_add(&as_poly, &product, params);
                }

                // b = a*s + e + delta * m
                let mut scaled_message = message_poly;
                for coeff in &mut scaled_message.coeffs {
                    coeff.w = mul_mod(coeff.w, delta, q);
                    coeff.x = mul_mod(coeff.x, delta, q);
                    coeff.y = mul_mod(coeff.y, delta, q);
                    coeff.z = mul_mod(coeff.z, delta, q);
                }
                
                let b = self.polynomial_add(&self.polynomial_add(&as_poly, &e, params), &scaled_message, params);
                
                rlk_vec.push(Ciphertext { b, a_vec });
            }
        }
        RelinearizationKey(rlk_vec)
    }
}
