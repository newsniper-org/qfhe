use crate::core::{
    Ciphertext, Polynomial, Quaternion, SecretKey, QfheParameters, RelinearizationKey,
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

impl CpuBackend {
    fn encrypt_poly(&self, msg_poly: &Polynomial, params: &QfheParameters, secret_key: &SecretKey) -> Ciphertext {
        let mut rng = rand::rng();
        let k = params.module_dimension_k;

        let a_vec = (0..k).map(|_| {
            let coeffs = (0..params.polynomial_degree).map(|_| Quaternion {
                w: rng.random_range(0..params.modulus_q), x: 0, y: 0, z: 0,
            }).collect();
            Polynomial { coeffs }
        }).collect::<Vec<_>>();

        let e_coeffs = (0..params.polynomial_degree).map(|_| Quaternion {
            w: sample_discrete_gaussian(params.noise_std_dev).rem_euclid(params.modulus_q as i128) as u128,
            x: 0, y: 0, z: 0,
        }).collect();
        let e_poly = Polynomial { coeffs: e_coeffs };
        
        let mut as_poly = Polynomial::zero(params.polynomial_degree);
        for i in 0..k {
            let product = self.polynomial_mul(&a_vec[i], &secret_key.0[i], params);
            as_poly = self.polynomial_add(&as_poly, &product, params);
        }
        
        let b_poly = self.polynomial_add(&as_poly, &e_poly, params);
        let b_poly = self.polynomial_add(&b_poly, &msg_poly, params);

        Ciphertext { a_vec, b: b_poly }
    }
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
        let mut scaled_m_coeffs = vec![Quaternion::default(); params.polynomial_degree];
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
        let zero = Quaternion::default();
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
        let zero = Quaternion::default();
        for i in 0..params.polynomial_degree {
            let q1 = p1.coeffs.get(i).unwrap_or(&zero);
            let q2 = p2.coeffs.get(i).unwrap_or(&zero);
            let w = sub_mod(q1.w, q2.w, params.modulus_q);
            let x = sub_mod(q1.x, q2.x, params.modulus_q);
            let y = sub_mod(q1.y, q2.y, params.modulus_q);
            let z = sub_mod(q1.z, q2.z, params.modulus_q);
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




    fn generate_relinearization_key(&self, secret_key: &SecretKey, params: &QfheParameters) -> RelinearizationKey {
        // 비밀키의 제곱(s_i * s_j)을 암호화하여 재선형화 키를 생성합니다.
        // 구현의 편의를 위해 k*k개의 모든 조합 대신, s_0^2, s_1^2, ... 등 일부만 생성합니다.
        let k = params.module_dimension_k;
        let mut key_vec = Vec::with_capacity(k);

        for i in 0..k {
            let s_squared = self.polynomial_mul(&secret_key.0[i], &secret_key.0[i], params);
            // 여기에 plaintext_modulus (t)를 곱하는 등 스케일링 과정이 필요하지만 단순화함.
            key_vec.push(self.encrypt_poly(&s_squared, params, secret_key));
        }

        RelinearizationKey(key_vec)
    }

    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext, rlk: &RelinearizationKey, params: &QfheParameters) -> Ciphertext {
        // 1. 암호문 곱셈 (Tensor Product)
        // ct_new = (c0, c1, c2) 형태의 2차 암호문 생성.
        // c0 = b1*b2, c1 = a1*b2 + b1*a2, c2 = a1*a2
        // 실제로는 스케일링(t/q)이 필요하지만 개념적 흐름을 위해 생략.
        let k = params.module_dimension_k;
        let c0 = self.polynomial_mul(&ct1.b, &ct2.b, params);
        
        let mut c1 = vec![Polynomial::zero(params.polynomial_degree); k];
        let mut c2 = vec![Polynomial::zero(params.polynomial_degree); k]; // s_i*s_j 항에 대응

        for i in 0..k {
            let a1_b2 = self.polynomial_mul(&ct1.a_vec[i], &ct2.b, params);
            let a2_b1 = self.polynomial_mul(&ct2.a_vec[i], &ct1.b, params);
            c1[i] = self.polynomial_add(&a1_b2, &a2_b1, params);
            c2[i] = self.polynomial_mul(&ct1.a_vec[i], &ct2.a_vec[i], params);
        }

        // 2. 재선형화 (Relinearization)
        // c2 항을 재선형화 키를 사용해 1차항으로 변환.
        // new_ct = (c0, c1) + relin_key * c2
        let mut new_b = c0;
        let mut new_a_vec = c1;

        for i in 0..k {
            let rlk_a_mul_c2 = self.polynomial_mul(&rlk.0[i].a_vec[0], &c2[i], params); // rlk가 k=1 기준으로 생성됨
            let rlk_b_mul_c2 = self.polynomial_mul(&rlk.0[i].b, &c2[i], params);
            
            new_a_vec[i] = self.polynomial_add(&new_a_vec[i], &rlk_a_mul_c2, params);
            new_b = self.polynomial_add(&new_b, &rlk_b_mul_c2, params);
        }

        Ciphertext { a_vec: new_a_vec, b: new_b }
    }



    fn generate_keyswitching_key(&self, old_key: &SecretKey, new_key: &SecretKey, params: &QfheParameters) -> KeySwitchingKey {
        // TODO: old_key의 각 원소를 new_key로 암호화하여 KeySwitchingKey를 생성합니다.
        // 이 과정은 여러 개의 암호문을 생성하는 복잡한 로직을 포함합니다.
        println!("[Warning] generate_keyswitching_key is a stub and not fully implemented.");
        KeySwitchingKey(Vec::new())
    }

    fn generate_bootstrap_key(&self, secret_key: &SecretKey, params: &QfheParameters) -> BootstrapKey {
        // TODO: MLWE 비밀키를 GGSW 형태로 암호화하여 부트스트래핑 키를 생성합니다.
        // 이는 이중 암호화와 유사한 복잡한 과정을 포함합니다.
        println!("[Warning] generate_bootstrap_key is a stub and not fully implemented.");
        BootstrapKey { ggsw_vector: Vec::new() }
    }

    fn bootstrap(&self, ct: &Ciphertext, test_poly: &Polynomial, bsk: &BootstrapKey, ksk: &KeySwitchingKey, params: &QfheParameters) -> Ciphertext {
        // PBS의 핵심 로직:
        // 1. ModulusSwitch: 암호문의 모듈러스를 내려서 부트스트래핑 준비.
        // 2. BlindRotate: 부트스트래핑 키(bsk)를 사용하여 암호화된 토러스를 회전시키면서 test_poly(함수)를 적용.
        //    이 결과는 다른 키로 암호화된 LWE 암호문이 됨.
        // 3. SampleExtract: LWE 암호문에서 샘플을 추출.
        // 4. KeySwitch: 키 스위칭 키(ksk)를 사용해 원래의 MLWE 비밀키로 암호문을 되돌림.
        println!("[Warning] bootstrap is a stub and not fully implemented.");
        // 임시로 입력 암호문을 그대로 반환합니다.
        ct.clone()
    }

    

    fn modulus_switch(&self, ct: &Ciphertext, params: &QfheParameters) -> Ciphertext {
        let old_modulus = params.modulus_q;
        // 체인의 다음 모듈러스를 가져옵니다 (여기서는 간단히 마지막 것을 사용).
        let new_modulus = *params.modulus_chain.last().unwrap_or(&old_modulus);

        if new_modulus >= old_modulus {
            return ct.clone(); // 스위칭할 필요 없음
        }

        let scale = |val: u128| -> u128 {
            // (val * new_modulus) / old_modulus, 정수 연산으로 근사
            // BigUint 라이브러리를 사용하면 더 정확한 연산이 가능합니다.
            let scaled = (val as u128 * new_modulus) / old_modulus;
            let error = val - (scaled * old_modulus) / new_modulus;
            // 반올림을 위해 에러를 더해줍니다.
            scaled + (error * 2 / old_modulus)
        };

        let switch_poly = |poly: &Polynomial| -> Polynomial {
            let new_coeffs = poly.coeffs.iter().map(|q| Quaternion {
                w: scale(q.w), x: scale(q.x), y: scale(q.y), z: scale(q.z),
            }).collect();
            Polynomial { coeffs: new_coeffs }
        };

        let new_a_vec = ct.a_vec.iter().map(switch_poly).collect();
        let new_b = switch_poly(&ct.b);

        Ciphertext { a_vec: new_a_vec, b: new_b }
    }
}
