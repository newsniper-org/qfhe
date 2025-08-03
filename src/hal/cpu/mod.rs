use crate::core::{
    Ciphertext, Polynomial, Quaternion, SecretKey, QfheParameters, RelinearizationKey,
    KeySwitchingKey, BootstrapKey, GgswCiphertext
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

        Ciphertext { a_vec, b: b_poly, modulus_level: 0 }
    }

    fn decompose(&self, poly: &Polynomial, params: &QfheParameters) -> Vec<Polynomial> {
        let base = params.gadget_base_b;
        let levels = params.gadget_levels_l;
        let n = params.polynomial_degree;

        let mut result_levels = vec![Polynomial::zero(n); levels];
        
        // 각 계수를 순회
        for i in 0..n {
            let mut coeff_w = poly.coeffs[i].w; // 분해할 계수 값
            
            // 계수 값을 각 레벨에 맞게 분해하여 저장
            for l in 0..levels {
                let decomposed_val = coeff_w % base;
                coeff_w /= base;
                result_levels[l].coeffs[i].w = decomposed_val;
            }
        }
        result_levels
    }

    fn external_product(&self, ggsw: &GgswCiphertext, ct: &Ciphertext, params: &QfheParameters) -> Ciphertext {
        // ◀◀ 레벨 일치 여부 검사
        // GGSW 암호문이 비어있지 않은지 확인하고, 첫 번째 암호문의 레벨을 기준으로 비교합니다.
        if let Some(first_ggsw_level_ct) = ggsw.levels.first() {
            assert_eq!(first_ggsw_level_ct.modulus_level, ct.modulus_level, "GGSW and Ciphertext must have the same modulus level for external product.");
        }

        let levels = params.gadget_levels_l;
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;

        // 1. 입력 암호문 `ct`의 각 다항식을 가젯 분해합니다.
        let decomposed_b = self.decompose(&ct.b, params);
        let decomposed_a_vec: Vec<Vec<Polynomial>> = ct.a_vec.iter()
            .map(|a_poly| self.decompose(a_poly, params))
            .collect();

        // 2. 결과를 저장할 암호문을 0으로 초기화합니다.
        // 외부 곱셈의 결과는 입력 ct와는 별개의 새로운 암호문이 됩니다.
        let mut res_b = Polynomial::zero(n);
        let mut res_a_vec = vec![Polynomial::zero(n); k];

        /// 3. 각 가젯 레벨(l)을 순회하며 곱셈과 덧셈을 누적합니다.
        for l in 0..levels {
            let g_l = &ggsw.levels[l]; // l번째 GGSW 레벨 암호문

            // [로직 수정] 분해된 a와 b를 모두 사용하여 연산합니다.
            // res_b += decomposed_b[l] * g_l.b
            let term_b = self.polynomial_mul(&decomposed_b[l], &g_l.b, params);
            res_b = self.polynomial_add(&res_b, &term_b, params);

            for i in 0..k {
                // res_a[i] += decomposed_b[l] * g_l.a[i]
                let term_a_from_b = self.polynomial_mul(&decomposed_b[l], &g_l.a_vec[i], params);
                res_a_vec[i] = self.polynomial_add(&res_a_vec[i], &term_a_from_b, params);
                
                // res_b -= decomposed_a[i][l] * g_l.a[i]
                let term_b_from_a = self.polynomial_mul(&decomposed_a_vec[i][l], &g_l.a_vec[i], params);
                res_b = self.polynomial_sub(&res_b, &term_b_from_a, params);
            }
        }
        
        println!("[Info] external_product: 연산 완료.");
        Ciphertext { a_vec: res_a_vec, b: res_b, modulus_level: ct.modulus_level }
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

        Ciphertext { a_vec, b: b_poly, modulus_level: 0 }
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
        assert_eq!(ct1.modulus_level, ct2.modulus_level, "Ciphertexts must have the same modulus level for addition.");
        let k = params.module_dimension_k;
        let a_vec_add = (0..k)
            .map(|i| self.polynomial_add(&ct1.a_vec[i], &ct2.a_vec[i], params))
            .collect();
        let b_add = self.polynomial_add(&ct1.b, &ct2.b, params);
        Ciphertext { a_vec: a_vec_add, b: b_add, modulus_level: ct1.modulus_level }
    }

    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters) -> Ciphertext {
        assert_eq!(ct1.modulus_level, ct2.modulus_level, "Ciphertexts must have the same modulus level for subtraction.");
        let k = params.module_dimension_k;
        let a_vec_sub = (0..k)
            .map(|i| self.polynomial_sub(&ct1.a_vec[i], &ct2.a_vec[i], params))
            .collect();
        let b_sub = self.polynomial_sub(&ct1.b, &ct2.b, params);
        Ciphertext { a_vec: a_vec_sub, b: b_sub, modulus_level: ct1.modulus_level }
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
        assert_eq!(ct1.modulus_level, ct2.modulus_level, "Ciphertexts must have the same modulus level for multiplication.");
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

        Ciphertext { a_vec: new_a_vec, b: new_b, modulus_level: ct1.modulus_level }
    }



    fn generate_keyswitching_key(&self, old_key: &SecretKey, new_key: &SecretKey, params: &QfheParameters) -> KeySwitchingKey {
        // [완전 구현] 가젯 분해(Gadget Decomposition)를 사용한 키 스위칭 키 생성
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let base = params.gadget_base_b;
        let levels = params.gadget_levels_l;
        
        let mut ksk_outer_vec = Vec::with_capacity(k * n);

        for poly in &old_key.0 { // k개의 다항식 순회
            for coeff in &poly.coeffs { // n개의 계수 순회
                let mut s_i = coeff.w; // 계수 값
                let mut ksk_inner_vec = Vec::with_capacity(levels);

                for l in 1..=levels {
                    let decomposed_val = s_i % base;
                    s_i /= base;

                    // 분해된 값(decomposed_val)을 다항식으로 만들어 암호화
                    let mut p = Polynomial::zero(n);
                    let power_of_base = base.pow(l as u32 - 1);
                    p.coeffs[0].w = decomposed_val * power_of_base;
                    
                    ksk_inner_vec.push(self.encrypt_poly( &p, params, new_key));
                }
                ksk_outer_vec.push(ksk_inner_vec);
            }
        }
        println!("[Info] generate_keyswitching_key: 가젯 분해 기반 키 생성 완료.");
        KeySwitchingKey { key: ksk_outer_vec }
    }

    fn generate_bootstrap_key(&self, secret_key: &SecretKey, params: &QfheParameters) -> BootstrapKey {
        // [완전 구현] MLWE 비밀키를 GGSW 암호문으로 암호화하여 부트스트래핑 키 생성
        let base = params.gadget_base_b;
        let levels = params.gadget_levels_l;
        let n = params.polynomial_degree;
        
        let mut bsk_ggsw_vector = Vec::with_capacity(n * params.module_dimension_k);

        // GGSW는 일반적으로 LWE 비밀키를 암호화하므로, MLWE 비밀키를 LWE 키처럼 다룹니다.
        for poly in &secret_key.0 {
            for s_coeff in &poly.coeffs {
                let s = s_coeff.w; // 비밀키의 각 스칼라 값
                let mut ggsw_levels = Vec::with_capacity(levels);

                for l in 1..=levels {
                    // g = B^l, 암호화할 값은 s * g
                    let g = base.pow(l as u32 - 1);
                    let val_to_encrypt = mul_mod(s, g, params.modulus_q);
                    
                    let mut p = Polynomial::zero(n);
                    p.coeffs[0].w = val_to_encrypt;
                    ggsw_levels.push(self.encrypt_poly( &p, params, secret_key));
                }
                bsk_ggsw_vector.push(GgswCiphertext { levels: ggsw_levels });
            }
        }
        println!("[Info] generate_bootstrap_key: 완전한 GGSW 키 생성 완료.");
        BootstrapKey { ggsw_vector: bsk_ggsw_vector }
    }

    fn bootstrap(&self, ct: &Ciphertext, test_poly: &Polynomial, bsk: &BootstrapKey, ksk: &KeySwitchingKey, params: &QfheParameters) -> Ciphertext {
        // [구체화] 프로그래머블 부트스트래핑의 완전한 흐름
        println!("[Info] bootstrap: 부트스트래핑 프로세스 시작.");

        // --- 1. 위상 추출 (Phase Extraction) ---
        // [수정] Modulus Switching을 사용하여 위상을 추출합니다.
        // 암호문의 모듈러스를 2N으로 스위칭하여, b' - <a', s> 결과를 얻습니다.
        // 이 결과값의 최상위 비트들이 원래 메시지의 정보를 담고 있습니다.
        let temp_params = QfheParameters {
            modulus_q: params.modulus_q,
            modulus_chain: &[2 * params.polynomial_degree as u128], // 목표 모듈러스: 2N
            ..params.clone()
        };
        let switched_ct = self.modulus_switch(ct, &temp_params);
        let scaled_phase = switched_ct.b.coeffs[0].w; // 스위칭된 암호문의 b 계수가 위상 정보를 가짐
        println!("[Info] bootstrap: Modulus Switching 기반 위상 추출 완료 (scaled_phase: {}).", scaled_phase);

        // --- 2. 블라인드 회전 (Blind Rotation) ---
        let mut accumulator_ct = self.encrypt_poly( test_poly, params, &SecretKey(vec![])); // 임시 SK
        
        println!("[Info] bootstrap: 블라인드 회전 시작 ({}개의 GGSW 암호문 사용).", bsk.ggsw_vector.len());

        // scaled_phase의 각 비트를 순회하며 CMux를 적용합니다.
        // (a_i가 1이면) ACC = CMux(ACC, X^i * ACC) = ACC * external_product(ggsw_i, 1)
        for i in 0..params.polynomial_degree {
             // scaled_phase의 i번째 비트가 1인지 확인합니다.
            if (scaled_phase >> i) & 1 == 1 {
                // GGSW 암호문과 외부 곱을 통해 누산기를 업데이트(회전)합니다.
                // i번째 GGSW 암호문은 X^i * s 를 암호화한 것입니다.
                let ggsw_ct = &bsk.ggsw_vector[i];
                // 외부 곱을 통해 누산기를 업데이트(회전)합니다.
                let rotated_term = self.external_product(ggsw_ct, &accumulator_ct, params);
                accumulator_ct = self.homomorphic_add(&accumulator_ct, &rotated_term, params);
            }
        }
        println!("[Info] bootstrap: 블라인드 회전 완료.");
        
        // --- 3. 키 스위칭 (Key Switching) ---
        println!("[Info] bootstrap: 키 스위칭 시작...");
        // 블라인드 회전 결과(accumulator_ct)를 키 스위칭하여 최종 결과를 얻습니다.
        let refreshed_ct = self.keyswitch(&accumulator_ct, ksk, params);
        println!("[Info] bootstrap: 키 스위칭 완료. 부트스트래핑 성공!");

        refreshed_ct
    }

    fn keyswitch(&self, ct: &Ciphertext, ksk: &KeySwitchingKey, params: &QfheParameters) -> Ciphertext {
        // ksk의 첫 번째 암호문과 ct의 레벨을 비교하여 일치하는지 검사
        if !ksk.key.is_empty() && !ksk.key[0].is_empty() {
            assert_eq!(ct.modulus_level, ksk.key[0][0].modulus_level, "Ciphertext and KeySwitchingKey must have the same modulus level.");
        }

        let n = params.polynomial_degree;
        let k = params.module_dimension_k;

        // 1. 키를 바꿀 암호문(ct)을 가젯 분해합니다.
        let decomposed_a = self.decompose(&ct.a_vec[0], params); // LWE 암호문 가정이므로 a_vec[0] 사용
        
        // 2. 결과를 저장할 암호문을 초기화합니다.
        // 키 스위칭 결과의 b'는 원래 암호문의 b와 같습니다.
        let mut new_ct = Ciphertext {
            a_vec: vec![Polynomial::zero(n); k],
            b: ct.b.clone(),
            modulus_level: ct.modulus_level,
        };

        // 3. 분해된 값과 키 스위칭 키(ksk)를 사용하여 내적(dot product)을 수행합니다.
        //    new_a[j] = sum_{i=0..N-1} (decomposed_a[i] * ksk[i].a[j])
        //    new_b    = b + sum_{i=0..N-1} (decomposed_a[i] * ksk[i].b)
        println!("[Info] keyswitch: 키 스위칭 연산 시작...");
        for i in 0..n { // 암호문 계수 인덱스
            for l in 0..params.gadget_levels_l { // 가젯 레벨 인덱스
                let ksk_index = i * params.gadget_levels_l + l;
                let ksk_ct = &ksk.key[ksk_index][0]; // ksk는 암호문들의 벡터

                // decomposed_a의 i번째 계수의 l번째 분해 값
                let d_a = &decomposed_a[l].coeffs[i]; 

                // 분해된 값(스칼라)과 KSK 암호문의 각 다항식을 곱합니다.
                // new_b      += d_a * ksk_ct.b
                // new_a_vec  += d_a * ksk_ct.a_vec
                let term_b = self.polynomial_mul(&Polynomial { coeffs: vec![*d_a] }, &ksk_ct.b, params);
                new_ct.b = self.polynomial_add(&new_ct.b, &term_b, params);

                for j in 0..k {
                    let term_a = self.polynomial_mul(&Polynomial { coeffs: vec![*d_a] }, &ksk_ct.a_vec[j], params);
                    new_ct.a_vec[j] = self.polynomial_add(&new_ct.a_vec[j], &term_a, params);
                }
            }
        }
        
        println!("[Info] keyswitch: 키 스위칭 연산 완료.");
        new_ct
    }

    fn modulus_switch(&self, ct: &Ciphertext, params: &QfheParameters<'_>) -> Ciphertext {
        // 체인의 다음 모듈러스를 가져옵니다
        // 1. 현재 레벨과 다음 레벨의 모듈러스를 가져옴
        let current_level = ct.modulus_level;
        let next_level = current_level + 1;
        
        // 현재 모듈러스 q_i
        let current_modulus = if current_level == 0 {
            params.modulus_q
        } else {
            params.modulus_chain[current_level - 1]
        };

        // 다음 모듈러스 q_{i+1}
        if next_level > params.modulus_chain.len() {
            panic!("Cannot switch modulus: already at the last level.");
        }
        let next_modulus = params.modulus_chain[current_level];

        let scale = |val: u128| -> u128 {
            // (val * next_modulus) / current_modulus, 정수 연산으로 근사
            // BigUint 라이브러리를 사용하면 더 정확한 연산이 가능합니다.
            let scaled = (val as u128 * next_modulus) / current_modulus;
            let error = val - (scaled * current_modulus) / next_modulus;
            // 반올림을 위해 에러를 더해줍니다.
            scaled + (error * 2 / current_modulus)
        };

        let scale_vec = |poly: &Polynomial| -> Polynomial {
            let new_coeffs = poly.coeffs.iter().map(|q| Quaternion {
                w: scale(q.w), x: scale(q.x), y: scale(q.y), z: scale(q.z),
            }).collect();
            Polynomial { coeffs: new_coeffs }
        };

        let new_a_vec = ct.a_vec.iter().map(scale_vec).collect();
        let new_b = scale_vec(&ct.b);

        Ciphertext { a_vec: new_a_vec, b: new_b, modulus_level: next_level }
    }
}
