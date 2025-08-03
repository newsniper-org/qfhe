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
        let b_poly = self.polynomial_add(&as_poly, &e_poly, params);
        let b_poly = self.polynomial_add(&b_poly, &scaled_m_poly, params);

        Ciphertext { a_vec, b: b_poly, modulus_level: 0 }
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
        assert_eq!(ct1.modulus_level, ct2.modulus_level, "Ciphertexts must have the same modulus level for addition.");
        let k = params.module_dimension_k;
        let a_vec_add = (0..k).map(|i| self.polynomial_add(&ct1.a_vec[i], &ct2.a_vec[i], params)).collect();
        let b_add = self.polynomial_add(&ct1.b, &ct2.b, params);
        Ciphertext { a_vec: a_vec_add, b: b_add, modulus_level: ct1.modulus_level }
    }

    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters) -> Ciphertext {
        assert_eq!(ct1.modulus_level, ct2.modulus_level, "Ciphertexts must have the same modulus level for subtraction.");
        let k = params.module_dimension_k;
        let a_vec_sub = (0..k).map(|i| self.polynomial_sub(&ct1.a_vec[i], &ct2.a_vec[i], params)).collect();
        let b_sub = self.polynomial_sub(&ct1.b, &ct2.b, params);
        Ciphertext { a_vec: a_vec_sub, b: b_sub, modulus_level: ct1.modulus_level }
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
        new_ct
    }

    fn keyswitch(&self, ct: &Ciphertext, ksk: &KeySwitchingKey, params: &QfheParameters) -> Ciphertext {
        // ksk의 첫 번째 암호문과 ct의 레벨을 비교하여 일치하는지 검사
        if !ksk.key.is_empty() && !ksk.key[0].is_empty() {
            assert_eq!(ct.modulus_level, ksk.key[0][0].modulus_level, "Ciphertext and KeySwitchingKey must have the same modulus level.");
        }

        let n = params.polynomial_degree;
        let k = params.module_dimension_k;
        let base = params.gadget_base_b;
        let levels = params.gadget_levels_l;
        let mut new_ct = Ciphertext {
            a_vec: vec![SimdPolynomial::zero(n); k],
            b: ct.b.clone(),
            modulus_level: ct.modulus_level,
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
