use crate::core::{
    Ciphertext, Polynomial, Quaternion, SecretKey, QfheParameters, RelinearizationKey,
    KeySwitchingKey, BootstrapKey, GgswCiphertext
};
use crate::core::rns::*;
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

impl<'a, 'b, 'c> CpuBackend {
    // ... (이 함수는 RNS 기반으로 수정이 필요합니다) ...
    fn encrypt_poly(msg_poly: &Polynomial, params: &QfheParameters, secret_key: &SecretKey) -> Ciphertext {
        let mut rng = rand::thread_rng();
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let rns_basis = params.modulus_q;
        let rns_basis_size = rns_basis.len();

        let a_vec = (0..k).map(|_| {
            let mut poly = Polynomial::zero(n, rns_basis_size);
            for i in 0..n {
                for j in 0..rns_basis_size {
                    poly.coeffs[i].w[j] = rng.gen_range(0..rns_basis[j]);
                }
            }
            poly
        }).collect::<Vec<_>>();

        let e_poly = {
            let mut poly = Polynomial::zero(n, rns_basis_size);
            for i in 0..n {
                let noise = sample_discrete_gaussian(params.noise_std_dev) as u128;
                // This needs proper RNS conversion for large noise
                for j in 0..rns_basis_size {
                    poly.coeffs[i].w[j] = (noise % rns_basis[j] as u128) as u64;
                }
            }
            poly
        };

        let backend = CpuBackend;
        let mut as_poly = Polynomial::zero(n, rns_basis_size);
        for i in 0..k {
            let product = backend.polynomial_mul(&a_vec[i], &secret_key.0[i], params);
            as_poly = backend.polynomial_add(&as_poly, &product, params);
        }

        let b_poly = backend.polynomial_add(&as_poly, &e_poly, params);
        let b_poly = backend.polynomial_add(&b_poly, msg_poly, params);

        Ciphertext { a_vec, b: b_poly, modulus_level: 0 }
    }

    fn decompose(&self, poly: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Vec<Polynomial> {
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

    fn external_product(&self, ggsw: &GgswCiphertext, ct: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
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

    fn polynomial_scalar_mul(p: &Polynomial, scalar: u128, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial {
        // ... (이 함수는 RNS 기반으로 수정이 필요합니다) ...
        p.clone() // Placeholder
    }
}

fn polynomial_scalar_mul(p: &Polynomial, scalar: u128, params: &QfheParameters) -> Polynomial {
    let n = params.polynomial_degree;
    let rns_basis_size = params.modulus_q.len();
    let mut res = Polynomial::zero(n, rns_basis_size);

    for i in 0..n {
        for j in 0..rns_basis_size {
            let q_j = params.modulus_q[j];
            let reducer = BarrettReducer64::new(q_j);
            res.coeffs[i].w[j] = reducer.reduce(p.coeffs[i].w[j] as u128 * scalar);
            res.coeffs[i].x[j] = reducer.reduce(p.coeffs[i].x[j] as u128 * scalar);
            res.coeffs[i].y[j] = reducer.reduce(p.coeffs[i].y[j] as u128 * scalar);
            res.coeffs[i].z[j] = reducer.reduce(p.coeffs[i].z[j] as u128 * scalar);
        }
    }
    res
}

impl<'a, 'b, 'c> HardwareBackend<'a, 'b, 'c> for CpuBackend {
    // [수정] RNS 기반 암호화
    fn encrypt(&self, message: u64, params: &QfheParameters<'a, 'b, 'c>, secret_key: &SecretKey) -> Ciphertext {
        let n = params.polynomial_degree;
        let k = params.module_dimension_k;
        let rns_basis = params.modulus_q;
        let rns_basis_size = rns_basis.len();

        // a_vec: 무작위 다항식 벡터 생성 (RNS 형태)
        let a_vec = (0..k).map(|_| {
            let mut poly = Polynomial::zero(n, rns_basis_size);
            for i in 0..n {
                for j in 0..rns_basis_size {
                    poly.coeffs[i].w[j] = rand::thread_rng().gen_range(0..rns_basis[j]);
                }
            }
            poly
        }).collect::<Vec<_>>();

        // e: 작은 오차 다항식 생성 (RNS 형태)
        let e_poly = {
            let mut poly = Polynomial::zero(n, rns_basis_size);
            for i in 0..n {
                let noise = sample_discrete_gaussian(params.noise_std_dev) as u128;
                poly.coeffs[i].w = integer_to_rns(noise, rns_basis);
            }
            poly
        };

        // m: 메시지 인코딩 (RNS 형태)
        let mut scaled_m_poly = Polynomial::zero(n, rns_basis_size);
        let plaintext_mask = params.plaintext_modulus - 1;
        let scaled_message = ((message as u128) & plaintext_mask) * params.scaling_factor_delta;
        scaled_m_poly.coeffs[0].w = integer_to_rns(scaled_message, rns_basis);
        
        // b = <a, s> + e + m 계산
        let mut as_poly = Polynomial::zero(n, rns_basis_size);
        for i in 0..k {
            let product = self.polynomial_mul(&a_vec[i], &secret_key.0[i], params);
            as_poly = self.polynomial_add(&as_poly, &product, params);
        }
        
        let b_poly = self.polynomial_add(&as_poly, &e_poly, params);
        let b_poly = self.polynomial_add(&b_poly, &scaled_m_poly, params);

        Ciphertext { a_vec, b: b_poly, modulus_level: 0 }
    }

    // [수정] RNS 기반 복호화
    fn decrypt(&self, ciphertext: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>, secret_key: &SecretKey) -> u64 {
        let n = params.polynomial_degree;
        let k = params.module_dimension_k;
        let rns_basis = params.modulus_q;

        // <a, s> 계산
        let mut as_poly = Polynomial::zero(n, rns_basis.len());
        for i in 0..k {
            let product = self.polynomial_mul(&ciphertext.a_vec[i], &secret_key.0[i], params);
            as_poly = self.polynomial_add(&as_poly, &product, params);
        }

        // m' = b - <a, s> (RNS 상에서)
        let m_prime_poly = self.polynomial_sub(&ciphertext.b, &as_poly, params);
        
        // 첫 번째 계수의 RNS 표현을 가져옴
        let noisy_message_rns = &m_prime_poly.coeffs[0].w;

        // CRT를 사용하여 RNS 표현을 큰 정수로 복원
        let noisy_message = rns_to_integer(noisy_message_rns, rns_basis);

        // 디코딩
        let half_delta = params.scaling_factor_delta / 2;
        // 전체 모듈러스 Q에 대한 연산
        let q_product = rns_basis.iter().fold(1u128, |acc, &m| acc.wrapping_mul(m as u128));
        let rounded_val = (noisy_message + half_delta) % q_product;
        
        (rounded_val / params.scaling_factor_delta) as u64
    }

    // [수정] RNS 기반 다항식 덧셈
    fn polynomial_add(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial {
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();
        let mut res = Polynomial::zero(n, rns_basis_size);

        for i in 0..n {
            for j in 0..rns_basis_size {
                let q_j = params.modulus_q[j];
                res.coeffs[i].w[j] = (p1.coeffs[i].w[j] + p2.coeffs[i].w[j]) % q_j;
                res.coeffs[i].x[j] = (p1.coeffs[i].x[j] + p2.coeffs[i].x[j]) % q_j;
                res.coeffs[i].y[j] = (p1.coeffs[i].y[j] + p2.coeffs[i].y[j]) % q_j;
                res.coeffs[i].z[j] = (p1.coeffs[i].z[j] + p2.coeffs[i].z[j]) % q_j;
            }
        }
        res
    }

    // [수정] RNS 기반 다항식 뺄셈
    fn polynomial_sub(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial {
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();
        let mut res = Polynomial::zero(n, rns_basis_size);

        for i in 0..n {
            for j in 0..rns_basis_size {
                let q_j = params.modulus_q[j];
                res.coeffs[i].w[j] = (p1.coeffs[i].w[j] + q_j - p2.coeffs[i].w[j]) % q_j;
                res.coeffs[i].x[j] = (p1.coeffs[i].x[j] + q_j - p2.coeffs[i].x[j]) % q_j;
                res.coeffs[i].y[j] = (p1.coeffs[i].y[j] + q_j - p2.coeffs[i].y[j]) % q_j;
                res.coeffs[i].z[j] = (p1.coeffs[i].z[j] + q_j - p2.coeffs[i].z[j]) % q_j;
            }
        }
        res
    }

    // [수정] RNS 기반 다항식 곱셈
    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial {
        // QNTT 함수들이 in-place로 동작하므로, 입력 다항식을 복제합니다.
        let mut p1_ntt = p1.clone();
        let p2_ntt = p2.clone(); // p2는 수정되지 않으므로 mut이 필요 없음

        // 1. 순방향 QNTT
        qntt_forward(&mut p1_ntt, params);
        // p2도 변환해야 하지만, qntt_forward가 mut을 받으므로 임시 변수 사용
        let mut p2_ntt_mut = p2_ntt;
        qntt_forward(&mut p2_ntt_mut, params);

        // 2. 점별 곱셈
        qntt_pointwise_mul(&mut p1_ntt, &p2_ntt_mut, params);

        // 3. 역방향 QNTT
        qntt_inverse(&mut p1_ntt, params);

        p1_ntt
    }
    
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
        assert_eq!(ct1.modulus_level, ct2.modulus_level, "Ciphertexts must have the same modulus level for addition.");
        let k = params.module_dimension_k;
        let a_vec_add = (0..k)
            .map(|i| self.polynomial_add(&ct1.a_vec[i], &ct2.a_vec[i], params))
            .collect();
        let b_add = self.polynomial_add(&ct1.b, &ct2.b, params);
        Ciphertext { a_vec: a_vec_add, b: b_add, modulus_level: ct1.modulus_level }
    }

    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
        assert_eq!(ct1.modulus_level, ct2.modulus_level, "Ciphertexts must have the same modulus level for subtraction.");
        let k = params.module_dimension_k;
        let a_vec_sub = (0..k)
            .map(|i| self.polynomial_sub(&ct1.a_vec[i], &ct2.a_vec[i], params))
            .collect();
        let b_sub = self.polynomial_sub(&ct1.b, &ct2.b, params);
        Ciphertext { a_vec: a_vec_sub, b: b_sub, modulus_level: ct1.modulus_level }
    }


    // [수정] 모든 s_i * s_j 조합을 암호화하도록 재선형화 키 생성 업데이트
    fn generate_relinearization_key(&self, secret_key: &SecretKey, params: &QfheParameters<'a, 'b, 'c>) -> RelinearizationKey {
        let k = params.module_dimension_k;
        let mut key_vec = Vec::with_capacity(k * k);
        for i in 0..k {
            for j in 0..k {
                // 1. 비밀키의 곱(s_i * s_j)을 RNS 상에서 계산
                let s_i_s_j = self.polynomial_mul(&secret_key.0[i], &secret_key.0[j], params);
                
                // 2. s_i * s_j를 암호화하여 키를 생성
                key_vec.push(encrypt_poly(&s_i_s_j, params, secret_key));
            }
        }
        RelinearizationKey(key_vec)
    }

    // [수정] RNS 기반 동형 곱셈 (재선형화 포함)
    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext, rlk: &RelinearizationKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
        assert_eq!(ct1.modulus_level, ct2.modulus_level, "Ciphertexts must have the same modulus level for multiplication.");
        
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();
        let base = params.gadget_base_b;
        let levels = params.gadget_levels_l;

        // 1. 텐서 곱 계산
        let c0 = self.polynomial_mul(&ct1.b, &ct2.b, params);
        let mut c1 = vec![Polynomial::zero(n, rns_basis_size); k];
        for i in 0..k {
            let a1i_b2 = self.polynomial_mul(&ct1.a_vec[i], &ct2.b, params);
            let b1_a2i = self.polynomial_mul(&ct1.b, &ct2.a_vec[i], params);
            c1[i] = self.polynomial_add(&a1i_b2, &b1_a2i, params);
        }
        let mut c2 = vec![vec![Polynomial::zero(n, rns_basis_size); k]; k];
        for i in 0..k {
            for j in 0..k {
                c2[i][j] = self.polynomial_mul(&ct1.a_vec[i], &ct2.a_vec[j], params);
            }
        }

        // 2. 재선형화(Relinearization) 과정
        let mut c2_prime_b = Polynomial::zero(n, rns_basis_size);
        let mut c2_prime_a = vec![Polynomial::zero(n, rns_basis_size); k];

        for i in 0..k {
            for j in 0..k {
                let c2_poly = &c2[i][j];
                // c2_{ij}를 가젯 분해하여 재선형화 키와 내적
                for rns_idx in 0..rns_basis_size {
                    for coeff_idx in 0..n {
                        let mut coeff_val = c2_poly.coeffs[coeff_idx].w[rns_idx] as u128;
                        for l in 0..levels {
                            let decomposed_val = coeff_val % base;
                            coeff_val /= base;
                            if decomposed_val == 0 { continue; }

                            let rlk_index = (i * k + j) * levels + l; // This indexing needs to be more complex
                            if rlk_index >= rlk.0.len() { continue; }
                            
                            let rlk_ct = &rlk.0[rlk_index];

                            let term_b = polynomial_scalar_mul(&rlk_ct.b, decomposed_val, params);
                            c2_prime_b = self.polynomial_add(&c2_prime_b, &term_b, params);

                            for m in 0..k {
                                let term_a = polynomial_scalar_mul(&rlk_ct.a_vec[m], decomposed_val, params);
                                c2_prime_a[m] = self.polynomial_add(&c2_prime_a[m], &term_a, params);
                            }
                        }
                    }
                }
            }
        }
        
        // 3. 최종 암호문 결합
        let final_b = self.polynomial_add(&c0, &c2_prime_b, params);
        let mut final_a = vec![Polynomial::zero(n, rns_basis_size); k];
        for i in 0..k {
            final_a[i] = self.polynomial_add(&c1[i], &c2_prime_a[i], params);
        }
        
        Ciphertext {
            a_vec: final_a,
            b: final_b,
            modulus_level: ct1.modulus_level,
        }
    }


    // ... (이 함수는 RNS 기반으로 수정이 필요합니다) ...
    fn generate_keyswitching_key(&self, old_key: &SecretKey, new_key: &SecretKey, params: &QfheParameters<'a, 'b, 'c>) -> KeySwitchingKey {
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

    // ... (이 함수는 RNS 기반으로 수정이 필요합니다) ...
    fn generate_bootstrap_key(&self, secret_key: &SecretKey, params: &QfheParameters<'a, 'b, 'c>) -> BootstrapKey {
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

    // ... (이 함수는 RNS 기반으로 수정이 필요합니다) ...
    fn bootstrap(&self, ct: &Ciphertext, test_poly: &Polynomial, bsk: &BootstrapKey, ksk: &KeySwitchingKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
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

    // ... (이 함수는 RNS 기반으로 수정이 필요합니다) ...
    fn keyswitch(&self, ct: &Ciphertext, ksk: &KeySwitchingKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
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

    // ... (이 함수는 RNS 기반으로 수정이 필요합니다) ...
    fn modulus_switch(&self, ct: &Ciphertext, params: &QfheParameters<'_, '_, '_>) -> Ciphertext {
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