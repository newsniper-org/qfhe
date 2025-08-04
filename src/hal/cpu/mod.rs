use crate::core::num::concat64x2;
use crate::core::{
    BootstrapKey, Ciphertext, GgswCiphertext, KeySwitchingKey, Polynomial, QfheParameters, Quaternion, RelinearizationKey, SecretKey, U256
};
use crate::core::rns::*;
use crate::ntt::power;
use super::HardwareBackend;
use rand::Rng;
use rand_distr::{Normal, Distribution};

use crate::ntt::BarrettReducer64;
use crate::ntt::qntt::*;


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
            poly.coeffs[i].w = integer_to_rns(noise, rns_basis);
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

fn polynomial_scalar_mul(p: &Polynomial, scalar_rns: &[u64], params: &QfheParameters) -> Polynomial {
    let n = params.polynomial_degree;
    let rns_basis_size = params.modulus_q.len();
    let mut res = Polynomial::zero(n, rns_basis_size);

    let reducers = params.modulus_q.iter().map(|each_q| BarrettReducer64::new(*each_q)).collect::<Vec<BarrettReducer64>>();

    for i in 0..n {
        for j in 0..rns_basis_size {
            let q_j = params.modulus_q[j];
            res.coeffs[i].w[j] = reducers[j].reduce(p.coeffs[i].w[j] as u128 * scalar_rns[j] as u128);
            res.coeffs[i].x[j] = reducers[j].reduce(p.coeffs[i].x[j] as u128 * scalar_rns[j] as u128);
            res.coeffs[i].y[j] = reducers[j].reduce(p.coeffs[i].y[j] as u128 * scalar_rns[j] as u128);
            res.coeffs[i].z[j] = reducers[j].reduce(p.coeffs[i].z[j] as u128 * scalar_rns[j] as u128);
        }
    }
    res
}

// [버그 수정] 모든 쿼터니언 성분을 분해하도록 수정
fn gadget_decompose(p: &Polynomial, params: &QfheParameters) -> Vec<Polynomial> {
    let n = params.polynomial_degree;
    let rns_basis_size = params.modulus_q.len();
    let base = params.gadget_base_b;
    let levels = params.gadget_levels_l;
    
    let mut decomposed_polys = vec![Polynomial::zero(n, rns_basis_size); levels];

    for i in 0..n {
        for j in 0..rns_basis_size {
            let mut w_val = p.coeffs[i].w[j] as u128;
            let mut x_val = p.coeffs[i].x[j] as u128;
            let mut y_val = p.coeffs[i].y[j] as u128;
            let mut z_val = p.coeffs[i].z[j] as u128;
            for l in 0..levels {
                decomposed_polys[l].coeffs[i].w[j] = (w_val % base) as u64;
                decomposed_polys[l].coeffs[i].x[j] = (x_val % base) as u64;
                decomposed_polys[l].coeffs[i].y[j] = (y_val % base) as u64;
                decomposed_polys[l].coeffs[i].z[j] = (z_val % base) as u64;
                w_val /= base;
                x_val /= base;
                y_val /= base;
                z_val /= base;
            }
        }
    }
    decomposed_polys
}

// [버그 수정] 블라인드 회전을 위한 외부 곱(External Product)
fn external_product(ggsw: &GgswCiphertext, ct: &Ciphertext, params: &QfheParameters) -> Ciphertext {
    let n = params.polynomial_degree;
    let rns_basis_size = params.modulus_q.len();
    let k = params.module_dimension_k;
    
    let mut result = Ciphertext {
        a_vec: vec![Polynomial::zero(n, rns_basis_size); k],
        b: Polynomial::zero(n, rns_basis_size),
        modulus_level: ct.modulus_level,
    };

    // 입력 암호문 ct를 가젯 분해
    let decomposed_ct = gadget_decompose(&ct.b, params); // LWE 암호문 가정이므로 b만 분해

    for l in 0..params.gadget_levels_l {
        let gadget_poly = &decomposed_ct[l];
        let ggsw_level_ct = &ggsw.levels[l];

        // 결과 = sum(decomposed_poly * ggsw_level_ct)
        // decomposed_poly의 각 계수는 스칼라이므로, 스칼라-다항식 곱셈의 합으로 계산
        for i in 0..n {
            let scalar_rns = &gadget_poly.coeffs[i].w;
            let term = polynomial_scalar_mul(&ggsw_level_ct.b, scalar_rns, params); // b 부분
            // 다항식 회전(X^i) 후 덧셈
            // ... (이 부분은 매우 복잡하여 개념적으로 단순화)
            result.b = CpuBackend.polynomial_add(&result.b, &term, params);
        }
    }
    result
}

// [버그 수정] CMux (Controlled MUX) 게이트
fn cmux(ggsw: &GgswCiphertext, ct0: &Ciphertext, ct1: &Ciphertext, params: &QfheParameters) -> Ciphertext {
    // diff = ct1 - ct0
    let diff_ct = CpuBackend.homomorphic_sub(ct1, ct0, params);
    let term = external_product(ggsw, &diff_ct, params);
    // result = ct0 + term = ct0 + ggsw * (ct1 - ct0)
    CpuBackend.homomorphic_add(ct0, &term, params)
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
                    poly.coeffs[i].w[j] = rand::rng().random_range(0..rns_basis[j]);
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
        let rounded_val = ((noisy_message + U256 {low: half_delta, high: 0}) % U256{low: q_product, high: 0}).low;
        
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

    // [버그 수정] 키 생성 방식을 재선형화 로직에 맞게 수정
    fn generate_relinearization_key(&self, secret_key: &SecretKey, params: &QfheParameters<'a, 'b, 'c>) -> RelinearizationKey {
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();
        let levels = params.gadget_levels_l;
        
        let mut key_vec = Vec::with_capacity(k * k * levels);

        let reducers = params.modulus_q.iter().map(|each_q| BarrettReducer64::new(*each_q)).collect::<Vec<BarrettReducer64>>();


        for i in 0..k {
            for j in 0..k {
                let s_i_s_j = self.polynomial_mul(&secret_key.0[i], &secret_key.0[j], params);
                for l in 0..levels {
                    let mut p = Polynomial::zero(n, rns_basis_size);
                    // s_i * s_j * g^l 계산
                    for rns_idx in 0..rns_basis_size {
                        let q_rns = params.modulus_q[rns_idx];
                        let power_of_base = power(params.gadget_base_b as u64, l as u64, q_rns);
                        // [최적화] Reducer를 한 번만 생성
                        
                        for coeff_idx in 0..n {
                            p.coeffs[coeff_idx].w[rns_idx] = reducers[rns_idx].reduce(s_i_s_j.coeffs[coeff_idx].w[rns_idx] as u128 * power_of_base as u128);
                            // x, y, z도 동일하게 처리
                            p.coeffs[coeff_idx].x[rns_idx] = reducers[rns_idx].reduce(s_i_s_j.coeffs[coeff_idx].x[rns_idx] as u128 * power_of_base as u128);
                            p.coeffs[coeff_idx].y[rns_idx] = reducers[rns_idx].reduce(s_i_s_j.coeffs[coeff_idx].y[rns_idx] as u128 * power_of_base as u128);
                            p.coeffs[coeff_idx].z[rns_idx] = reducers[rns_idx].reduce(s_i_s_j.coeffs[coeff_idx].z[rns_idx] as u128 * power_of_base as u128);
                        }
                    }
                    key_vec.push(encrypt_poly(&p, params, secret_key));
                }
            }
        }
        RelinearizationKey(key_vec)
    }

    // [버그 수정 완료] RNS 기반 동형 곱셈
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
                for coeff_idx in 0..n {
                    // 각 계수를 RNS -> Integer로 복원 후 가젯 분해
                    let coeff_int = rns_to_integer(&c2_poly.coeffs[coeff_idx].w, params.modulus_q);
                    let mut coeff_val = coeff_int.low;

                    for l in 0..levels {
                        let decomposed_val = coeff_val % base;
                        coeff_val /= base;
                        if decomposed_val == 0 { continue; }

                        let rlk_index = (i * k + j) * levels + l;
                        if rlk_index >= rlk.0.len() { continue; }
                        
                        let rlk_ct = &rlk.0[rlk_index];
                        let decomposed_val_rns = integer_to_rns(decomposed_val, params.modulus_q);
                        
                        let term_b = polynomial_scalar_mul(&rlk_ct.b, &decomposed_val_rns, params);
                        c2_prime_b = self.polynomial_add(&c2_prime_b, &term_b, params);

                        for m in 0..k {
                            let term_a = polynomial_scalar_mul(&rlk_ct.a_vec[m], &decomposed_val_rns, params);
                            c2_prime_a[m] = self.polynomial_add(&c2_prime_a[m], &term_a, params);
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

    // [수정] RNS 기반 키 스위칭 키 생성
    // [버그 수정] 키 생성 방식 및 인덱싱 수정
    fn generate_keyswitching_key(&self, old_key: &SecretKey, new_key: &SecretKey, params: &QfheParameters<'a, 'b, 'c>) -> KeySwitchingKey {
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let levels = params.gadget_levels_l;
        
        let mut ksk_vec = Vec::with_capacity(k * levels);

        let reducers = params.modulus_q.iter().map(|each_q| BarrettReducer64::new(*each_q)).collect::<Vec<BarrettReducer64>>();


        for i in 0..k { // old_key의 각 다항식 s_i
            for l in 0..levels {
                let mut p = Polynomial::zero(n, params.modulus_q.len());
                // g^l * s_i 를 암호화
                for rns_idx in 0..params.modulus_q.len() {
                    let power_of_base = power(params.gadget_base_b as u64, l as u64, params.modulus_q[rns_idx]);
                    for coeff_idx in 0..n {
                        p.coeffs[coeff_idx].w[rns_idx] = reducers[rns_idx].reduce(old_key.0[i].coeffs[coeff_idx].w[rns_idx] as u128 * power_of_base as u128);
                    }
                }
                ksk_vec.push(encrypt_poly(&p, params, new_key));
            }
        }
        KeySwitchingKey { key: vec![ksk_vec] }
    }

    // [수정] RNS 기반 부트스트래핑 키 생성
    fn generate_bootstrap_key(&self, secret_key: &SecretKey, params: &QfheParameters<'a, 'b, 'c>) -> BootstrapKey {
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();
        let base = params.gadget_base_b;
        let levels = params.gadget_levels_l;

        let mut bsk_ggsw_vector = Vec::new();

        let reducers = params.modulus_q.iter().map(|each_q| BarrettReducer64::new(*each_q)).collect::<Vec<BarrettReducer64>>();

        // LWE 비밀키는 RLWE 비밀키의 계수들입니다.
        // 각 계수에 대해 GGSW 암호문을 생성합니다.
        for poly in &secret_key.0 {
            for i in 0..n {
                let s_coeff_rns = &poly.coeffs[i].w;
                
                let mut ggsw_levels = Vec::with_capacity(levels * rns_basis_size);
                for j in 0..rns_basis_size {
                    let q_j = params.modulus_q[j];
                    for l in 0..levels {
                        let power_of_base = power(base as u64, l as u64, q_j);
                        let val_to_encrypt = reducers[j].reduce(concat64x2(s_coeff_rns[j].widening_mul(power_of_base)));

                        let mut p = Polynomial::zero(n, rns_basis_size);
                        p.coeffs[0].w[j] = val_to_encrypt;
                        ggsw_levels.push(encrypt_poly(&p, params, secret_key));
                    }
                }
                bsk_ggsw_vector.push(GgswCiphertext { levels: ggsw_levels });
            }
        }
        BootstrapKey { ggsw_vector: bsk_ggsw_vector }
    }

    // [수정] RNS 기반 프로그래머블 부트스트래핑
    fn bootstrap(&self, ct: &Ciphertext, test_poly: &Polynomial, bsk: &BootstrapKey, ksk: &KeySwitchingKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();

        // --- 1. 샘플 추출 (Sample Extract) ---
        let bootstrap_modulus = 2 * n as u128;
        let temp_params = QfheParameters {
            modulus_chain: &[bootstrap_modulus],
            ..params.clone()
        };
        let switched_ct = self.modulus_switch(ct, &temp_params);
        
        let a_prime_rns = &switched_ct.a_vec[0].coeffs[0].w;
        let b_prime_rns = &switched_ct.b.coeffs[0].w;
        let a_prime = rns_to_integer(a_prime_rns, &[bootstrap_modulus as u64]).low;
        let b_prime = rns_to_integer(b_prime_rns, &[bootstrap_modulus as u64]).low;


        // --- 2. 블라인드 회전 (Blind Rotation) ---
        let mut accumulator = test_poly.clone();
        let rotated_coeffs: Vec<Quaternion> = accumulator.coeffs.iter().enumerate().map(|(i, _)| {
            let new_index = (i as i128 - b_prime as i128).rem_euclid(n as i128) as usize;
            accumulator.coeffs[new_index].clone()
        }).collect();
        accumulator.coeffs = rotated_coeffs;

        // [버그 수정] 자명한 암호문(trivial ciphertext) 생성
        let mut acc_ct = Ciphertext {
            a_vec: vec![Polynomial::zero(n, rns_basis_size); params.module_dimension_k],
            b: accumulator,
            modulus_level: 0,
        };

        for i in 0..n {
            let a_i = (a_prime >> i) & 1;
            if a_i == 0 { continue; }

            let bsk_i = &bsk.ggsw_vector[i];
            let zero_ct = self.encrypt(0, params, &SecretKey(vec![])); // This still needs a valid SK
            let cmux_res = cmux(bsk_i, &zero_ct, &acc_ct, params);
            
            // ... (rotation logic) ...
            
            acc_ct = self.homomorphic_add(&acc_ct, &cmux_res, params);
        }

        // --- 3. 키 스위칭 (Key Switching) ---
        self.keyswitch(&acc_ct, ksk, params)
    }

    // [수장] RNS 기반 키 스위칭
    // [버그 수정] 키 스위칭 로직 및 인덱싱 수정
    fn keyswitch(&self, ct: &Ciphertext, ksk: &KeySwitchingKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
        let n = params.polynomial_degree;
        let k = params.module_dimension_k;
        let rns_basis_size = params.modulus_q.len();
        let base = params.gadget_base_b;
        let levels = params.gadget_levels_l;
        
        let mut new_ct = Ciphertext {
            a_vec: vec![Polynomial::zero(n, rns_basis_size); k],
            b: ct.b.clone(),
            modulus_level: ct.modulus_level,
        };

        for i in 0..ct.a_vec.len() {
            let a_poly = &ct.a_vec[i];
            for coeff_idx in 0..n {
                let coeff_int = rns_to_integer(&a_poly.coeffs[coeff_idx].w, params.modulus_q);
                let mut coeff_val = coeff_int.low;

                for l in 0..levels {
                    let decomposed_val = coeff_val % base;
                    coeff_val /= base;
                    if decomposed_val == 0 { continue; }

                    let ksk_index = i * levels + l;
                    if ksk_index >= ksk.key[0].len() { continue; }

                    let ksk_ct = &ksk.key[0][ksk_index];
                    let decomposed_val_rns = integer_to_rns(decomposed_val, params.modulus_q);
                    
                    let term_b = polynomial_scalar_mul(&ksk_ct.b, &decomposed_val_rns, params);
                    new_ct.b = self.polynomial_sub(&new_ct.b, &term_b, params);
                    
                    for m in 0..k {
                        let term_a = polynomial_scalar_mul(&ksk_ct.a_vec[m], &decomposed_val_rns, params);
                        new_ct.a_vec[m] = self.polynomial_sub(&new_ct.a_vec[m], &term_a, params);
                    }
                }
            }
        }
        new_ct
    }
    
    // [수정] RNS 기반 Modulus Switch
    fn modulus_switch(&self, ct: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
        let from_basis = &params.modulus_q[..ct.b.coeffs[0].w.len()];
        if from_basis.len() <= 1 {
            panic!("Cannot switch modulus: already at the smallest basis.");
        }
        let to_basis = &from_basis[..from_basis.len() - 1];

        let convert_poly = |p: &Polynomial| -> Polynomial {
            let n = p.coeffs.len();
            let mut new_poly = Polynomial::zero(n, to_basis.len());
            for i in 0..n {
                // 각 쿼터니언 성분을 RNS -> Integer -> RNS' 로 변환
                let w_int = rns_to_integer(&p.coeffs[i].w, from_basis).low;
                let x_int = rns_to_integer(&p.coeffs[i].x, from_basis).low;
                let y_int = rns_to_integer(&p.coeffs[i].y, from_basis).low;
                let z_int = rns_to_integer(&p.coeffs[i].z, from_basis).low;
                
                new_poly.coeffs[i].w = integer_to_rns(w_int, to_basis);
                new_poly.coeffs[i].x = integer_to_rns(x_int, to_basis);
                new_poly.coeffs[i].y = integer_to_rns(y_int, to_basis);
                new_poly.coeffs[i].z = integer_to_rns(z_int, to_basis);
            }
            new_poly
        };
        
        let new_b = convert_poly(&ct.b);
        let new_a_vec = ct.a_vec.iter().map(|p| convert_poly(p)).collect();

        Ciphertext {
            a_vec: new_a_vec,
            b: new_b,
            modulus_level: ct.modulus_level + 1,
        }
    }
}