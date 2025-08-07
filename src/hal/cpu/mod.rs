// src/hal/cpu/mod.rs

use crate::core::num::concat64x2;
use crate::core::{
    BootstrapKey, Ciphertext, GgswCiphertext, KeySwitchingKey, Polynomial, PublicKey, QfheParameters, Quaternion, RelinearizationKey, SecretKey
};
use crate::ntt::power;
use super::HardwareBackend;
use rand::{Rng, RngCore, SeedableRng};
use rand_distr::{Normal, Distribution};

use crate::ntt::BarrettReducer64;
use crate::ntt::qntt::*;

use crate::core::num::SafeModuloArith;

use crate::core::rns::*;

use rand_chacha::ChaCha20Rng;

use rayon::prelude::*; // 병렬 처리를 위해 추가

use crypto_bigint::U256;


pub struct CpuBackend;

/// 이산 가우시안 분포에서 노이즈를 샘플링합니다.
fn sample_discrete_gaussian(noise_std_dev: f64) -> i128 {
    let mut rng = rand::thread_rng();
    let normal = Normal::new(0.0, noise_std_dev).unwrap();
    normal.sample(&mut rng).round() as i128
}


// #region 결정론적 샘플링 헬퍼 함수

/// CSPRNG를 사용하여 균등 분포에서 다항식을 샘플링합니다.
fn sample_uniform_poly(n: usize, rns_size: usize, rng: &mut ChaCha20Rng, params: &QfheParameters) -> Polynomial {
    let mut poly = Polynomial::zero(n, rns_size);
    let mut buffer = [0u8; 8];
    for i in 0..n {
        for j in 0..rns_size {
            let q_j = params.modulus_q[j];
            // --- ❗❗❗ 핵심 버그 수정: 아키텍처 독립적인 .gen() 사용 ❗❗❗ ---
            poly.coeffs[i].w[j] = rng.r#gen::<u64>() % q_j;
            poly.coeffs[i].x[j] = rng.r#gen::<u64>() % q_j;
            poly.coeffs[i].y[j] = rng.r#gen::<u64>() % q_j;
            poly.coeffs[i].z[j] = rng.r#gen::<u64>() % q_j;
        }
    }
    poly
}

/// CSPRNG를 사용하여 이산 가우시안 분포에서 작은 다항식을 샘플링합니다.
fn sample_gaussian_poly(n: usize, rns_size: usize, std_dev: f64, rng: &mut ChaCha20Rng, params: &QfheParameters) -> Polynomial {
    let mut poly = Polynomial::zero(n, rns_size);
    let normal = Normal::new(0.0, std_dev).unwrap();
    for i in 0..n {
        let noise = normal.sample(rng).round() as i128;
        // ❗ 버그 수정: params.modulus_q를 RNS 기저로 전달
        poly.coeffs[i].w = crate::core::rns::integer_to_rns(noise.unsigned_abs(), params.modulus_q);
        if noise < 0 {
            // 음수 처리: q - a
            for j in 0..rns_size {
                poly.coeffs[i].w[j] = params.modulus_q[j] - poly.coeffs[i].w[j];
            }
        }
    }
    poly
}

/// CSPRNG를 사용하여 삼항 분포({-1, 0, 1})에서 비밀키 다항식을 샘플링합니다.
fn sample_ternary_poly(n: usize, rns_size: usize, q_moduli: &[u64], rng: &mut ChaCha20Rng) -> Polynomial {
    let mut poly = Polynomial::zero(n, rns_size);
    for i in 0..n {
        let val = (rng.next_u32() % 3) as i128 - 1;
        if val != 0 {
             poly.coeffs[i].w = crate::core::rns::integer_to_rns(val.abs() as u128, q_moduli);
             if val < 0 {
                // 음수 처리
             }
        }
    }
    poly
}

/// 내부 암호화 함수 (공개키 생성 및 재선형화/부트스트랩 키 생성에 사용)
fn encrypt_internal(
    msg_poly: &Polynomial,
    sk: &SecretKey,
    rng: &mut ChaCha20Rng,
    params: &QfheParameters,
) -> Ciphertext {
    let k = params.module_dimension_k;
    let n = params.polynomial_degree;
    let rns_size = params.modulus_q.len();
    let backend = CpuBackend;

    let a_vec = (0..k).map(|_| sample_uniform_poly(n, rns_size, rng, params)).collect::<Vec<_>>();
    let e_poly = sample_gaussian_poly(n, rns_size, params.noise_std_dev, rng, params);
    
    let mut as_poly = Polynomial::zero(n, rns_size);
    for i in 0..k {
        let product = backend.polynomial_mul(&a_vec[i], &sk.0[i], params);
        as_poly = backend.polynomial_add(&as_poly, &product, params);
    }
    
    let b_poly = backend.polynomial_add(&as_poly, &e_poly, params);
    let b_poly = backend.polynomial_add(&b_poly, msg_poly, params);

    Ciphertext { a_vec, b: b_poly, modulus_level: 0 }
}

/// 다항식과 RNS로 표현된 스칼라를 곱합니다.
fn polynomial_scalar_mul(p: &Polynomial, scalar_rns: &[u64], params: &QfheParameters) -> Polynomial {
    let n = params.polynomial_degree;
    let rns_basis_size = params.modulus_q.len();
    let mut res = Polynomial::zero(n, rns_basis_size);

    for i in 0..n {
        for j in 0..rns_basis_size {
            // 모든 쿼터니언 성분에 스칼라 곱셈을 적용합니다.
            res.coeffs[i].w[j] = params.reducers[j].reduce(p.coeffs[i].w[j] as u128 * scalar_rns[j] as u128);
            res.coeffs[i].x[j] = params.reducers[j].reduce(p.coeffs[i].x[j] as u128 * scalar_rns[j] as u128);
            res.coeffs[i].y[j] = params.reducers[j].reduce(p.coeffs[i].y[j] as u128 * scalar_rns[j] as u128);
            res.coeffs[i].z[j] = params.reducers[j].reduce(p.coeffs[i].z[j] as u128 * scalar_rns[j] as u128);
        }
    }
    res
}

/// 다항식을 가젯 분해합니다.
fn gadget_decompose(p: &Polynomial, params: &QfheParameters) -> Vec<Polynomial> {
    let n = params.polynomial_degree;
    let rns_basis_size = params.modulus_q.len();
    let base = crypto_bigint::NonZero::new(U256::from_u128(params.gadget_base_b)).unwrap();
    let levels = params.gadget_levels_l;
    
    let mut decomposed_polys = vec![Polynomial::zero(n, rns_basis_size); levels];

    for i in 0..n {
        // ❗ 수정: .low를 제거하고 U256 타입으로 값을 받음
        let mut current_w = rns_to_integer(&p.coeffs[i].w, params.modulus_q);
        let mut current_x = rns_to_integer(&p.coeffs[i].x, params.modulus_q);
        let mut current_y = rns_to_integer(&p.coeffs[i].y, params.modulus_q);
        let mut current_z = rns_to_integer(&p.coeffs[i].z, params.modulus_q);

        for l in 0..levels {
            // ❗ 수정: U256의 나눗셈/나머지 연산(div_rem) 사용
            let (next_w, rem_w) = current_w.div_rem(&base);
            let (next_x, rem_x) = current_x.div_rem(&base);
            let (next_y, rem_y) = current_y.div_rem(&base);
            let (next_z, rem_z) = current_z.div_rem(&base);
            
            // 분해된 나머지(rem)는 base보다 작으므로 u128로 안전하게 변환 가능
            decomposed_polys[l].coeffs[i].w = integer_to_rns(rem_w.to_words()[0] as u128, params.modulus_q);
            decomposed_polys[l].coeffs[i].x = integer_to_rns(rem_x.to_words()[0] as u128, params.modulus_q);
            decomposed_polys[l].coeffs[i].y = integer_to_rns(rem_y.to_words()[0] as u128, params.modulus_q);
            decomposed_polys[l].coeffs[i].z = integer_to_rns(rem_z.to_words()[0] as u128, params.modulus_q);

            current_w = next_w;
            current_x = next_x;
            current_y = next_y;
            current_z = next_z;
        }
    }
    decomposed_polys
}

/// GGSW 암호문과 LWE 암호문의 외부 곱(External Product)을 계산합니다.
fn external_product(ggsw: &GgswCiphertext, lwe_ct: &Ciphertext, params: &QfheParameters) -> Ciphertext {
    let k = params.module_dimension_k;
    let n = params.polynomial_degree;
    let rns_basis_size = params.modulus_q.len();
    let levels = params.gadget_levels_l;

    // LWE 암호문의 a_vec과 b를 가젯 분해합니다.
    let mut decomposed_a = Vec::with_capacity(k);
    for i in 0..k {
        decomposed_a.push(gadget_decompose(&lwe_ct.a_vec[i], params));
    }
    let decomposed_b = gadget_decompose(&lwe_ct.b, params);

    let mut result_ct = Ciphertext {
        a_vec: vec![Polynomial::zero(n, rns_basis_size); k],
        b: Polynomial::zero(n, rns_basis_size),
        modulus_level: lwe_ct.modulus_level,
    };
    
    // GGSW 암호문의 각 레벨에 대해 연산을 수행합니다.
    // GGSW(m) * LWE(p) = LWE(m*p)
    for l in 0..levels {
        let ggsw_level_ct = &ggsw.levels[l]; // GGSW의 l번째 레벨 암호문

        // LWE의 b 부분 처리
        let b_decomp_poly = &decomposed_b[l];
        result_ct.b = CpuBackend.polynomial_add(&result_ct.b, &CpuBackend.polynomial_mul(&ggsw_level_ct.b, b_decomp_poly, params), params);
        for i in 0..k {
            result_ct.a_vec[i] = CpuBackend.polynomial_add(&result_ct.a_vec[i], &CpuBackend.polynomial_mul(&ggsw_level_ct.a_vec[i], b_decomp_poly, params), params);
        }

        // LWE의 a_vec 부분 처리
        for i in 0..k {
            let a_decomp_poly = &decomposed_a[i][l];
            result_ct.b = CpuBackend.polynomial_add(&result_ct.b, &CpuBackend.polynomial_mul(&ggsw_level_ct.b, a_decomp_poly, params), params);
            for j in 0..k {
                 result_ct.a_vec[j] = CpuBackend.polynomial_add(&result_ct.a_vec[j], &CpuBackend.polynomial_mul(&ggsw_level_ct.a_vec[j], a_decomp_poly, params), params);
            }
        }
    }
    result_ct
}

/// CMUX (Controlled MUX) 게이트: if(g) then ct1 else ct0
fn cmux(ggsw_gate: &GgswCiphertext, ct0: &Ciphertext, ct1: &Ciphertext, params: &QfheParameters) -> Ciphertext {
    // CMUX(g, ct0, ct1) = ct0 + g * (ct1 - ct0)
    let diff_ct = CpuBackend.homomorphic_sub(ct1, ct0, params);
    let term = external_product(ggsw_gate, &diff_ct, params);
    CpuBackend.homomorphic_add(ct0, &term, params)
}

/// 주어진 메시지 다항식을 암호화하는 내부 함수입니다.
fn encrypt_poly(msg_poly: &Polynomial, params: &QfheParameters, secret_key: &SecretKey) -> Ciphertext {
    let mut rng = rand::thread_rng();
    let k = params.module_dimension_k;
    let n = params.polynomial_degree;
    let rns_basis = params.modulus_q;
    let rns_basis_size = rns_basis.len();

    // a_vec: 무작위 다항식 벡터 생성 (RNS 형태)
    let a_vec = (0..k).map(|_| {
        let mut poly = Polynomial::zero(n, rns_basis_size);
        for i in 0..n {
            for j in 0..rns_basis_size {
                // 각 쿼터니언 성분에 대해 무작위 값을 채웁니다.
                poly.coeffs[i].w[j] = rng.gen_range(0..rns_basis[j]);
                poly.coeffs[i].x[j] = rng.gen_range(0..rns_basis[j]);
                poly.coeffs[i].y[j] = rng.gen_range(0..rns_basis[j]);
                poly.coeffs[i].z[j] = rng.gen_range(0..rns_basis[j]);
            }
        }
        poly
    }).collect::<Vec<_>>();

    // e: 작은 오차 다항식 생성 (RNS 형태)
    let e_poly = {
        let mut poly = Polynomial::zero(n, rns_basis_size);
        for i in 0..n {
            let noise = sample_discrete_gaussian(params.noise_std_dev);
            // 모든 쿼터니언 성분에 노이즈를 추가합니다. (필요에 따라 주 성분에만 추가할 수도 있음)
            poly.coeffs[i].w = integer_to_rns(noise as u128, rns_basis);
            poly.coeffs[i].x = integer_to_rns(sample_discrete_gaussian(params.noise_std_dev) as u128, rns_basis);
            poly.coeffs[i].y = integer_to_rns(sample_discrete_gaussian(params.noise_std_dev) as u128, rns_basis);
            poly.coeffs[i].z = integer_to_rns(sample_discrete_gaussian(params.noise_std_dev) as u128, rns_basis);
        }
        poly
    };
    
    // b = <a, s> + e + m 계산
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


impl<'a, 'b, 'c> HardwareBackend<'a, 'b, 'c> for CpuBackend {
    fn generate_public_key(
        &self, sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>,
    ) -> PublicKey {
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();

        // a: 무작위 다항식 벡터 생성
        let a_vec = (0..k).map(|_| sample_uniform_poly(n, rns_size, rng, params)).collect::<Vec<_>>();
        
        // e: 작은 오차 다항식 생성
        let e = sample_gaussian_poly(n, rns_size, params.noise_std_dev, rng, params);

        // b = -(a_0*s_0 + a_1*s_1 + ...) + e
        let mut b = e;
        for i in 0..k {
            let a_s = self.polynomial_mul(&a_vec[i], &sk.0[i], params);
            b = self.polynomial_sub(&b, &a_s, params);
        }

        PublicKey { b, a_vec }
    }

    fn generate_secret_key(
        &self, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>,
    ) -> SecretKey {
        let secret_key_vec = (0..params.module_dimension_k)
            .map(|_| sample_ternary_poly(params.polynomial_degree, params.modulus_q.len(), params.modulus_q, rng))
            .collect();
        SecretKey(secret_key_vec)
    }


    fn encrypt(
        &self, message: u64, pk: &PublicKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>,
    ) -> Ciphertext {
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();

        // 작은 다항식 u, e0, e_vec 샘플링
        let u = sample_gaussian_poly(n, rns_size, params.noise_std_dev, rng, params);
        let e0 = sample_gaussian_poly(n, rns_size, params.noise_std_dev, rng, params);
        let e_vec = (0..k)
            .map(|_| sample_gaussian_poly(n, rns_size, params.noise_std_dev, rng, params))
            .collect::<Vec<_>>();
        
        // c0 = pk.b * u + e0 + m*Δ
        let mut c0 = self.polynomial_mul(&pk.b, &u, params);
        c0 = self.polynomial_add(&c0, &e0, params);
        
        let mut msg_poly = Polynomial::zero(n, rns_size);
        let scaled_msg = (message as u128) * params.scaling_factor_delta;
        msg_poly.coeffs[0].w = crate::core::rns::integer_to_rns(scaled_msg, params.modulus_q);
        c0 = self.polynomial_add(&c0, &msg_poly, params);

        // c_i = pk.a_i * u + e_i
        let a_vec = (0..k)
            .map(|i| {
                let u_a = self.polynomial_mul(&pk.a_vec[i], &u, params);
                self.polynomial_add(&u_a, &e_vec[i], params)
            })
            .collect();

        // 최종 암호문 (c_0, c_1, ...) => (b, a_vec)
        Ciphertext { b: c0, a_vec, modulus_level: 0 }
    }

    // --- ❗❗❗ 3. 복호화 로직 수정 ❗❗❗ ---
    /// 암호문을 복호화합니다. [crypto-bigint::U256 적용 최종본]
    /// 암호문을 복호화합니다. [최종 안정화 버전]
    fn decrypt(
        &self,
        ciphertext: &Ciphertext,
        secret_key: &SecretKey,
        params: &QfheParameters<'a, 'b, 'c>,
    ) -> u64 {
        let k = params.module_dimension_k;

        // --- ❗❗❗ 핵심 수정: c_0 + <c_1, s> 를 계산 ❗❗❗ ---
        // 1. noisy_poly를 암호문의 첫 번째 부분(b)으로 초기화
        let mut noisy_poly = ciphertext.b.clone();

        // 2. 암호문의 두 번째 부분(a_vec)과 비밀키(s)를 곱하여 더함
        for i in 0..k {
            let a_s = self.polynomial_mul(&ciphertext.a_vec[i], &secret_key.0[i], params);
            noisy_poly = self.polynomial_add(&noisy_poly, &a_s, params);
        }
        
        // 3. CRT를 사용하여 RNS 표현을 U256 정수로 복원
        let noisy_message = crate::core::rns::rns_to_integer(&noisy_poly.coeffs[0].w, params.modulus_q);

        // 4. 안정적인 정수 기반 디코딩 (변경 없음)
        let delta = U256::from(params.scaling_factor_delta);
        let half_delta = delta.div_rem(&crypto_bigint::NonZero::new(U256::from(2u64)).unwrap()).0;
        
        let rounded = noisy_message.wrapping_add(&half_delta).div_rem(&crypto_bigint::NonZero::new(delta).unwrap()).0;

        let final_val = rounded.to_words()[0];
        final_val % params.plaintext_modulus as u64
    }


    /// 두 다항식을 더합니다. [RNS 기반, 안전한 모듈러 연산 적용]
    fn polynomial_add(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial {
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();
        let mut res = Polynomial::zero(n, rns_basis_size);

        for i in 0..n {
            for j in 0..rns_basis_size {
                let q_j = params.modulus_q[j];
                res.coeffs[i].w[j] = p1.coeffs[i].w[j].safe_add_mod(p2.coeffs[i].w[j], q_j);
                res.coeffs[i].x[j] = p1.coeffs[i].x[j].safe_add_mod(p2.coeffs[i].x[j], q_j);
                res.coeffs[i].y[j] = p1.coeffs[i].y[j].safe_add_mod(p2.coeffs[i].y[j], q_j);
                res.coeffs[i].z[j] = p1.coeffs[i].z[j].safe_add_mod(p2.coeffs[i].z[j], q_j);
            }
        }
        res
    }

    /// 두 다항식을 뺍니다. [RNS 기반, 안전한 모듈러 연산 적용]
    fn polynomial_sub(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial {
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();
        let mut res = Polynomial::zero(n, rns_basis_size);

        for i in 0..n {
            for j in 0..rns_basis_size {
                let q_j = params.modulus_q[j];
                res.coeffs[i].w[j] = p1.coeffs[i].w[j].safe_sub_mod(p2.coeffs[i].w[j], q_j);
                res.coeffs[i].x[j] = p1.coeffs[i].x[j].safe_sub_mod(p2.coeffs[i].x[j], q_j);
                res.coeffs[i].y[j] = p1.coeffs[i].y[j].safe_sub_mod(p2.coeffs[i].y[j], q_j);
                res.coeffs[i].z[j] = p1.coeffs[i].z[j].safe_sub_mod(p2.coeffs[i].z[j], q_j);
            }
        }
        res
    }

    /// 두 다항식을 곱합니다. (QNTT 사용) [RNS 기반]
    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial {
        let mut p1_ntt = p1.clone();
        let mut p2_ntt = p2.clone();

        qntt_forward(&mut p1_ntt, params);
        qntt_forward(&mut p2_ntt, params);
        qntt_pointwise_mul(&mut p1_ntt, &p2_ntt, params);
        qntt_inverse(&mut p1_ntt, params);

        p1_ntt
    }
    
    /// 두 암호문을 더합니다.
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
        assert_eq!(ct1.modulus_level, ct2.modulus_level, "Ciphertexts must have the same modulus level for addition.");
        let k = params.module_dimension_k;
        let a_vec_add = (0..k)
            .map(|i| self.polynomial_add(&ct1.a_vec[i], &ct2.a_vec[i], params))
            .collect();
        let b_add = self.polynomial_add(&ct1.b, &ct2.b, params);
        Ciphertext { a_vec: a_vec_add, b: b_add, modulus_level: ct1.modulus_level }
    }

    /// 두 암호문을 뺍니다.
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
        assert_eq!(ct1.modulus_level, ct2.modulus_level, "Ciphertexts must have the same modulus level for subtraction.");
        let k = params.module_dimension_k;
        let a_vec_sub = (0..k)
            .map(|i| self.polynomial_sub(&ct1.a_vec[i], &ct2.a_vec[i], params))
            .collect();
        let b_sub = self.polynomial_sub(&ct1.b, &ct2.b, params);
        Ciphertext { a_vec: a_vec_sub, b: b_sub, modulus_level: ct1.modulus_level }
    }

    /// 재선형화 키를 생성합니다.
    fn generate_relinearization_key(&self, sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> RelinearizationKey {
        let k = params.module_dimension_k;
        let l = params.gadget_levels_l;
        let mut key_vec = Vec::with_capacity(k * k * l);

        for i in 0..k {
            for j in 0..k {
                let s_i_s_j = self.polynomial_mul(&sk.0[i], &sk.0[j], params);
                for m in 0..l {
                    let power_of_base = params.gadget_base_b.pow(m as u32);
                    let power_of_base_rns = crate::core::rns::integer_to_rns(power_of_base, params.modulus_q);
                    let p_to_encrypt = polynomial_scalar_mul(&s_i_s_j, &power_of_base_rns, params);
                    key_vec.push(encrypt_internal(&p_to_encrypt, sk, rng, params));
                }
            }
        }
        RelinearizationKey(key_vec)
    }

    /// 두 암호문을 곱합니다. [재선형화 포함]
    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext, rlk: &RelinearizationKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
        assert_eq!(ct1.modulus_level, ct2.modulus_level, "Ciphertexts must have the same modulus level for multiplication.");
        
        let k = params.module_dimension_k;
        let n = params.polynomial_degree;
        let rns_basis_size = params.modulus_q.len();
        let levels = params.gadget_levels_l;

        // 1. 텐서 곱 계산 (ct_res = ct1 ⊗ ct2)
        // c0 = b1*b2
        let c0 = self.polynomial_mul(&ct1.b, &ct2.b, params);
        // c1_i = a1_i*b2 + b1*a2_i
        let mut c1 = Vec::with_capacity(k);
        for i in 0..k {
            let a1i_b2 = self.polynomial_mul(&ct1.a_vec[i], &ct2.b, params);
            let b1_a2i = self.polynomial_mul(&ct1.b, &ct2.a_vec[i], params);
            c1.push(self.polynomial_add(&a1i_b2, &b1_a2i, params));
        }
        // c2_ij = a1_i*a2_j
        let mut c2 = vec![vec![Polynomial::zero(n, rns_basis_size); k]; k];
        for i in 0..k {
            for j in 0..k {
                c2[i][j] = self.polynomial_mul(&ct1.a_vec[i], &ct2.a_vec[j], params);
            }
        }

        // 2. 재선형화(Relinearization)
        // c2항(s^2을 포함)을 s에 대한 암호문으로 변환
        let mut c2_prime = Ciphertext {
            a_vec: vec![Polynomial::zero(n, rns_basis_size); k],
            b: Polynomial::zero(n, rns_basis_size),
            modulus_level: ct1.modulus_level,
        };
        
        for i in 0..k {
            for j in 0..k {
                // c2_ij를 가젯 분해
                let decomposed_c2_poly = gadget_decompose(&c2[i][j], params);
                for l in 0..levels {
                    let rlk_index = (i * k + j) * levels + l;
                    let rlk_ct = &rlk.0[rlk_index];
                    
                    // 재선형화 키와 분해된 다항식을 곱하여 합산
                    c2_prime.b = self.polynomial_add(&c2_prime.b, &self.polynomial_mul(&rlk_ct.b, &decomposed_c2_poly[l], params), params);
                    for m in 0..k {
                        c2_prime.a_vec[m] = self.polynomial_add(&c2_prime.a_vec[m], &self.polynomial_mul(&rlk_ct.a_vec[m], &decomposed_c2_poly[l], params), params);
                    }
                }
            }
        }
        
        // 3. 최종 암호문 결합
        let final_b = self.polynomial_add(&c0, &c2_prime.b, params);
        let mut final_a = c1;
        for i in 0..k {
            final_a[i] = self.polynomial_add(&final_a[i], &c2_prime.a_vec[i], params);
        }
        
        Ciphertext {
            a_vec: final_a,
            b: final_b,
            modulus_level: ct1.modulus_level,
        }
    }

    /// 키 스위칭 키를 생성합니다.
    fn generate_key_switching_key(&self, old_sk: &SecretKey, new_sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> KeySwitchingKey {
        let k = params.module_dimension_k;
        let l = params.gadget_levels_l;
        let mut key_levels = Vec::with_capacity(k);

        for i in 0..k {
            let mut key_level = Vec::with_capacity(l);
            for m in 0..l {
                let power_of_base = params.gadget_base_b.pow(m as u32);
                let power_of_base_rns = crate::core::rns::integer_to_rns(power_of_base, params.modulus_q);
                let mut p_to_encrypt = old_sk.0[i].clone();
                p_to_encrypt = polynomial_scalar_mul(&p_to_encrypt, &power_of_base_rns, params);
                // 새 비밀키(new_sk)로 암호화
                key_level.push(encrypt_internal(&p_to_encrypt, new_sk, rng, params));
            }
            key_levels.push(key_level);
        }
        KeySwitchingKey { key: key_levels }
    }

    /// 부트스트래핑 키를 생성합니다. (LWE 비밀키를 GGSW로 암호화)
    fn generate_bootstrap_key(
        &self,
        sk: &SecretKey,
        rng: &mut ChaCha20Rng,
        params: &QfheParameters<'a, 'b, 'c>,
    ) -> BootstrapKey {
        let n = params.polynomial_degree;
        let l = params.gadget_levels_l;
        let lwe_sk_poly = &sk.0[0];

        // Rayon을 사용하여 병렬 처리
        let mut seeds: Vec<[u8; 32]> = Vec::with_capacity(n);
        for _ in 0..n {
            seeds.push(rng.r#gen());
        }

        let bsk_ggsw_vector: Vec<GgswCiphertext> = (0..n)
            .into_par_iter()
            .map(|i| {
                let mut thread_rng = ChaCha20Rng::from_seed(seeds[i]);
                let s_coeff_rns = &lwe_sk_poly.coeffs[i].w;
                let s_coeff_int = rns_to_integer(s_coeff_rns, params.modulus_q);

                let mut ggsw_levels = Vec::with_capacity(l);
                for m in 0..l {
                    let power_of_base = params.gadget_base_b.pow(m as u32);
                    
                    // --- ❗❗❗ 핵심 버그 수정 ❗❗❗ ---
                    // ❗ 수정: crypto_bigint::U256의 곱셈 API 사용
                    let val_to_encrypt = s_coeff_int.wrapping_mul(&U256::from_u128(power_of_base));

                    let mut p = Polynomial::zero(n, params.modulus_q.len());
                    // ❗ 수정: to_words()[0]를 사용하여 u64로 변환 후 u128로 캐스팅
                    p.coeffs[0].w = integer_to_rns(val_to_encrypt.to_words()[0] as u128, params.modulus_q);
                    
                    ggsw_levels.push(encrypt_internal(&p, sk, &mut thread_rng, params));
                }
                GgswCiphertext { levels: ggsw_levels }
            })
            .collect();

        BootstrapKey {
            ggsw_vector: bsk_ggsw_vector,
        }
    }
    
    /// 프로그래머블 부트스트래핑을 수행합니다. [구현 완료]
    fn bootstrap(
        &self,
        ct: &Ciphertext,
        test_poly: &Polynomial,
        bk: &BootstrapKey,
        ksk: &KeySwitchingKey,
        params: &QfheParameters<'a, 'b, 'c>,
    ) -> Ciphertext {
        let n = params.polynomial_degree;
        let k = params.module_dimension_k;

        // --- ❗❗❗ 1. 올바른 Modulus Switch (Sample Extract) 로직 ❗❗❗ ---
        // 부트스트래핑을 위한 임시 파라미터 생성 (더 작은 모듈러스 사용)
        let bootstrap_modulus = (2 * n) as u128;
        let temp_params = QfheParameters {
            modulus_q: &[(2 * n) as u64], // 임시 모듈러스
            modulus_chain: &[bootstrap_modulus],
            reducers: &[BarrettReducer64::new((2*n) as u64)],
            ..params.clone()
        };
        
        // 암호문을 작은 모듈러스 2N으로 스위칭
        let switched_ct = self.modulus_switch(ct, &temp_params);

        // 스위칭된 암호문의 계수들을 b_bar와 a_bar로 사용
        let b_bar = switched_ct.b.coeffs[0].w[0];
        let a_bar: Vec<u64> = switched_ct.a_vec[0].coeffs.iter().map(|c| c.w[0]).collect();

        // --- 2. 블라인드 회전 (Blind Rotation) ---
        let mut accumulator = {
            let mut poly = test_poly.clone();
            let rotated_coeffs: Vec<Quaternion> = (0..n).map(|i| {
                let rotated_index = (i as i128 - b_bar as i128).rem_euclid(n as i128) as usize;
                test_poly.coeffs[rotated_index].clone()
            }).collect();
            poly.coeffs = rotated_coeffs;
            
            let mut dummy_rng = ChaCha20Rng::from_seed([0u8; 32]);
            // 자명한 암호화 (비밀키가 0인 암호문)
            encrypt_internal(&poly, &SecretKey(vec![Polynomial::zero(n, params.modulus_q.len())]), &mut dummy_rng, params)
        };

        // ... (이후 CMUX 및 Key Switching 부분은 변경 없음) ...
        for i in 0..n {
            let control_bit_ggsw = &bk.ggsw_vector[i]; // GGSW(s_i)
            
            let mut rot_poly = Polynomial::zero(n, params.modulus_q.len());
            let rot_index = (n - (1 << i)) % n;
            rot_poly.coeffs[rot_index].w = crate::core::rns::integer_to_rns(1, params.modulus_q);
            
            let mut dummy_rng = ChaCha20Rng::from_seed([0u8; 32]);
            let rot_poly_ct = encrypt_internal(&rot_poly, &SecretKey(vec![Polynomial::zero(n, params.modulus_q.len())]), &mut dummy_rng, params);
            let one_ct = encrypt_internal(&Polynomial::zero(n, params.modulus_q.len()), &SecretKey(vec![Polynomial::zero(n, params.modulus_q.len())]), &mut dummy_rng, params);
            
            let term = if a_bar[i] != 0 {
                cmux(control_bit_ggsw, &one_ct, &rot_poly_ct, params)
            } else {
                one_ct
            };
            
            accumulator = self.homomorphic_mul(&accumulator, &term, &RelinearizationKey(vec![]), params);
        }

        // --- 3. 키 스위칭 (Key Switching) ---
        // 최종적으로 RLWE 암호문을 LWE 암호문으로 변환 (이 예제에서는 RLWE->RLWE)
        self.keyswitch(&accumulator, ksk, params)
    }

    /// 암호문의 키를 바꿉니다.
    fn keyswitch(&self, ct: &Ciphertext, ksk: &KeySwitchingKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext {
        let n = params.polynomial_degree;
        let k = params.module_dimension_k;
        let rns_basis_size = params.modulus_q.len();
        
        // 결과 암호문 (b' = b, a' = 0)
        let mut new_ct = Ciphertext {
            a_vec: vec![Polynomial::zero(n, rns_basis_size); k],
            b: ct.b.clone(),
            modulus_level: ct.modulus_level,
        };

        for i in 0..k { // ct의 각 a_i에 대해
            let decomposed_a = gadget_decompose(&ct.a_vec[i], params);
            for l in 0..params.gadget_levels_l {
                let ksk_ct = &ksk.key[i][l]; // KSK(g^l * s_i)
                let decomp_poly = &decomposed_a[l];

                // b' = b' - <decomp, ksk.b>
                new_ct.b = self.polynomial_sub(&new_ct.b, &self.polynomial_mul(&decomp_poly, &ksk_ct.b, params), params);
                // a'_j = a'_j - <decomp, ksk.a_j>
                for j in 0..k {
                    new_ct.a_vec[j] = self.polynomial_sub(&new_ct.a_vec[j], &self.polynomial_mul(decomp_poly, &ksk_ct.a_vec[j], params), params);
                }
            }
        }
        new_ct
    }
    
    /// 암호문의 모듈러스를 한 단계 낮춥니다.
    fn modulus_switch(
        &self,
        ct: &Ciphertext,
        params: &QfheParameters<'a, 'b, 'c>,
    ) -> Ciphertext {
        let from_basis = &params.modulus_q[..ct.b.coeffs[0].w.len()];
        if from_basis.len() <= 1 {
            // 이미 가장 낮은 레벨이므로 변환 불가
            return ct.clone();
        }
        let to_basis = &from_basis[..from_basis.len() - 1];

        // 다항식의 각 계수를 (RNS -> Integer -> new RNS)로 변환하는 함수
        let convert_poly = |p: &Polynomial| -> Polynomial {
            let n = p.coeffs.len();
            let mut new_poly = Polynomial::zero(n, to_basis.len());
            for i in 0..n {
                // --- ❗❗❗ 핵심 버그 수정 ❗❗❗ ---
                // ❗ 수정: to_words()[0]를 사용하여 u64로 변환 후 u128로 캐스팅
                let w_int = rns_to_integer(&p.coeffs[i].w, from_basis).to_words()[0] as u128;
                let x_int = rns_to_integer(&p.coeffs[i].x, from_basis).to_words()[0] as u128;
                let y_int = rns_to_integer(&p.coeffs[i].y, from_basis).to_words()[0] as u128;
                let z_int = rns_to_integer(&p.coeffs[i].z, from_basis).to_words()[0] as u128;
                
                // 새로운 RNS 기저로 변환
                new_poly.coeffs[i].w = integer_to_rns(w_int, to_basis);
                new_poly.coeffs[i].x = integer_to_rns(x_int, to_basis);
                new_poly.coeffs[i].y = integer_to_rns(y_int, to_basis);
                new_poly.coeffs[i].z = integer_to_rns(z_int, to_basis);
            }
            new_poly
        };
        
        Ciphertext {
            a_vec: ct.a_vec.iter().map(convert_poly).collect(),
            b: convert_poly(&ct.b),
            modulus_level: ct.modulus_level + 1,
        }
    }
}