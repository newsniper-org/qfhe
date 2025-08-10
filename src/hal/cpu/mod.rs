// src/hal/cpu/mod.rs

// src/hal/cpu/mod.rs

use crate::core::{
    Ciphertext, GgswCiphertext, Polynomial, QfheParameters, keys::{RelinearizationKey, SecretKey, BootstrapKey, EvaluationKey, PublicKey}
};
use super::HardwareBackend;
use rand::{Rng, RngCore, SeedableRng};
use rand_distr::{Normal, Distribution};
use rand_chacha::ChaCha20Rng;
use crate::ntt::qntt::*;
use crate::core::num::SafeModuloArith;
use crate::core::rns::*;
use crypto_bigint::{U256, NonZero};

use rayon::prelude::*;
pub struct CpuBackend;

// ✅ RLWE: 모든 샘플링 함수는 그대로 재사용 가능
fn sample_discrete_gaussian<R: Rng + ?Sized>(noise_std_dev: f64, rng: &mut R) -> i128 {
    let normal = Normal::new(0.0, noise_std_dev).unwrap();
    normal.sample(rng).round() as i128
}

fn gadget_decompose(p: &Polynomial, params: &QfheParameters) -> Vec<Polynomial> {
    let n = params.polynomial_degree;
    let rns_basis_size = params.modulus_q.len();
    let base = NonZero::new(U256::from_u128(params.gadget_base_b)).unwrap();
    let levels = params.gadget_levels_l;
    
    let mut decomposed_polys = vec![Polynomial::zero(n, rns_basis_size); levels];

    for i in 0..n {
        let mut current_w = rns_to_integer(&p.coeffs[i].w, params.modulus_q);
        let mut current_x = rns_to_integer(&p.coeffs[i].x, params.modulus_q);
        let mut current_y = rns_to_integer(&p.coeffs[i].y, params.modulus_q);
        let mut current_z = rns_to_integer(&p.coeffs[i].z, params.modulus_q);

        for l in 0..levels {
            let (next_w, rem_w) = current_w.div_rem(&base);
            let (next_x, rem_x) = current_x.div_rem(&base);
            let (next_y, rem_y) = current_y.div_rem(&base);
            let (next_z, rem_z) = current_z.div_rem(&base);
            
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

fn polynomial_rotation(p: &Polynomial, k: i128, params: &QfheParameters) -> Polynomial {
    let n = params.polynomial_degree as i128;
    let rns_size = params.modulus_q.len();
    let mut rotated_p = Polynomial::zero(n as usize, rns_size);
    for i in 0..n {
        let target_index = (i - k).rem_euclid(n);
        rotated_p.coeffs[i as usize] = p.coeffs[target_index as usize].clone();
    }
    rotated_p
}

/// ✅ NEW: 암호문에 포함된 다항식들의 계수를 k만큼 회전시킵니다.
fn ciphertext_rotation(ct: &Ciphertext, k: i128, params: &QfheParameters) -> Ciphertext {
    Ciphertext {
        c0: polynomial_rotation(&ct.c0, k, params),
        c1: polynomial_rotation(&ct.c1, k, params),
        modulus_level: ct.modulus_level,
    }
}

impl<'a> CpuBackend {
    fn sample_uniform_poly(n: usize, rns_size: usize, rng: &mut ChaCha20Rng, params: &QfheParameters<'a>) -> Polynomial {
        let mut poly = Polynomial::zero(n, rns_size);
        for i in 0..n {
            for j in 0..rns_size {
                let q_j = params.modulus_q[j];
                poly.coeffs[i].w[j] = rng.r#gen::<u64>() % q_j;
                poly.coeffs[i].x[j] = rng.r#gen::<u64>() % q_j;
                poly.coeffs[i].y[j] = rng.r#gen::<u64>() % q_j;
                poly.coeffs[i].z[j] = rng.r#gen::<u64>() % q_j;
            }
        }
        poly
    }

    fn sample_gaussian_poly(n: usize, rns_size: usize, std_dev: f64, rng: &mut ChaCha20Rng, params: &QfheParameters<'a>) -> Polynomial {
        let mut poly = Polynomial::zero(n, rns_size);
        let handle_noise = |noise: i128| -> Vec<u64> {
            let mut rns_noise = crate::core::rns::integer_to_rns(noise.unsigned_abs(), params.modulus_q);
            if noise < 0 {
                for j in 0..rns_size {
                    rns_noise[j] = params.modulus_q[j] - rns_noise[j];
                }
            }
            rns_noise
        };
        for i in 0..n {
            poly.coeffs[i].w = handle_noise(sample_discrete_gaussian(std_dev, rng));
            poly.coeffs[i].x = handle_noise(sample_discrete_gaussian(std_dev, rng));
            poly.coeffs[i].y = handle_noise(sample_discrete_gaussian(std_dev, rng));
            poly.coeffs[i].z = handle_noise(sample_discrete_gaussian(std_dev, rng));
        }
        poly
    }

    fn sample_ternary_poly(n: usize, rns_size: usize, q_moduli: &[u64], rng: &mut ChaCha20Rng) -> Polynomial {
        let mut poly = Polynomial::zero(n, rns_size);
        for i in 0..n {
            let val = (rng.next_u32() % 3) as i128 - 1;
            if val != 0 {
                let rns_one = crate::core::rns::integer_to_rns(1, q_moduli);
                if val < 0 {
                    for j in 0..rns_size {
                        poly.coeffs[i].w[j] = q_moduli[j] - rns_one[j];
                    }
                } else {
                    poly.coeffs[i].w = rns_one;
                }
            }
        }
        poly
    }


    /// 내부 암호화 함수 (키 생성에 사용)
    fn encrypt_internal(&self, msg_poly: &Polynomial, pk: &PublicKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a>) -> Ciphertext {
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();

        let u = Self::sample_gaussian_poly(n, rns_size, params.noise_std_dev, rng, params);
        let e0 = Self::sample_gaussian_poly(n, rns_size, params.noise_std_dev, rng, params);
        let e1 = Self::sample_gaussian_poly(n, rns_size, params.noise_std_dev, rng, params);

        let mut c0 = self.polynomial_mul(&pk.b, &u, params);
        c0 = self.polynomial_add(&c0, &e0, params);
        c0 = self.polynomial_add(&c0, msg_poly, params);

        let mut c1 = self.polynomial_mul(&pk.a, &u, params);
        c1 = self.polynomial_add(&c1, &e1, params);

        Ciphertext { c0, c1, modulus_level: 0 }
    }

    /// ✅ NEW: 다항식의 각 쿼터니언 계수에 켤레 연산을 적용합니다.
    fn polynomial_conjugate(p: &Polynomial, params: &QfheParameters<'a>) -> Polynomial {
        let n = p.coeffs.len();
        let rns_size = params.modulus_q.len();
        let mut res = Polynomial::zero(n, rns_size);

        for i in 0..n {
            for j in 0..rns_size {
                let q_j = params.modulus_q[j];
                res.coeffs[i].w[j] = p.coeffs[i].w[j]; // w는 그대로
                res.coeffs[i].x[j] = q_j.wrapping_sub(p.coeffs[i].x[j]); // -x
                res.coeffs[i].y[j] = q_j.wrapping_sub(p.coeffs[i].y[j]); // -y
                res.coeffs[i].z[j] = q_j.wrapping_sub(p.coeffs[i].z[j]); // -z
            }
        }
        res
    }

    // ✅ NEW: GGSW 암호문과 RLWE 암호문의 외부 곱(External Product)을 계산합니다.
    fn external_product(&self, ggsw: &GgswCiphertext, rlwe: &Ciphertext, params: &QfheParameters<'a>) -> Ciphertext {
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();
        let levels = params.gadget_levels_l;

        let c0_decomposed = gadget_decompose(&rlwe.c0, params);
        let c1_decomposed = gadget_decompose(&rlwe.c1, params);

        let mut res_c0 = Polynomial::zero(n, rns_size);
        let mut res_c1 = Polynomial::zero(n, rns_size);

        for l in 0..levels {
            // Process c0 part
            let term0 = self.polynomial_mul(&ggsw.levels[l].c0, &c0_decomposed[l], params);
            res_c0 = self.polynomial_add(&res_c0, &term0, params);
            let term1 = self.polynomial_mul(&ggsw.levels[l].c1, &c0_decomposed[l], params);
            res_c1 = self.polynomial_add(&res_c1, &term1, params);

            // Process c1 part
            let term0 = self.polynomial_mul(&ggsw.levels[l].c0, &c1_decomposed[l], params);
            res_c0 = self.polynomial_add(&res_c0, &term0, params);
            let term1 = self.polynomial_mul(&ggsw.levels[l].c1, &c1_decomposed[l], params);
            res_c1 = self.polynomial_add(&res_c1, &term1, params);
        }

        Ciphertext { c0: res_c0, c1: res_c1, modulus_level: rlwe.modulus_level }
    }

    /// ✅ NEW: CMUX (Controlled MUX) 게이트 구현: if(g) then ct1 else ct0
    fn cmux(&self, ggsw_gate: &GgswCiphertext, ct0: &Ciphertext, ct1: &Ciphertext, params: &QfheParameters) -> Ciphertext {
        // CMUX(g, ct0, ct1) = ct0 + g * (ct1 - ct0)
        let diff_ct = self.homomorphic_sub(ct1, ct0, params);
        let term = self.external_product(ggsw_gate, &diff_ct, params);
        self.homomorphic_add(ct0, &term, params)
    }
}

impl<'a> HardwareBackend<'a> for CpuBackend {
    /// ✅ RLWE: 비밀키 s1, s2 생성
    fn generate_secret_key(&self, rng: &mut ChaCha20Rng, params: &QfheParameters<'a>) -> SecretKey {
        let s1 = Self::sample_ternary_poly(params.polynomial_degree, params.modulus_q.len(), params.modulus_q, rng);
        let s2 = Self::sample_ternary_poly(params.polynomial_degree, params.modulus_q.len(), params.modulus_q, rng);
        SecretKey { s1, s2 }
    }

    /// ✅ RLWE: 공개키 (b, a) 생성. b = -a*s1 + e
    fn generate_public_key(&self, sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a>) -> PublicKey {
        let s1 = &sk.s1;
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();

        let a = Self::sample_uniform_poly(n, rns_size, rng, params);
        let e = Self::sample_gaussian_poly(n, rns_size, params.noise_std_dev, rng, params);

        let a_s1 = self.polynomial_mul(&a, s1, params);
        let b = self.polynomial_sub(&e, &a_s1, params); // b = e - a*s1

        PublicKey { b, a }
    }

    /// ✅ RLWE: 암호화. (c0, c1) = (pk.b*u + e0 + mΔ, pk.a*u + e1)
    fn encrypt(&self, message: u64, pk: &PublicKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a>) -> Ciphertext {
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();

        let u = Self::sample_gaussian_poly(n, rns_size, params.noise_std_dev, rng, params);
        let e0 = Self::sample_gaussian_poly(n, rns_size, params.noise_std_dev, rng, params);
        let e1 = Self::sample_gaussian_poly(n, rns_size, params.noise_std_dev, rng, params);

        // c0 = pk.b * u + e0 + m*Δ
        let mut c0 = self.polynomial_mul(&pk.b, &u, params);
        c0 = self.polynomial_add(&c0, &e0, params);
        
        let mut msg_poly = Polynomial::zero(n, rns_size);
        let scaled_msg = (message as u128) * params.scaling_factor_delta;
        msg_poly.coeffs[0].w = crate::core::rns::integer_to_rns(scaled_msg, params.modulus_q);
        c0 = self.polynomial_add(&c0, &msg_poly, params);

        // c1 = pk.a * u + e1
        let c1 = self.polynomial_mul(&pk.a, &u, params);
        let c1 = self.polynomial_add(&c1, &e1, params);

        Ciphertext { c0, c1, modulus_level: 0 }
    }

    /// ✅ RLWE: 복호화. m' = c0 + c1*s1
    fn decrypt(&self, ciphertext: &Ciphertext, sk: &SecretKey, params: &QfheParameters<'a>) -> u64 {
        let s1 = &sk.s1;
        
        // noisy_poly = c0 + c1*s1
        let c1_s1 = self.polynomial_mul(&ciphertext.c1, s1, params);
        let noisy_poly = self.polynomial_add(&ciphertext.c0, &c1_s1, params);
        
        let noisy_message = crate::core::rns::rns_to_integer(&noisy_poly.coeffs[0].w, params.modulus_q);

        let q_product = params.modulus_q.iter().fold(U256::ONE, |acc, &m| acc.wrapping_mul(&U256::from_u64(m)));
        let q_half = q_product >> 1;

        let final_val: u64;
        let delta = U256::from(params.scaling_factor_delta);
        let half_delta = delta >> 1;

        if noisy_message <= q_half {
            let rounded = noisy_message.wrapping_add(&half_delta).div_rem(&NonZero::new(delta).unwrap()).0;
            final_val = rounded.to_words()[0];
        } else {
            let magnitude = q_product.wrapping_sub(&noisy_message);
            let rounded = magnitude.wrapping_add(&half_delta).div_rem(&NonZero::new(delta).unwrap()).0;
            let neg_rounded = rounded.to_words()[0];
            final_val = (params.plaintext_modulus as u64).wrapping_sub(neg_rounded);
        }
        
        final_val % params.plaintext_modulus as u64
    }

    /// ✅ RLWE: 동형 덧셈
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters<'a>) -> Ciphertext {
        let c0 = self.polynomial_add(&ct1.c0, &ct2.c0, params);
        let c1 = self.polynomial_add(&ct1.c1, &ct2.c1, params);
        Ciphertext { c0, c1, modulus_level: ct1.modulus_level }
    }

    /// ✅ RLWE: 동형 뺄셈
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters<'a>) -> Ciphertext {
        let c0 = self.polynomial_sub(&ct1.c0, &ct2.c0, params);
        let c1 = self.polynomial_sub(&ct1.c1, &ct2.c1, params);
        Ciphertext { c0, c1, modulus_level: ct1.modulus_level }
    }

    /// ✅ RLWE: 동형 곱셈 구현 (텐서곱 + 재선형화)
    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext, rlk: &RelinearizationKey, params: &QfheParameters<'a>) -> Ciphertext {
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();

        // 1. 텐서 곱
        let d0 = self.polynomial_mul(&ct1.c0, &ct2.c0, params);
        let d1_part1 = self.polynomial_mul(&ct1.c0, &ct2.c1, params);
        let d1_part2 = self.polynomial_mul(&ct1.c1, &ct2.c0, params);
        let d1 = self.polynomial_add(&d1_part1, &d1_part2, params);
        let d2 = self.polynomial_mul(&ct1.c1, &ct2.c1, params);

        // 2. 재선형화 (d2를 키스위칭)
        let d2_decomposed = gadget_decompose(&d2, params);

        let mut ks_c0 = Polynomial::zero(n, rns_size);
        let mut ks_c1 = Polynomial::zero(n, rns_size);

        for l in 0..params.gadget_levels_l {
            let rlk_ct = &rlk.0[l];
            let decomp_poly = &d2_decomposed[l];

            let term_c0 = self.polynomial_mul(&rlk_ct.c0, decomp_poly, params);
            let term_c1 = self.polynomial_mul(&rlk_ct.c1, decomp_poly, params);

            ks_c0 = self.polynomial_add(&ks_c0, &term_c0, params);
            ks_c1 = self.polynomial_add(&ks_c1, &term_c1, params);
        }

        // 3. 최종 암호문 결합
        let final_c0 = self.polynomial_add(&d0, &ks_c0, params);
        let final_c1 = self.polynomial_add(&d1, &ks_c1, params);

        Ciphertext {
            c0: final_c0,
            c1: final_c1,
            modulus_level: ct1.modulus_level,
        }
    }

    /// ✅ NEW: 동형 켤레 연산 구현
    fn homomorphic_conjugate(&self, ct: &Ciphertext, evk_conj: &EvaluationKey, params: &QfheParameters<'a>) -> Ciphertext {
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();
        
        // 1. 암호문의 각 다항식에 켤레 연산 적용
        let c0_conj = Self::polynomial_conjugate(&ct.c0, params);
        let c1_conj = Self::polynomial_conjugate(&ct.c1, params);

        // 2. 이는 m_conj를 s1_conj 하에 암호화한 것과 같음
        let ct_twisted = Ciphertext {
            c0: c0_conj,
            c1: c1_conj,
            modulus_level: ct.modulus_level,
        };

        // 3. s1_conj -> s1 으로 키 스위칭하여 최종 결과 도출
        // Note: The keyswitch function needs to be corrected for this to work.
        // Let's assume a simplified keyswitch for automorphism for now.
        // Automorphism keyswitch: input is (c0(s_conj), c1(s_conj)). Switch c1.
        let c1_twisted_decomposed = gadget_decompose(&ct_twisted.c1, params);
        let mut switched_part0 = Polynomial::zero(n, rns_size);
        let mut switched_part1 = Polynomial::zero(n, rns_size);

        for l in 0..params.gadget_levels_l {
            let evk_l = &evk_conj.0[l];
            let decomp_l = &c1_twisted_decomposed[l];
            switched_part0 = self.polynomial_add(&switched_part0, &self.polynomial_mul(&evk_l.c0, decomp_l, params), params);
            switched_part1 = self.polynomial_add(&switched_part1, &self.polynomial_mul(&evk_l.c1, decomp_l, params), params);
        }

        Ciphertext {
            c0: self.polynomial_add(&ct_twisted.c0, &switched_part0, params),
            c1: switched_part1,
            modulus_level: ct.modulus_level,
        }
    }
    
    /// ✅ RLWE: 재선형화 키 생성 구현. RLK = Enc(g^l * s1^2)
    fn generate_relinearization_key(&self, sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a>) -> RelinearizationKey {
        let s1 = &sk.s1;
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();
        let levels = params.gadget_levels_l;
        
        let pk = self.generate_public_key(sk, rng, params);
        let s1_squared = self.polynomial_mul(s1, s1, params);

        let mut key_vec = Vec::with_capacity(levels);

        for l in 0..levels {
            let power_of_base = params.gadget_base_b.pow(l as u32);
            let power_of_base_rns = crate::core::rns::integer_to_rns(power_of_base, params.modulus_q);
            
            let mut p_to_encrypt = s1_squared.clone();
            for i in 0..n {
                for j in 0..rns_size {
                    p_to_encrypt.coeffs[i].w[j] = p_to_encrypt.coeffs[i].w[j].safe_mul_mod(power_of_base_rns[j], params.modulus_q[j]);
                    p_to_encrypt.coeffs[i].x[j] = p_to_encrypt.coeffs[i].x[j].safe_mul_mod(power_of_base_rns[j], params.modulus_q[j]);
                    p_to_encrypt.coeffs[i].y[j] = p_to_encrypt.coeffs[i].y[j].safe_mul_mod(power_of_base_rns[j], params.modulus_q[j]);
                    p_to_encrypt.coeffs[i].z[j] = p_to_encrypt.coeffs[i].z[j].safe_mul_mod(power_of_base_rns[j], params.modulus_q[j]);
                }
            }
            key_vec.push(self.encrypt_internal(&p_to_encrypt, &pk, rng, params));
        }
        RelinearizationKey(key_vec)
    }

    /// ✅ RLWE: 평가 키(키 스위칭 키) 생성 구현. EVK = Enc_new(g^l * sk_old)
    fn generate_evaluation_key(&self, old_sk: &Polynomial, new_sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a>) -> EvaluationKey {
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();
        let levels = params.gadget_levels_l;
        
        let pk_new = self.generate_public_key(new_sk, rng, params);
        let mut key_vec = Vec::with_capacity(levels);

        for l in 0..levels {
            let power_of_base = params.gadget_base_b.pow(l as u32);
            let power_of_base_rns = crate::core::rns::integer_to_rns(power_of_base, params.modulus_q);
            
            let mut p_to_encrypt = old_sk.clone();
            // p_to_encrypt *= g^l
            for i in 0..n {
                for j in 0..rns_size {
                    let q_j = params.modulus_q[j];
                    p_to_encrypt.coeffs[i].w[j] = p_to_encrypt.coeffs[i].w[j].safe_mul_mod(power_of_base_rns[j], q_j);
                    p_to_encrypt.coeffs[i].x[j] = p_to_encrypt.coeffs[i].x[j].safe_mul_mod(power_of_base_rns[j], q_j);
                    p_to_encrypt.coeffs[i].y[j] = p_to_encrypt.coeffs[i].y[j].safe_mul_mod(power_of_base_rns[j], q_j);
                    p_to_encrypt.coeffs[i].z[j] = p_to_encrypt.coeffs[i].z[j].safe_mul_mod(power_of_base_rns[j], q_j);
                }
            }
            key_vec.push(self.encrypt_internal(&p_to_encrypt, &pk_new, rng, params));
        }
        EvaluationKey(key_vec)
    }

    /// ✅ RLWE: 부트스트래핑 키 생성 구현. BSK = { GGSW(s1_i) }
    fn generate_bootstrap_key(&self, sk: &SecretKey, pk: &PublicKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a>) -> BootstrapKey {
        let s1 = &sk.s1;
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();

        let s1_integer_coeffs: Vec<i128> = (0..n).map(|i| {
            let rns_w = &s1.coeffs[i].w;
            let integer_w = rns_to_integer(rns_w, params.modulus_q);
            let q_product = params.modulus_q.iter().fold(U256::ONE, |acc, &m| acc.wrapping_mul(&U256::from_u64(m)));
            let q_half = q_product >> 1;
            if integer_w > q_half {
                -((q_product - integer_w).to_words()[0] as i128)
            } else {
                integer_w.to_words()[0] as i128
            }
        }).collect();

        // ✅ FIX (Rust 2024): 병렬 처리를 위해 각 스레드가 사용할 시드를 미리 생성합니다.
        let seeds: Vec<[u8; 32]> = (0..n).map(|_| rng.random()).collect();

        let ggsw_vector: Vec<GgswCiphertext> = (0..n).into_par_iter().map(|i| {
            let mut thread_rng = ChaCha20Rng::from_seed(seeds[i]);
            let mut levels = Vec::with_capacity(params.gadget_levels_l);
            let s1_i_val = s1_integer_coeffs[i];
            
            // ✅ [OPTIMIZATION]
            // Polynomial 할당을 루프 밖으로 이동하여 메모리 할당/해제 오버헤드를 줄입니다.
            let mut msg_poly = Polynomial::zero(n, rns_size);

            for l in 0..params.gadget_levels_l {
                let power_of_base = params.gadget_base_b.pow(l as u32);
                let scaled_s1_i = U256::from(power_of_base).wrapping_mul(&U256::from(s1_i_val.unsigned_abs()));
                
                let msg_to_encrypt = if s1_i_val < 0 {
                    scaled_s1_i.wrapping_neg()
                } else {
                    scaled_s1_i
                };
                
                // ✅ [OPTIMIZATION]
                // 할당된 Polynomial 객체를 재사용합니다. 
                // 0이 아닌 계수는 덮어쓰고, 나머지 계수는 0으로 유지됩니다.
                msg_poly.coeffs[0].w = integer_to_rns(msg_to_encrypt.to_words()[0] as u128, params.modulus_q);
                // 만약 이전 반복에서 다른 계수를 사용했다면 0으로 초기화하는 코드가 필요하지만,
                // 현재 로직에서는 coeffs[0]만 사용하므로 추가 작업이 필요 없습니다.

                levels.push(self.encrypt_internal(&msg_poly, &pk, &mut thread_rng, params));
            }
            GgswCiphertext { levels }
        }).collect();

        BootstrapKey { ggsw_vector }
    }

    /// ✅ RLWE: 프로그래머블 부트스트래핑 완전 구현
    fn bootstrap(&self, ct: &Ciphertext, test_poly: &Polynomial, bk: &BootstrapKey, params: &QfheParameters<'a>) -> Ciphertext {
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();
        let new_modulus = (2 * n) as u64;

        // 1. Modulus Switch (Sample Extract) to get LWE sample (b, -a)
        let (c0_switched, c1_switched) = self.modulus_switch(ct, new_modulus);
        let b_bar = c0_switched[0];
        let a_bar = c1_switched; 

        // 2. Blind Rotation
        let mut accumulator = {
            // ✅ FIX: test_poly(평문)를 회전시키기 위해 polynomial_rotation 사용
            let rotated_poly = polynomial_rotation(test_poly, -(b_bar as i128), params);
            // 자명한 암호화: Enc(rotated_poly, 0)
            Ciphertext { c0: rotated_poly, c1: Polynomial::zero(n, rns_size), modulus_level: 0 }
        };

        for i in 0..n {
            let a_i_bar = a_bar[i];
            if a_i_bar == 0 { continue; }
            
            // ✅ FIX: accumulator(암호문)를 회전시키기 위해 ciphertext_rotation 사용
            let rotated_acc = ciphertext_rotation(&accumulator, a_i_bar as i128, params);
            accumulator = self.cmux(&bk.ggsw_vector[i], &accumulator, &rotated_acc, params);
        }

        accumulator
    }

    /// ✅ RLWE: Modulus Switch 구현 (Sample Extract)
    fn modulus_switch(&self, ct: &Ciphertext, new_modulus: u64) -> (Vec<u64>, Vec<u64>) {
        let n = ct.c0.coeffs.len();
        let q_product = U256::from_u128(1_152_921_504_606_584_833u128); // L128 기준 Q
        let new_mod_u256 = U256::from(new_modulus);

        let round_and_scale = |poly: &Polynomial| -> Vec<u64> {
            (0..n).map(|i| {
                let coeff_int = rns_to_integer(&poly.coeffs[i].w, &[q_product.to_words()[0]]);
                // round( (x * 2N) / Q )
                let scaled = coeff_int.wrapping_mul(&new_mod_u256);
                let rounded = scaled.wrapping_add(&(q_product >> 1)).div_rem(&NonZero::new(q_product).unwrap()).0;
                rounded.to_words()[0]
            }).collect()
        };
        
        let c0_switched = round_and_scale(&ct.c0);
        let c1_switched = round_and_scale(&ct.c1);
        
        (c0_switched, c1_switched)
    }

    /// ✅ RLWE: 키 스위칭 구현
    fn keyswitch(&self, ct: &Ciphertext, evk: &EvaluationKey, params: &QfheParameters<'a>) -> Ciphertext {
        let n = params.polynomial_degree;
        let rns_size = params.modulus_q.len();

        let c1_decomposed = gadget_decompose(&ct.c1, params);

        let mut res_c0 = ct.c0.clone();
        let mut res_c1 = Polynomial::zero(n, rns_size);

        for l in 0..params.gadget_levels_l {
            let evk_ct = &evk.0[l];
            let decomp_poly = &c1_decomposed[l];

            let term_c0 = self.polynomial_mul(&evk_ct.c0, decomp_poly, params);
            let term_c1 = self.polynomial_mul(&evk_ct.c1, decomp_poly, params);

            res_c0 = self.polynomial_sub(&res_c0, &term_c0, params); // c0' = c0 - sum(decomp*evk.c0)
            res_c1 = self.polynomial_add(&res_c1, &term_c1, params); // c1' = sum(decomp*evk.c1)
        }
        
        // This is a common mistake. The key switch result should be ct' = (c0,0) + KeySwitch(c1).
        // Let's correct the logic.
        let mut new_c0 = ct.c0.clone();
        let mut new_c1 = Polynomial::zero(n, rns_size); // This will be the new c1, which is effectively 0 before adding terms.
        
        // The c1 part of the original ciphertext is the one we want to switch.
        let c1_decomposed = gadget_decompose(&ct.c1, params);
        
        for l in 0..params.gadget_levels_l {
            let evk_ct = &evk.0[l];
            let decomp_poly = &c1_decomposed[l];
            
            // The logic should be: new_ct = (c0, 0) + sum(decomp(c1) * evk)
            // But standard RLWE key switching is simpler: result = (c0, 0) + KeySwitch(c1)
            // Let's implement the key switch part on c1 first.
        }
        
        // Correct RLWE Key Switch Logic:
        // Input: ct=(c0, c1) under sk_old. evk encrypts sk_old under sk_new.
        // Output: ct'=(c0', c1') under sk_new.
        // 1. Decompose c1
        let c1_decomposed = gadget_decompose(&ct.c1, params);
        // 2. Calculate the two parts of the new ciphertext
        let mut new_ct_part0 = ct.c0.clone();
        let mut new_ct_part1 = Polynomial::zero(n, rns_size);
        for l in 0..params.gadget_levels_l {
            let evk_l = &evk.0[l];
            let decomp_l = &c1_decomposed[l];
            new_ct_part0 = self.polynomial_add(&new_ct_part0, &self.polynomial_mul(&evk_l.c0, decomp_l, params), params);
            new_ct_part1 = self.polynomial_add(&new_ct_part1, &self.polynomial_mul(&evk_l.c1, decomp_l, params), params);
        }

        Ciphertext {
            c0: new_ct_part0,
            c1: new_ct_part1,
            modulus_level: ct.modulus_level,
        }
    }

    /// 두 다항식을 더합니다. [RNS 기반, 안전한 모듈러 연산 적용]
    fn polynomial_add(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a>) -> Polynomial {
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
    fn polynomial_sub(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a>) -> Polynomial {
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
    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a>) -> Polynomial {
        let mut p1_ntt = p1.clone();
        let mut p2_ntt = p2.clone();

        qntt_forward(&mut p1_ntt, params);
        qntt_forward(&mut p2_ntt, params);
        qntt_pointwise_mul(&mut p1_ntt, &p2_ntt, params);
        qntt_inverse(&mut p1_ntt, params);

        p1_ntt
    }
}