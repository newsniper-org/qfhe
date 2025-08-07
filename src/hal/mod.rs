// src/hal/mod.rs

use crate::core::{Ciphertext, Polynomial, QfheParameters};
use crate::core::keys::{SecretKey, RelinearizationKey, EvaluationKey, BootstrapKey, PublicKey};

use rand_chacha::ChaCha20Rng;

// ✅ RLWE: 트레이트 전체를 새로운 아키텍처에 맞게 수정
pub trait HardwareBackend<'a, 'b, 'c> {
    // --- 암호화 및 복호화 ---
    fn encrypt(&self, message: u64, pk: &PublicKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn decrypt(&self, ciphertext: &Ciphertext, sk: &SecretKey, params: &QfheParameters<'a, 'b, 'c>) -> u64;

    // --- 다항식 연산 (변경 없음) ---
    fn polynomial_add(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial;
    fn polynomial_sub(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial;
    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial;

    // --- 동형 연산 ---
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext, rlk: &RelinearizationKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn homomorphic_conjugate(&self, ct: &Ciphertext, evk_conj: &EvaluationKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;

    // --- 키 생성 함수 ---
    fn generate_secret_key(&self, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> SecretKey;
    fn generate_public_key(&self, sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> PublicKey;
    fn generate_relinearization_key(&self, sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> RelinearizationKey;
    fn generate_evaluation_key(&self, old_sk: &Polynomial, new_sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> EvaluationKey;
    fn generate_bootstrap_key(&self, sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> BootstrapKey;

    // --- 부가 기능 ---
    fn keyswitch(&self, ct: &Ciphertext, evk: &EvaluationKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn bootstrap(&self, ct: &Ciphertext, test_poly: &Polynomial, bk: &BootstrapKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn modulus_switch(&self, ct: &Ciphertext, new_modulus: u64) -> (Vec<u64>, Vec<u64>);
}

pub mod cpu;
pub use cpu::CpuBackend;
