// src/hal/mod.rs

use crate::core::{Ciphertext, Polynomial, SecretKey, QfheParameters, RelinearizationKey, KeySwitchingKey, BootstrapKey, PublicKey };

use rand_chacha::ChaCha20Rng;

pub trait HardwareBackend<'a, 'b, 'c> {
    // --- 암호화 및 복호화 ---
    fn encrypt(&self, message: u64, pk: &PublicKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn decrypt(&self, ciphertext: &Ciphertext, sk: &SecretKey, params: &QfheParameters<'a, 'b, 'c>) -> u64;


    fn polynomial_add(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial;
    fn polynomial_sub(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial;
    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial;

    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext, rlk: &RelinearizationKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;

    // --- 키 생성 함수 ---
    fn generate_secret_key(&self, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> SecretKey;
    fn generate_public_key(&self, sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> PublicKey;
    fn generate_relinearization_key(&self, sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> RelinearizationKey;
    fn generate_key_switching_key(&self, old_sk: &SecretKey, new_sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> KeySwitchingKey;
    fn generate_bootstrap_key(&self, sk: &SecretKey, rng: &mut ChaCha20Rng, params: &QfheParameters<'a, 'b, 'c>) -> BootstrapKey;

    fn bootstrap(&self, ct: &Ciphertext, test_poly: &Polynomial, bk: &BootstrapKey, ksk: &KeySwitchingKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn keyswitch(&self, ct: &Ciphertext, ksk: &KeySwitchingKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn modulus_switch(&self, ct: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;

    /// ✅ NEW: 암호문과 일반 다항식(스칼라)의 곱셈을 위한 헬퍼 함수
    fn ciphertext_scalar_mul(&self, ct: &Ciphertext, scalar: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
}

pub mod cpu;
pub use cpu::CpuBackend;