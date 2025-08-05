// src/hal/mod.rs

use crate::core::{Ciphertext, Polynomial, SecretKey, QfheParameters, RelinearizationKey, KeySwitchingKey, BootstrapKey, PublicKey };

pub trait HardwareBackend<'a, 'b, 'c> {
    fn encrypt(&self, message: u64, params: &QfheParameters<'a, 'b, 'c>, public_key: &PublicKey) -> Ciphertext;
    fn decrypt(&self, ciphertext: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>, secret_key: &SecretKey) -> u64;
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn polynomial_add(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial;
    fn polynomial_sub(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial;
    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters<'a, 'b, 'c>) -> Polynomial;

    fn generate_relinearization_key(&self, secret_key: &SecretKey, params: &QfheParameters<'a, 'b, 'c>) -> RelinearizationKey;
    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext, rlk: &RelinearizationKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;

    fn generate_keyswitching_key(&self, old_key: &SecretKey, new_key: &SecretKey, params: &QfheParameters<'a, 'b, 'c>) -> KeySwitchingKey;
    fn generate_bootstrap_key(&self, secret_key: &SecretKey, params: &QfheParameters<'a, 'b, 'c>) -> BootstrapKey;
    fn bootstrap(&self, ct: &Ciphertext, test_poly: &Polynomial, bsk: &BootstrapKey, ksk: &KeySwitchingKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;
    fn keyswitch(&self, ct: &Ciphertext, ksk: &KeySwitchingKey, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;

    fn modulus_switch(&self, ct: &Ciphertext, params: &QfheParameters<'a, 'b, 'c>) -> Ciphertext;

    fn generate_public_key(&self, secret_key: &SecretKey, params: &QfheParameters<'a, 'c>) -> PublicKey;
}

pub mod cpu;
pub use cpu::CpuBackend;