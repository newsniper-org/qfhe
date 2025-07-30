// src/hal/mod.rs

use crate::core::{Ciphertext, Polynomial, SecretKey, QfheParameters, RelinearizationKey};

pub trait HardwareBackend {
    fn encrypt(&self, message: u64, params: &QfheParameters, secret_key: &SecretKey) -> Ciphertext;
    fn decrypt(&self, ciphertext: &Ciphertext, params: &QfheParameters, secret_key: &SecretKey) -> u64;
    
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters) -> Ciphertext;
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext, params: &QfheParameters) -> Ciphertext;
    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext, rlk: &RelinearizationKey, params: &QfheParameters) -> Ciphertext;

    fn polynomial_add(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters) -> Polynomial;
    fn polynomial_sub(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters) -> Polynomial;
    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial, params: &QfheParameters) -> Polynomial;

    fn gen_relinearization_key(&self, secret_key: &SecretKey, params: &QfheParameters) -> RelinearizationKey;
}

pub mod cpu;
pub use cpu::CpuBackend;
