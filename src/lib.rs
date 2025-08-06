#![feature(bigint_helper_methods)]

pub mod core;
pub mod hal;
pub mod ffi;
pub mod ntt;

pub use crate::core::{Ciphertext, Polynomial, SecretKey, QfheParameters, SecurityLevel};
pub use crate::ffi::{EvaluationContext, EncryptionContext, DecryptionContext};

pub mod serialization;
pub use serialization::{CipherObject, KeyObject, Key, KeyType};

use rand_chacha::ChaCha20Rng;

// --- 테스트 모듈 ---
// `cargo test` 명령어를 실행할 때만 컴파일되고 실행됩니다.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{keys::generate_key_s, MasterKey, Salt, SecurityLevel};
    use crate::ffi::setup_context;
    use crate::hal::CpuBackend;
    use crate::core::QfheEngine;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_encrypt_decrypt_correctness() {
        println!("\n--- Testing Encrypt/Decrypt Correctness (L128) ---");
        let context = setup_context(SecurityLevel::L128);

        let msg: u64 = 42;
        println!("Original message: {}", msg);

        let ct = context.encrypt(msg);
        println!("Encryption complete.");

        let decrypted_msg = context.decrypt(&ct);
        println!("Decryption complete. Decrypted message: {}", decrypted_msg);

        assert_eq!(
            msg, decrypted_msg,
            "FAIL: Decrypted message does not match original message!"
        );
        println!(" -> Encrypt/Decrypt VERIFIED! ✅");
    }

    #[test]
    fn test_homomorphic_addition_correctness() {
        println!("\n--- Testing Homomorphic Addition Correctness (L128) ---");
        let context = setup_context(SecurityLevel::L128);

        let msg1: u64 = 25;
        let msg2: u64 = 17;
        let expected_add = msg1 + msg2;
        println!("Messages: {}, {}. Expected sum: {}", msg1, msg2, expected_add);

        let ct1 = context.encrypt(msg1);
        let ct2 = context.encrypt(msg2);
        println!("Encryption complete.");

        let ct_add = context.homomorphic_add(&ct1, &ct2);
        println!("Homomorphic addition complete.");

        let decrypted_add = context.decrypt(&ct_add);
        println!("Decryption complete. Decrypted sum: {}", decrypted_add);

        assert_eq!(
            expected_add, decrypted_add,
            "FAIL: Homomorphic addition result is incorrect!"
        );
        println!(" -> Homomorphic Addition VERIFIED! ✅");
    }

    #[test]
    fn test_homomorphic_multiplication_correctness() {
        println!("\n--- Testing Homomorphic Multiplication Correctness (L128) ---");
        let context = setup_context(SecurityLevel::L128);

        let msg1: u64 = 7;
        let msg2: u64 = 6;
        let expected_mul = msg1 * msg2;
        println!("Messages: {}, {}. Expected product: {}", msg1, msg2, expected_mul);

        let ct1 = context.encrypt(msg1);
        let ct2 = context.encrypt(msg2);
        println!("Encryption complete.");

        let ct_mul = context.homomorphic_mul(&ct1, &ct2);
        println!("Homomorphic multiplication complete.");

        let decrypted_mul = context.decrypt(&ct_mul);
        println!("Decryption complete. Decrypted product: {}", decrypted_mul);

        assert_eq!(
            expected_mul, decrypted_mul,
            "FAIL: Homomorphic multiplication result is incorrect!"
        );
        println!(" -> Homomorphic Multiplication VERIFIED! ✅");
    }
}