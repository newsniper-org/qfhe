#![feature(bigint_helper_methods)]

pub mod core;
pub mod hal;
pub mod ffi;
pub mod ntt;
pub mod serialization;


pub use crate::core::{
    Ciphertext, Polynomial, QfheParameters, SecurityLevel, Quaternion,
    keys::{BootstrapKey, EvaluationKey, SecretKey, PublicKey, RelinearizationKey}
};
pub use crate::hal::{HardwareBackend, cpu::CpuBackend};
pub use crate::ffi::{EvaluationContext, EncryptionContext, DecryptionContext};
pub use crate::serialization::{CipherObject, KeyType};

// ✅ RLWE: 테스트 모듈 전체를 새로운 API에 맞게 재작성
#[cfg(test)]
mod tests {
    use crate::{BootstrapKey, Polynomial};

    use super::core::{keys::{generate_keys, MasterKey, Salt, SecretKey, PublicKey}, SecurityLevel};
    use super::hal::{cpu::CpuBackend, HardwareBackend};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::OsRng;

    // 테스트를 위한 공통 설정
    fn setup_keys(level: SecurityLevel) -> (crate::core::keys::SecretKey, crate::core::keys::PublicKey, crate::core::keys::RelinearizationKey, crate::core::keys::EvaluationKey, crate::core::keys::BootstrapKey) {
        let master_key = MasterKey(rand::random());
        let salt = Salt(rand::random());
        let backend = CpuBackend;
        let params = level.get_params();
        
        // ❗ NOTE: generate_keys가 아직 미완성이므로, 직접 백엔드 함수 호출
        generate_keys(level, &master_key, &salt, &backend)
    }

    #[test]
    fn test_rlwe_encrypt_decrypt_correctness() {
        println!("\n--- Testing RLWE Encrypt/Decrypt Correctness (L128) ---");
        let level = SecurityLevel::L128;
        let (sk, pk, _, _,_ ) = setup_keys(level);
        let backend = CpuBackend;
        let params = level.get_params();
        let mut rng = rand_chacha::ChaCha20Rng::from_os_rng();

        let msg: u64 = 42;
        println!("Original message: {}", msg);

        let ct = backend.encrypt(msg, &pk, &mut rng, &params);
        println!("Encryption complete.");

        let decrypted_msg = backend.decrypt(&ct, &sk, &params);
        println!("Decryption complete. Decrypted message: {}", decrypted_msg);

        assert_eq!(msg, decrypted_msg, "FAIL: Decrypted message does not match!");
        println!(" -> RLWE Encrypt/Decrypt VERIFIED! ✅");
    }

    #[test]
    fn test_rlwe_homomorphic_addition_correctness() {
        println!("\n--- Testing RLWE Homomorphic Addition Correctness (L128) ---");
        let level = SecurityLevel::L128;
        let (sk, pk, _, _,_ ) = setup_keys(level);
        let backend = CpuBackend;
        let params = level.get_params();
        let mut rng = rand_chacha::ChaCha20Rng::from_os_rng();

        let msg1: u64 = 25;
        let msg2: u64 = 17;
        let expected_add = msg1 + msg2;
        println!("Messages: {}, {}. Expected sum: {}", msg1, msg2, expected_add);

        let ct1 = backend.encrypt(msg1, &pk, &mut rng, &params);
        let ct2 = backend.encrypt(msg2, &pk, &mut rng, &params);
        println!("Encryption complete.");

        let ct_add = backend.homomorphic_add(&ct1, &ct2, &params);
        println!("Homomorphic addition complete.");

        let decrypted_add = backend.decrypt(&ct_add, &sk, &params);
        println!("Decryption complete. Decrypted sum: {}", decrypted_add);

        assert_eq!(expected_add, decrypted_add, "FAIL: Homomorphic addition result is incorrect!");
        println!(" -> RLWE Homomorphic Addition VERIFIED! ✅");
    }

    #[test]
    // ✅ RLWE: 동형 곱셈 테스트 활성화
    fn test_rlwe_homomorphic_multiplication_correctness() {
        println!("\n--- Testing RLWE Homomorphic Multiplication Correctness (L128) ---");
        let level = SecurityLevel::L128;
        let (sk, pk, rlk, _, _) = setup_keys(level);
        let backend = CpuBackend;
        let params = level.get_params();
        let mut rng = rand_chacha::ChaCha20Rng::from_os_rng();

        let msg1: u64 = 7;
        let msg2: u64 = 6;
        let expected_mul = msg1 * msg2;
        println!("Messages: {}, {}. Expected product: {}", msg1, msg2, expected_mul);

        let ct1 = backend.encrypt(msg1, &pk, &mut rng, &params);
        let ct2 = backend.encrypt(msg2, &pk, &mut rng, &params);
        println!("Encryption complete.");

        let ct_mul = backend.homomorphic_mul(&ct1, &ct2, &rlk, &params);
        println!("Homomorphic multiplication complete.");

        let decrypted_mul = backend.decrypt(&ct_mul, &sk, &params);
        println!("Decryption complete. Decrypted product: {}", decrypted_mul);

        assert_eq!(expected_mul, decrypted_mul, "FAIL: Homomorphic multiplication result is incorrect!");
        println!(" -> RLWE Homomorphic Multiplication VERIFIED! ✅");
    }

    #[test]
    // ✅ NEW: 동형 켤레 연산 테스트
    fn test_rlwe_homomorphic_conjugation_correctness() {
        println!("\n--- Testing RLWE Homomorphic Conjugation Correctness (L128) ---");
        let level = SecurityLevel::L128;
        let (sk, pk, _, evk_conj, _) = setup_keys(level);
        let backend = CpuBackend;
        let params = level.get_params();
        let mut rng = rand_chacha::ChaCha20Rng::from_os_rng();

        let msg: u64 = 123;
        // u64 메시지는 실수부이므로, 켤레를 취해도 자기 자신이어야 함
        let expected_msg = msg; 
        println!("Original message (real part): {}", msg);

        let ct = backend.encrypt(msg, &pk, &mut rng, &params);
        println!("Encryption complete.");

        let ct_conj = backend.homomorphic_conjugate(&ct, &evk_conj, &params);
        println!("Homomorphic conjugation complete.");

        let decrypted_conj = backend.decrypt(&ct_conj, &sk, &params);
        println!("Decryption complete. Decrypted conjugate: {}", decrypted_conj);

        assert_eq!(expected_msg, decrypted_conj, "FAIL: Homomorphic conjugation result is incorrect!");
        println!(" -> RLWE Homomorphic Conjugation VERIFIED! ✅");
    }

    #[test]
    // ✅ NEW: 프로그래머블 부트스트래핑 완전 테스트
    fn test_rlwe_programmable_bootstrapping() {
        println!("\n--- Testing RLWE Programmable Bootstrapping (L128) ---");
        let level = SecurityLevel::L128;
        let (sk, pk, _, _, bk) = setup_keys(level);
        let backend = CpuBackend;
        let params = level.get_params();
        let mut rng = rand_chacha::ChaCha20Rng::from_os_rng();

        let msg: u64 = 3;
        let expected_res: u64 = 6; // f(x) = 2*x
        println!("Original message: {}, Expected f(m) = 2*m = {}", msg, expected_res);

        let mut ct = backend.encrypt(msg, &pk, &mut rng, &params);

        // 일부러 노이즈를 많이 증가시켜 복호화가 실패하는 상황을 만듦
        for _ in 0..3 { // 곱셈은 노이즈를 매우 빠르게 증가시킴
            ct = backend.homomorphic_add(&ct, &ct, &params);
        }
        println!("Noise increased significantly.");

        // 테스트 함수 f(x) = 2*x 를 인코딩하는 테스트 다항식 생성
        let mut test_poly = Polynomial::zero(params.polynomial_degree, params.modulus_q.len());
        let lut_scaling = params.scaling_factor_delta / (2 * params.polynomial_degree as u128);
        for i in 0..(params.plaintext_modulus as usize) {
             let val = (2 * i as u128) % params.plaintext_modulus as u128;
             let scaled_val = val * lut_scaling;
             test_poly.coeffs[i].w = crate::core::rns::integer_to_rns(scaled_val, params.modulus_q);
        }

        let bootstrapped_ct = backend.bootstrap(&ct, &test_poly, &bk, &params);
        println!("Bootstrapping complete.");

        let decrypted_res = backend.decrypt(&bootstrapped_ct, &sk, &params);
        println!("Decrypted result after PBS: {}", decrypted_res);
        
        // 부트스트래핑은 근사 계산이므로 약간의 오차를 허용
        let tolerance = 1;
        assert!((decrypted_res as i64 - expected_res as i64).abs() <= tolerance, 
                "FAIL: Bootstrapping result is incorrect!");
        println!(" -> RLWE Programmable Bootstrapping VERIFIED! ✅");
    }
}
