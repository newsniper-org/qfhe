// 라이브러리의 각 모듈을 선언합니다.
pub mod core;
pub mod hal;
pub mod ffi;

// --- Public API ---
// 라이브러리 사용자가 직접 접근할 수 있는 핵심 기능들을 공개(re-export)합니다.
pub use crate::core::{QfheEngine, Ciphertext, Polynomial, Quaternion, SecretKey,
    QfheParameters};
pub use crate::ffi::QfheContext;


// --- 테스트 모듈 ---
// `cargo test` 명령어를 실행할 때만 컴파일되고 실행됩니다.
#[cfg(test)]
mod tests {
    use super::{QfheEngine, QfheContext, SecurityLevel};
    use super::ffi::{qfhe_context_create, qfhe_context_destroy};
    
    fn run_test_for_level(level: SecurityLevel) {
        let context_ptr = unsafe { qfhe_context_create(level) };
        let context = unsafe { &*context_ptr };

        // Encryption/Decryption Test
        let msg1 = 42;
        let ct1 = context.encrypt(msg1);
        assert_eq!(context.decrypt(&ct1), msg1, "Encryption/Decryption failed for level");

        // Homomorphic Addition Test
        let msg2 = 100;
        let ct2 = context.encrypt(msg2);
        let ct_sum = context.homomorphic_add(&ct1, &ct2);
        assert_eq!(context.decrypt(&ct_sum), msg1 + msg2, "Homomorphic addition failed for level");
        
        // Homomorphic Multiplication Test
        let msg3 = 7;
        let msg4 = 6;
        let ct3 = context.encrypt(msg3);
        let ct4 = context.encrypt(msg4);
        let ct_mul = context.homomorphic_mul(&ct3, &ct4);
        assert_eq!(context.decrypt(&ct_mul), msg3 * msg4, "Homomorphic multiplication failed for level");

        unsafe { qfhe_context_destroy(context_ptr); }
    }

    #[test]
    fn test_all_levels() {
        println!("--- 모든 보안 수준에 대한 테스트 시작 ---");
        run_test_for_level(SecurityLevel::L128);
        println!("--- L128 테스트 통과 ---\n");
        // Higher levels can be slow, enable them if needed
        // run_test_for_level(SecurityLevel::L192);
        // println!("--- L192 테스트 통과 ---\n");
    }
}