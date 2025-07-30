use crate::core::{
    Ciphertext, QfheEngine, Polynomial, Quaternion, SecretKey, SecurityLevel, QfheParameters
};
use crate::hal::{CpuBackend, HardwareBackend};
use rand::Rng;

// CPU 백엔드를 사용하는 QFHE 컨텍스트 구조체
// QFHE 컨텍스트 구조체: 이제 암호 파라미터와 키를 포함합니다.
pub struct QfheContext {
    backend: Box<dyn HardwareBackend>,
    secret_key: SecretKey,
    params: QfheParameters,
}

impl QfheEngine for QfheContext {
    fn encrypt(&self, message: u64) -> Ciphertext {
        self.backend.encrypt(message, &self.params, &self.secret_key)
    }

    fn decrypt(&self, ciphertext: &Ciphertext) -> u64 {
        self.backend.decrypt(ciphertext, &self.params, &self.secret_key)
    }

    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        self.backend.homomorphic_add(ct1, ct2, &self.params)
    }
    
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        self.backend.homomorphic_sub(ct1, ct2, &self.params)
    }
}

/// C에서 사용할 컨텍스트 생성 함수
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_context_create(level: SecurityLevel) -> *mut QfheContext {
    let params = level.get_params();
    let mut rng = rand::rng();
    let secret_key_coeffs = (0..params.polynomial_degree).map(|_| {
        let val: i128 = rng.random_range(-1..=1);
        Quaternion {
            w: val.rem_euclid(params.modulus_q as i128) as u128,
            x: val.rem_euclid(params.modulus_q as i128) as u128,
            y: val.rem_euclid(params.modulus_q as i128) as u128,
            z: val.rem_euclid(params.modulus_q as i128) as u128,
        }
    }).collect();
    let secret_key = SecretKey(Polynomial { coeffs: secret_key_coeffs });
    
    let context = Box::new(QfheContext { 
        backend: Box::new(CpuBackend),
        secret_key,
        params,
    });
    Box::into_raw(context)
}

/// C에서 컨텍스트를 안전하게 해제하는 함수
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_context_destroy(context_ptr: *mut QfheContext) {
    if !context_ptr.is_null() {
        drop(unsafe { Box::from_raw(context_ptr) });
    }
}


/// 메시지를 암호화하는 FFI 함수
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_encrypt(context_ptr: *mut QfheContext, message: u64) -> *mut Ciphertext {
    let context = unsafe { &*context_ptr };
    let ciphertext = Box::new(context.encrypt(message));
    Box::into_raw(ciphertext)
}

/// 암호문을 복호화하는 FFI 함수
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_decrypt(context_ptr: *mut QfheContext, ciphertext_ptr: *mut Ciphertext) -> u64 {
    let context = unsafe { &*context_ptr };
    let ciphertext = unsafe { &*ciphertext_ptr };
    context.decrypt(ciphertext)
}

/// 동형적으로 두 암호문을 더합니다.
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_homomorphic_add(
    context_ptr: *mut QfheContext,
    ct1_ptr: *mut Ciphertext,
    ct2_ptr: *mut Ciphertext,
) -> *mut Ciphertext {
    let context = unsafe { &*context_ptr };
    let ct1 = unsafe { &*ct1_ptr };
    let ct2 = unsafe { &*ct2_ptr };
    let result_ct = Box::new(context.homomorphic_add(ct1, ct2));
    Box::into_raw(result_ct)
}

#[unsafe(no_mangle)]
pub extern "C" fn qfhe_homomorphic_sub(
    context_ptr: *mut QfheContext,
    ct1_ptr: *mut Ciphertext,
    ct2_ptr: *mut Ciphertext,
) -> *mut Ciphertext {
    let context = unsafe { &*context_ptr };
    let ct1 = unsafe { &*ct1_ptr };
    let ct2 = unsafe { &*ct2_ptr };
    let result_ct = Box::new(context.homomorphic_sub(ct1, ct2));
    Box::into_raw(result_ct)
}

/// 암호문을 안전하게 해제하는 함수
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_ciphertext_destroy(ciphertext_ptr: *mut Ciphertext) {
    if !ciphertext_ptr.is_null() {
        drop(unsafe { Box::from_raw(ciphertext_ptr) });
    }
}
