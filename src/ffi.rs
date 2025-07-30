use crate::core::Polynomial;
use crate::core::{
    SecretKey, Ciphertext, QfheEngine,
    POLYNOMIAL_DEGREE, MODULUS_Q,
    quaternion::Quaternion
};
use crate::hal::{CpuBackend, HardwareBackend};
use std::ffi::c_void;

use rand::prelude::*;

// CPU 백엔드를 사용하는 QFHE 컨텍스트 구조체
// QFHE 컨텍스트 구조체: 이제 암호 파라미터와 키를 포함합니다.
#[repr(C)]
pub struct QfheContext {
    backend: Box<dyn HardwareBackend>,
    secret_key: SecretKey,
}

impl QfheContext {
    pub fn encrypt(&self, message: u64) -> Ciphertext {
        self.backend.encrypt(message, &self.secret_key)
    }

    pub fn decrypt(&self, ciphertext: &Ciphertext) -> u64 {
        self.backend.decrypt(ciphertext, &self.secret_key)
    }

    pub fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        self.backend.homomorphic_add(ct1, ct2)
    }
    
    pub fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        self.backend.homomorphic_sub(ct1, ct2)
    }
}

// QfheEngine 구현은 이제 단순히 백엔드로 호출을 위임합니다.
impl QfheEngine for QfheContext {
    fn encrypt(&self, message: u64) -> Ciphertext {
        self.backend.encrypt(message, &self.secret_key)
    }

    fn decrypt(&self, ciphertext: &Ciphertext) -> u64 {
        self.backend.decrypt(ciphertext, &self.secret_key)
    }

    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        self.backend.homomorphic_add(ct1, ct2)
    }
    
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        self.backend.homomorphic_sub(ct1, ct2)
    }
}

/// C에서 사용할 컨텍스트 생성 함수
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_context_create() -> *mut c_void {
    let mut rng = rand::rng();
    let secret_key_coeffs = (0..POLYNOMIAL_DEGREE).map(|_| {
        let val = rng.random_range::<i128, _>(-1..1);
        Quaternion {
            w: val.rem_euclid(MODULUS_Q as i128) as u128,
            x: val.rem_euclid(MODULUS_Q as i128) as u128,
            y: val.rem_euclid(MODULUS_Q as i128) as u128,
            z: val.rem_euclid(MODULUS_Q as i128) as u128,
        }
    }).collect();
    let secret_key = SecretKey(Polynomial { coeffs: secret_key_coeffs });
    
    let context = Box::new(QfheContext { 
        backend: Box::new(CpuBackend),
        secret_key,
    });
    Box::into_raw(context) as *mut c_void
}

/// C에서 컨텍스트를 안전하게 해제하는 함수
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_context_destroy(context_ptr: *mut c_void) {
    if !context_ptr.is_null() {
        unsafe { drop(Box::from_raw(context_ptr as *mut QfheContext)); }
    }
}


/// 메시지를 암호화하는 FFI 함수
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_encrypt(context_ptr: *mut c_void, message: u64) -> *mut c_void {
    let context = unsafe { &*(context_ptr as *mut QfheContext) };
    let ciphertext = Box::new(context.encrypt(message));
    Box::into_raw(ciphertext) as *mut c_void
}

/// 암호문을 복호화하는 FFI 함수
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_decrypt(context_ptr: *mut c_void, ciphertext_ptr: *mut c_void) -> u64 {
    let context = unsafe { &*(context_ptr as *mut QfheContext) };
    let ciphertext = unsafe { &*(ciphertext_ptr as *mut Ciphertext) };
    context.decrypt(ciphertext)
}

/// 동형적으로 두 암호문을 더합니다.
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_homomorphic_add(
    context_ptr: *mut c_void,
    ciphertext1_ptr: *mut c_void,
    ciphertext2_ptr: *mut c_void,
) -> *mut c_void {
    let context = unsafe { &*(context_ptr as *mut QfheContext) };
    let ct1 = unsafe { &*(ciphertext1_ptr as *mut Ciphertext) };
    let ct2 = unsafe { &*(ciphertext2_ptr as *mut Ciphertext) };
    let result_ct = Box::new(context.homomorphic_add(ct1, ct2));
    Box::into_raw(result_ct) as *mut c_void
}

/// 암호문을 안전하게 해제하는 함수
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_ciphertext_destroy(ciphertext_ptr: *mut c_void) {
    if !ciphertext_ptr.is_null() {
        unsafe { drop(Box::from_raw(ciphertext_ptr as *mut Ciphertext)); }
    }
}
