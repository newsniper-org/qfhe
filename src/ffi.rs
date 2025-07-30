use crate::core::{
    Ciphertext, QfheEngine, Polynomial, Quaternion, SecretKey, SecurityLevel, QfheParameters, RelinearizationKey
};
use crate::hal::{CpuBackend, HardwareBackend};
use rand::Rng;

#[repr(C)]
pub struct QfheContext {
    backend: Box<dyn HardwareBackend>,
    secret_key: SecretKey,
    relinearization_key: RelinearizationKey,
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
    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        self.backend.homomorphic_mul(ct1, ct2, &self.relinearization_key, &self.params)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_create(level: SecurityLevel) -> *mut QfheContext {
    let params = level.get_params();
    let mut rng = rand::rng();
    let k = params.module_dimension_k;
    
    let s: Vec<Polynomial> = (0..k).map(|_| {
        let coeffs = (0..params.polynomial_degree).map(|_| {
            let val: i128 = rng.random_range(-1..=1);
            Quaternion { w: val.rem_euclid(params.modulus_q as i128) as u128, x:0,y:0,z:0 }
        }).collect();
        Polynomial { coeffs }
    }).collect();

    let backend = Box::new(CpuBackend);

    let s_squared: Vec<Polynomial> = (0..k*k).map(|idx| {
        let i = idx / k;
        let j = idx % k;
        backend.polynomial_mul(&s[i], &s[j], &params)
    }).collect();

    let secret_key = SecretKey { s, s_squared };
    let relinearization_key = backend.gen_relinearization_key(&secret_key, &params);
    
    let context = Box::new(QfheContext { 
        backend,
        secret_key,
        relinearization_key,
        params,
    });
    Box::into_raw(context)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_destroy(context_ptr: *mut QfheContext) {
    if !context_ptr.is_null() {
        drop(unsafe { Box::from_raw(context_ptr) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_encrypt(context_ptr: *mut QfheContext, message: u64) -> *mut Ciphertext {
    let context = unsafe { &*context_ptr };
    let ciphertext = Box::new(context.encrypt(message));
    Box::into_raw(ciphertext)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_decrypt(context_ptr: *mut QfheContext, ciphertext_ptr: *mut Ciphertext) -> u64 {
    let context = unsafe { &*context_ptr };
    let ciphertext = unsafe { &*ciphertext_ptr };
    context.decrypt(ciphertext)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_homomorphic_add(
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
pub unsafe extern "C" fn qfhe_homomorphic_sub(
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_homomorphic_mul(
    context_ptr: *mut QfheContext,
    ct1_ptr: *mut Ciphertext,
    ct2_ptr: *mut Ciphertext,
) -> *mut Ciphertext {
    let context = unsafe { &*context_ptr };
    let ct1 = unsafe { &*ct1_ptr };
    let ct2 = unsafe { &*ct2_ptr };
    let result_ct = Box::new(context.homomorphic_mul(ct1, ct2));
    Box::into_raw(result_ct)
}


#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_ciphertext_destroy(ciphertext_ptr: *mut Ciphertext) {
    if !ciphertext_ptr.is_null() {
        drop(unsafe { Box::from_raw(ciphertext_ptr) });
    }
}