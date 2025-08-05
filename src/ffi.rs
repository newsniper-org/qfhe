use crate::core::{
    Ciphertext, QfheEngine, Polynomial, Quaternion, SecretKey, SecurityLevel, QfheParameters,
    RelinearizationKey, BootstrapKey, KeySwitchingKey, GgswCiphertext
};
use crate::hal::{CpuBackend, HardwareBackend};
use rand::Rng;

use serde_json::{Serializer, Deserializer};

// QfheContext에 라이프타임 'a를 추가합니다.
#[repr(C)]
pub struct QfheContext {
    backend: Box<dyn HardwareBackend<'static, 'static, 'static> + 'static>,
    secret_key: SecretKey,
    relinearization_key: RelinearizationKey,
    bootstrap_key: BootstrapKey,
    keyswitching_key: KeySwitchingKey,
    params: QfheParameters<'static, 'static, 'static>,
}

// QfheEngine 트레이트 구현부에도 라이프타임을 명시합니다.
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

    fn bootstrap(&self, ct: &Ciphertext, test_poly: &Polynomial) -> Ciphertext {
        self.backend.bootstrap(ct, test_poly, &self.bootstrap_key, &self.keyswitching_key, &self.params)
    }

    fn modulus_switch(&self, ct: &Ciphertext) -> Ciphertext {
        self.backend.modulus_switch(ct, &self.params)
    }
}

// [수정] 반환 타입에 'static 라이프타임을 명시하고, RNS 기반으로 비밀키를 생성합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_create(level: SecurityLevel) -> *mut QfheContext {
    let params = level.get_params();
    let mut rng = rand::rng();
    let rns_basis_size = params.modulus_q.len();
    
    let secret_key_vec = (0..params.module_dimension_k).map(|_| {
        let coeffs = (0..params.polynomial_degree).map(|_| {
            let val: i128 = rng.random_range(-1..=1);
            let mut w = Vec::with_capacity(rns_basis_size);
            for &q_i in params.modulus_q {
                w.push(val.rem_euclid(q_i as i128) as u64);
            }
            // 쿼터니언의 다른 성분들도 동일하게 초기화 (또는 필요에 따라 다르게)
            Quaternion { w, x: vec![0; rns_basis_size], y: vec![0; rns_basis_size], z: vec![0; rns_basis_size] }
        }).collect();
        Polynomial { coeffs }
    }).collect();

    let secret_key = SecretKey(secret_key_vec);
    
    let backend = Box::new(CpuBackend);
    let relinearization_key = backend.generate_relinearization_key(&secret_key, &params);
    let bootstrap_key = backend.generate_bootstrap_key(&secret_key, &params);
    let keyswitching_key = backend.generate_keyswitching_key(&secret_key, &secret_key, &params);
    
    let context = Box::new(QfheContext { 
        backend,
        secret_key,
        relinearization_key,
        bootstrap_key,
        keyswitching_key,
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
pub unsafe extern "C" fn qfhe_context_generate_public_key(context: *const QfheContext) -> *mut PublicKey {
    let ctx = unsafe { &*context };
    let pk = ctx.backend.generate_public_key(&ctx.secret_key, &ctx.params);
    Box::into_raw(Box::new(pk))
}

// 공개키를 받아 암호화하는 FFI 함수
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_encrypt(
    context: *const QfheContext,
    message: u64,
    public_key: *const PublicKey,
) -> *mut Ciphertext {
    let ctx = unsafe { &*context };
    let pk = unsafe { &*public_key };
    let ciphertext = Box::new(ctx.backend.encrypt(message, pk, &ctx.params));
    Box::into_raw(ciphertext)
}

#[no_mangle]
pub unsafe extern "C" fn qfhe_public_key_destroy(pk_ptr: *mut PublicKey) {
    if !pk_ptr.is_null() {
        drop(unsafe { Box::from_raw(pk_ptr) });
    }
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