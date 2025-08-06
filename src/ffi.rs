use crate::core::{
    BootstrapKey, Ciphertext, GgswCiphertext, KeySwitchingKey, Polynomial, PublicKey, QfheEngine, QfheParameters, Quaternion, RelinearizationKey, SecretKey, SecurityLevel, MasterKey, Salt, keys::generate_keys
};
use crate::hal::{CpuBackend, HardwareBackend};
use rand::{Rng, SeedableRng};

use serde_json::{Serializer, Deserializer};

use rand_chacha::ChaCha20Rng;

// QfheContext에 라이프타임 'a를 추가합니다.
#[repr(C)]
pub struct QfheContext {
    backend: Box<dyn HardwareBackend<'static, 'static, 'static> + 'static>,
    secret_key: SecretKey,
    public_key: PublicKey,
    relinearization_key: RelinearizationKey,
    bootstrap_key: BootstrapKey,
    keyswitching_key: KeySwitchingKey,
    params: QfheParameters<'static, 'static, 'static>,
}

// QfheEngine 트레이트 구현부에도 라이프타임을 명시합니다.
impl QfheEngine for QfheContext {
    fn encrypt(&self, message: u64) -> Ciphertext {
        // 암호화 연산마다 새로운 임시 난수 생성기를 사용
        let mut ephemeral_rng = ChaCha20Rng::from_os_rng();
        self.backend.encrypt(message, &self.public_key, &mut ephemeral_rng, &self.params)
    }

    fn decrypt(&self, ciphertext: &Ciphertext) -> u64 {
        self.backend.decrypt(ciphertext, &self.secret_key, &self.params)
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

// [수정] RNS 기반으로 키들을 생성합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_create(
    level: SecurityLevel,
    master_key_ptr: *const u8,
    salt_ptr: *const u8,
) -> *mut QfheContext {
    let params = level.get_params();

    let master_key = MasterKey(unsafe { std::slice::from_raw_parts(master_key_ptr, 32).clone() });
    let salt_slice = Salt(unsafe { std::slice::from_raw_parts(salt_ptr, 24).clone() });
    let backend = Box::new(CpuBackend);
    
    let (secret_key, public_key, keyswitching_key, relinearization_key, bootstrap_key) = generate_keys(level, master_key, salt, backend.as_ref());

    let context = Box::new(QfheContext { 
        backend,
        secret_key,
        public_key,
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

// 공개키를 받아 암호화하는 FFI 함수
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_encrypt(
    context: *const QfheContext,
    message: u64,
    public_key: *const PublicKey,
) -> *mut Ciphertext {
    let ctx = unsafe { &*context };
    let pk = unsafe { &*public_key };
    let ciphertext = Box::new(ctx.encrypt(message));
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