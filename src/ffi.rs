use std::ffi::CString;

use std::ffi::CStr;

use crate::core::{
    BootstrapKey, Ciphertext, GgswCiphertext, KeySwitchingKey, Polynomial, PublicKey, QfheParameters, Quaternion, RelinearizationKey, SecretKey, SecurityLevel, MasterKey, Salt, keys::generate_key_s,
    EncryptionEngine, DecryptionEngine, EvaluationEngine,
};
use crate::hal::{CpuBackend, HardwareBackend};
use rand::{Rng, SeedableRng, TryRngCore};

use serde::Deserialize;
use serde::Serialize;
use serde_json::{Serializer, Deserializer};

use rand_chacha::ChaCha20Rng;

use crate::{CipherObject, KeyObject, KeyType};

use rand_core::{OsRng, RngCore};

use std::ffi::c_char;

use crate::serialization::Key;


// #################################################################
// #                  역할별 컨텍스트 구조체 정의                   #
// #################################################################


/// 암호화를 위한 컨텍스트
#[repr(C)]
pub struct EncryptionContext {
    backend: Box<dyn HardwareBackend<'static, 'static, 'static>>,
    params: QfheParameters<'static, 'static, 'static>,
    public_key: PublicKey,
}

/// 복호화를 위한 컨텍스트
#[repr(C)]
pub struct DecryptionContext {
    backend: Box<dyn HardwareBackend<'static, 'static, 'static>>,
    params: QfheParameters<'static, 'static, 'static>,
    secret_key: SecretKey,
}

/// 동형 연산을 위한 컨텍스트
#[repr(C)]
pub struct EvaluationContext {
    backend: Box<dyn HardwareBackend<'static, 'static, 'static>>,
    params: QfheParameters<'static, 'static, 'static>,
    relinearization_key: RelinearizationKey,
    bootstrap_key: BootstrapKey,
    key_switching_key: KeySwitchingKey,
}

impl EncryptionContext {
    pub fn new_from_ref(
        backend: Box<dyn HardwareBackend<'static, 'static, 'static> + 'static>,
        public_key: &PublicKey,
        level: SecurityLevel
    ) -> Self {
        Self {
            backend,
            public_key: public_key.clone(),
            params: level.get_params()
        }
    }
}

impl DecryptionContext {
    pub fn new_from_ref(
        backend: Box<dyn HardwareBackend<'static, 'static, 'static> + 'static>,
        secret_key: &SecretKey,
        level: SecurityLevel
    ) -> Self {
        Self {
            backend,
            secret_key: secret_key.clone(),
            params: level.get_params()
        }
    }
}

impl EvaluationContext {
    pub fn new_from_ref(
        backend: Box<dyn HardwareBackend<'static, 'static, 'static> + 'static>,
        relinearization_key: &RelinearizationKey,
        bootstrap_key: &BootstrapKey,
        key_switching_key: &KeySwitchingKey,
        level: SecurityLevel
    ) -> Self {
        Self {
            backend,
            relinearization_key: relinearization_key.clone(),
            bootstrap_key: bootstrap_key.clone(),
            key_switching_key: key_switching_key.clone(),
            params: level.get_params()
        }
    }
}

impl EncryptionEngine for EncryptionContext {
    fn encrypt(&self, message: u64) -> Ciphertext {
        // 암호화 연산마다 새로운 임시 난수 생성기를 사용
        let mut ephemeral_rng = ChaCha20Rng::from_os_rng();
        self.backend.encrypt(message, &self.public_key, &mut ephemeral_rng, &self.params)
    }
}


impl DecryptionEngine for DecryptionContext {
    fn decrypt(&self, ciphertext: &Ciphertext) -> u64 {
        self.backend.decrypt(ciphertext, &self.secret_key, &self.params)
    }
}

impl EvaluationEngine for EvaluationContext {
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
        self.backend.bootstrap(ct, test_poly, &self.bootstrap_key, &self.key_switching_key, &self.params)
    }

    fn modulus_switch(&self, ct: &Ciphertext) -> Ciphertext {
        self.backend.modulus_switch(ct, &self.params)
    }
}


// #################################################################
// #                  키 생성 FFI 함수                             #
// #################################################################

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_generate_key_s(
    level: SecurityLevel,
    master_key_ptr: *const u8,
    salt_ptr: *const u8,
    sk_out: *mut *mut SecretKey,
    pk_out: *mut *mut PublicKey,
    rlk_out: *mut *mut RelinearizationKey,
    ksk_out: *mut *mut KeySwitchingKey,
    bk_out: *mut *mut BootstrapKey,
) {
    let master_key = MasterKey((*unsafe { std::slice::from_raw_parts(master_key_ptr, 32) }).try_into().unwrap());
    let salt = Salt((*unsafe { std::slice::from_raw_parts(salt_ptr, 24) }).try_into().unwrap());
    let backend = CpuBackend;

    let (sk, pk, ksk, rlk, bk) = generate_key_s(level, &master_key, &salt, &backend);

    unsafe { *sk_out = Box::into_raw(Box::new(sk)) };
    unsafe { *pk_out = Box::into_raw(Box::new(pk)) };
    unsafe { *rlk_out = Box::into_raw(Box::new(rlk)) };
    unsafe { *ksk_out = Box::into_raw(Box::new(ksk)) };
    unsafe { *bk_out = Box::into_raw(Box::new(bk)) };
}

// #################################################################
// #             컨텍스트 생성 및 해제 FFI 함수                      #
// #################################################################

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_create_encryption_context(level: SecurityLevel, pk: *const PublicKey) -> *mut EncryptionContext {
    Box::into_raw(Box::new(EncryptionContext {
        backend: Box::new(CpuBackend),
        params: level.get_params(),
        public_key: (unsafe { &*pk }).clone(),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_destroy_encryption_context(ctx: *mut EncryptionContext) {
    if !ctx.is_null() { drop(unsafe { Box::from_raw(ctx) }); }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_create_decryption_context(level: SecurityLevel, sk: *const SecretKey) -> *mut DecryptionContext {
    Box::into_raw(Box::new(DecryptionContext {
        backend: Box::new(CpuBackend),
        params: level.get_params(),
        secret_key: (unsafe { &*sk }).clone(),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_destroy_decryption_context(ctx: *mut DecryptionContext) {
    if !ctx.is_null() { drop(unsafe { Box::from_raw(ctx) }); }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_create_evaluation_context(
    level: SecurityLevel,
    rlk: *const RelinearizationKey,
    bk: *const BootstrapKey,
    ksk: *const KeySwitchingKey,
) -> *mut EvaluationContext {
    Box::into_raw(Box::new(EvaluationContext {
        backend: Box::new(CpuBackend),
        params: level.get_params(),
        relinearization_key: (unsafe { &*rlk }).clone(),
        bootstrap_key: (unsafe { &*bk }).clone(),
        key_switching_key: (unsafe { &*ksk }).clone(),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_destroy_evaluation_context(ctx: *mut EvaluationContext) {
    if !ctx.is_null() { drop(unsafe { Box::from_raw(ctx) }); }
}


// #################################################################
// #                 핵심 기능 FFI 함수                            #
// #################################################################

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_encrypt(context: *const EncryptionContext, message: u64) -> *mut Ciphertext {
    let ctx = unsafe { &*context };
    let mut ephemeral_rng = rand_chacha::ChaCha20Rng::from_os_rng();
    let ct = ctx.backend.encrypt(message, &ctx.public_key, &mut ephemeral_rng, &ctx.params);
    Box::into_raw(Box::new(ct))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_decrypt(context: *const DecryptionContext, ct: *const Ciphertext) -> u64 {
    let ctx = &unsafe { &*context };
    ctx.backend.decrypt(unsafe { &*ct }, &ctx.secret_key, &ctx.params)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_homomorphic_add(context: *const EvaluationContext, ct1: *const Ciphertext, ct2: *const Ciphertext) -> *mut Ciphertext {
    let ctx = &unsafe { &*context };
    let res = ctx.backend.homomorphic_add(unsafe { &*ct1 }, unsafe { &*ct2 }, &ctx.params);
    Box::into_raw(Box::new(res))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_homomorphic_sub(context: *const EvaluationContext, ct1: *const Ciphertext, ct2: *const Ciphertext) -> *mut Ciphertext {
    let ctx = &unsafe { &*context };
    let res = ctx.backend.homomorphic_sub(unsafe { &*ct1 }, unsafe { &*ct2 }, &ctx.params);
    Box::into_raw(Box::new(res))
}


#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_homomorphic_mul(context: *const EvaluationContext, ct1: *const Ciphertext, ct2: *const Ciphertext) -> *mut Ciphertext {
    let ctx = &unsafe { &*context };
    let res = ctx.backend.homomorphic_mul(unsafe { &*ct1 }, unsafe { &*ct2 }, &ctx.relinearization_key, &ctx.params);
    Box::into_raw(Box::new(res))
}

// #################################################################
// #                직렬화/역직렬화 및 메모리 관리                  #
// #################################################################

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_ciphertext_to_json_str(obj: *const Ciphertext, level: SecurityLevel) -> *mut c_char {
    let rust_obj = unsafe { &*obj };
    let json_str = serde_json::to_string(&CipherObject {
        payload: rust_obj.clone(),
        security_level: level,
    }).unwrap();
    CString::new(json_str).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_ciphertext_from_json_str(json_str: *const c_char) -> *mut Ciphertext {
    let c_str = unsafe { CStr::from_ptr(json_str) };
    let rust_str = c_str.to_str().unwrap();
    let ct_obj: CipherObject = serde_json::from_str(rust_str).unwrap();
    Box::into_raw(Box::new(ct_obj.payload))
}

unsafe fn serialize_key_from_json_str<'de, K: Key + Serialize + Deserialize<'de> + Clone>(obj: *const K, level: SecurityLevel) -> *mut c_char {
    let rust_obj = unsafe { &*obj };
    let json_str = serde_json::to_string(&KeyObject::<K>::new(rust_obj.clone(), level)).unwrap();
    CString::new(json_str).unwrap().into_raw()
}

unsafe fn deserialize_key_to_json_str<'de, K: Key + Serialize + Deserialize<'de> + Clone>(json_str: *const c_char) -> *mut K {
    let c_str = unsafe { CStr::from_ptr(json_str) };
    let rust_str = c_str.to_str().unwrap();
    let key_obj: KeyObject<K> = serde_json::from_str(rust_str).unwrap();
    Box::into_raw(Box::new(key_obj.clone_payload()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_sk_to_json_str(obj: *const SecretKey, level: SecurityLevel) -> *mut c_char {
    unsafe { serialize_key_from_json_str::<SecretKey>(obj, level) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_sk_from_json_str(json_str: *const c_char) -> *mut SecretKey {
    unsafe { deserialize_key_to_json_str::<SecretKey>(json_str) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_pk_to_json_str(obj: *const PublicKey, level: SecurityLevel) -> *mut c_char {
    unsafe { serialize_key_from_json_str::<PublicKey>(obj, level) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_pk_from_json_str(json_str: *const c_char) -> *mut PublicKey {
    unsafe { deserialize_key_to_json_str::<PublicKey>(json_str) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_rlk_to_json_str(obj: *const RelinearizationKey, level: SecurityLevel) -> *mut c_char {
    unsafe { serialize_key_from_json_str::<RelinearizationKey>(obj, level) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_rlk_from_json_str(json_str: *const c_char) -> *mut RelinearizationKey {
    unsafe { deserialize_key_to_json_str::<RelinearizationKey>(json_str) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_bk_to_json_str(obj: *const BootstrapKey, level: SecurityLevel) -> *mut c_char {
    unsafe { serialize_key_from_json_str::<BootstrapKey>(obj, level) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_bk_from_json_str(json_str: *const c_char) -> *mut BootstrapKey {
    unsafe { deserialize_key_to_json_str::<BootstrapKey>(json_str) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_ksk_to_json_str(obj: *const KeySwitchingKey, level: SecurityLevel) -> *mut c_char {
    unsafe { serialize_key_from_json_str::<KeySwitchingKey>(obj, level) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_ksk_from_json_str(json_str: *const c_char) -> *mut KeySwitchingKey {
    unsafe { deserialize_key_to_json_str::<KeySwitchingKey>(json_str) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_free_string(ptr: *mut c_char) {
    if !ptr.is_null() { drop(unsafe { CString::from_raw(ptr) }); }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_ciphertext_destroy(obj: *mut Ciphertext) {
    if !obj.is_null() { drop(unsafe { Box::from_raw(obj) }); }
}

unsafe fn key_destroy<'de, K: Key + Serialize + Deserialize<'de> + Clone>(obj: *mut K) {
    if !obj.is_null() { drop(unsafe { Box::from_raw(obj) }); }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_secret_key_destroy(obj: *mut SecretKey) {
    unsafe { key_destroy(obj) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_public_key_destroy(obj: *mut PublicKey) {
    unsafe { key_destroy(obj) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_relinearization_key_destroy(obj: *mut RelinearizationKey) {
    unsafe { key_destroy(obj) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_bootstrap_key_destroy(obj: *mut BootstrapKey) {
    unsafe { key_destroy(obj) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_key_switching_key_destroy(obj: *mut KeySwitchingKey) {
    unsafe { key_destroy(obj) };
}