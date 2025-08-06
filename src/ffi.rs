use std::ffi::CString;

use std::ffi::CStr;

use crate::core::{
    BootstrapKey, Ciphertext, GgswCiphertext, KeySwitchingKey, Polynomial, PublicKey, QfheEngine, QfheParameters, Quaternion, RelinearizationKey, SecretKey, SecurityLevel, MasterKey, Salt, keys::generate_keys
};
use crate::hal::{CpuBackend, HardwareBackend};
use rand::{Rng, SeedableRng, TryRngCore};

use serde_json::{Serializer, Deserializer};

use rand_chacha::ChaCha20Rng;

use crate::{CipherObject, KeyObject, KeyType};

use rand_core::{OsRng, RngCore};


// QfheContext에 라이프타임 'a를 추가합니다.
#[repr(C)]
pub struct QfheContext {
    pub backend: Box<dyn HardwareBackend<'static, 'static, 'static> + 'static>,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub relinearization_key: RelinearizationKey,
    pub bootstrap_key: BootstrapKey,
    pub keyswitching_key: KeySwitchingKey,
    pub params: QfheParameters<'static, 'static, 'static>,
}

impl QfheContext {
    pub fn new_from_ref(
        backend: Box<dyn HardwareBackend<'static, 'static, 'static> + 'static>,
        secret_key: &SecretKey,
        public_key: &PublicKey,
        relinearization_key: &RelinearizationKey,
        bootstrap_key: &BootstrapKey,
        keyswitching_key: &KeySwitchingKey,
        level: SecurityLevel
    ) -> Self {
        let tmp = relinearization_key.clone();
        Self {
            backend,
            secret_key: secret_key.clone(),
            public_key: public_key.clone(),
            relinearization_key: relinearization_key.clone(),
            bootstrap_key: bootstrap_key.clone(),
            keyswitching_key: keyswitching_key.clone(),
            params: level.get_params()
        }
    }
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

pub fn setup_context(level: SecurityLevel) -> QfheContext {
    // 1. OsRng를 사용하여 안전한 무작위 마스터 키와 솔트 생성
    let mut master_key_bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut master_key_bytes).unwrap();
    let master_key = MasterKey(master_key_bytes);

    let mut salt_bytes = [0u8; 24];
    OsRng.try_fill_bytes(&mut salt_bytes).unwrap();
    let salt = Salt(salt_bytes);

    // 2. 결정론적 키 생성 함수 호출
    let backend = CpuBackend;
    let params = level.get_params();
    let (sk, pk, ksk, rlk, bsk) =
        generate_keys(level, &master_key, &salt, &backend);

    // 3. 테스트용 컨텍스트 구성
    QfheContext {
        backend: Box::new(backend),
        secret_key: sk,
        public_key: pk,
        relinearization_key: rlk,
        keyswitching_key: ksk,
        bootstrap_key: bsk,
        params,
    }
}




#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_load(
    level: SecurityLevel,
    secret_key: *const SecretKey,
    public_key: *const PublicKey,
    relinearization_key: *const RelinearizationKey,
    bootstrap_key: *const BootstrapKey,
    keyswitching_key: *const KeySwitchingKey
) -> *mut QfheContext {
    let backend = Box::new(CpuBackend);
    
    let context = Box::new(QfheContext::new_from_ref(
        backend,
        unsafe {
            &*secret_key
        },
        unsafe {
            &*public_key
        },
        unsafe {
            &*relinearization_key
        },
        unsafe {
            &*bootstrap_key
        },
        unsafe {
            &*keyswitching_key
        },
        level
    ));
    Box::into_raw(context)
}

// [수정] RNS 기반으로 키들을 생성합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_create(
    level: SecurityLevel
) -> *mut QfheContext {
    // 1. OsRng를 사용하여 안전한 무작위 마스터 키와 솔트 생성
    let mut master_key_bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut master_key_bytes).unwrap();
    let master_key = MasterKey(master_key_bytes);

    let mut salt_bytes = [0u8; 24];
    OsRng.try_fill_bytes(&mut salt_bytes).unwrap();
    let salt = Salt(salt_bytes);

    // 2. 결정론적 키 생성 함수 호출
    let backend = CpuBackend;
    let params = level.get_params();
    let (sk, pk, ksk, rlk, bsk) =
        generate_keys(level, &master_key, &salt, &backend);

    // 3. 테스트용 컨텍스트 구성
    Box::into_raw(Box::new(QfheContext {
        backend: Box::new(backend),
        secret_key: sk,
        public_key: pk,
        relinearization_key: rlk,
        keyswitching_key: ksk,
        bootstrap_key: bsk,
        params,
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_destroy(context_ptr: *mut QfheContext) {
    if !context_ptr.is_null() {
        drop(unsafe { Box::from_raw(context_ptr) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_get_sk(context: *const QfheContext) -> *const SecretKey {
    unsafe { &(*context).secret_key }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_get_pk(context: *const QfheContext) -> *const PublicKey {
    unsafe { &(*context).public_key }
}


#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_get_rlk(context: *const QfheContext) -> *const RelinearizationKey {
    unsafe { &(*context).relinearization_key }
}


#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_get_bk(context: *const QfheContext) -> *const BootstrapKey {
    unsafe { &(*context).bootstrap_key }
}


#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_get_ksk(context: *const QfheContext) -> *const KeySwitchingKey {
    unsafe { &(*context).keyswitching_key }
}


// 공개키를 받아 암호화하는 FFI 함수
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_encrypt(
    context: *const QfheContext,
    message: u64
) -> *mut Ciphertext {
    let ctx = unsafe { &*context };
    let ciphertext = Box::new(ctx.encrypt(message));
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

// --- 직렬화/역직렬화 FFI 함수들 ---

/// Rust의 Key 객체를 받아 JSON 문자열로 직렬화합니다.
/// 반환된 문자열은 반드시 qfhe_free_string으로 해제해야 합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_ciphertext_to_json_str(
    ciphertext_ptr: *const Ciphertext,
    level: SecurityLevel
) -> *mut std::os::raw::c_char {
    let result_json_str = serde_json::to_string(&CipherObject {payload: (unsafe{ &*ciphertext_ptr }).clone(), security_level: level}).unwrap();
    CString::new(result_json_str).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_ciphertext_from_json_str(json_str: *const std::os::raw::c_char) -> *mut Ciphertext {
    let c_str = unsafe { CStr::from_ptr(json_str) };
    let rust_str = c_str.to_str().unwrap();
    let ct_obj: CipherObject = serde_json::from_str(rust_str).unwrap();
    Box::into_raw(Box::new(ct_obj.payload.clone()))
}



#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_sk_to_json_str(
    key_ptr: *const SecretKey,
    level: SecurityLevel,
) -> *mut std::os::raw::c_char {
    let result_json_str = serde_json::to_string(&KeyObject { payload:  (unsafe { &*key_ptr }).clone(), security_level: level }).unwrap();
    CString::new(result_json_str).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_sk_from_json_str(json_str: *const std::os::raw::c_char) -> *mut SecretKey {
    let c_str = unsafe { CStr::from_ptr(json_str) };
    let rust_str = c_str.to_str().unwrap();
    let key_obj: KeyObject<SecretKey> = serde_json::from_str(rust_str).unwrap();
    Box::into_raw(Box::new(key_obj.payload.clone()))
}



#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_pk_to_json_str(
    key_ptr: *const PublicKey,
    level: SecurityLevel,
) -> *mut std::os::raw::c_char {
    let result_json_str = serde_json::to_string(&KeyObject { payload:  (unsafe { &*key_ptr }).clone(), security_level: level }).unwrap();
    CString::new(result_json_str).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_pk_from_json_str(json_str: *const std::os::raw::c_char) -> *mut PublicKey {
    let c_str = unsafe { CStr::from_ptr(json_str) };
    let rust_str = c_str.to_str().unwrap();
    let key_obj: KeyObject<PublicKey> = serde_json::from_str(rust_str).unwrap();
    Box::into_raw(Box::new(key_obj.payload.clone()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_rlk_to_json_str(
    key_ptr: *const RelinearizationKey,
    level: SecurityLevel,
) -> *mut std::os::raw::c_char {
    let result_json_str = serde_json::to_string(&KeyObject { payload:  (unsafe { &*key_ptr }).clone(), security_level: level }).unwrap();
    CString::new(result_json_str).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_rlk_from_json_str(json_str: *const std::os::raw::c_char) -> *mut RelinearizationKey {
    let c_str = unsafe { CStr::from_ptr(json_str) };
    let rust_str = c_str.to_str().unwrap();
    let key_obj: KeyObject<RelinearizationKey> = serde_json::from_str(rust_str).unwrap();
    Box::into_raw(Box::new(key_obj.payload.clone()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_bk_to_json_str(
    key_ptr: *const BootstrapKey,
    level: SecurityLevel,
) -> *mut std::os::raw::c_char {
    let result_json_str = serde_json::to_string(&KeyObject { payload:  (unsafe { &*key_ptr }).clone(), security_level: level }).unwrap();
    CString::new(result_json_str).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_bk_from_json_str(json_str: *const std::os::raw::c_char) -> *mut BootstrapKey {
    let c_str = unsafe { CStr::from_ptr(json_str) };
    let rust_str = c_str.to_str().unwrap();
    let key_obj: KeyObject<BootstrapKey> = serde_json::from_str(rust_str).unwrap();
    Box::into_raw(Box::new(key_obj.payload.clone()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_ksk_to_json_str(
    key_ptr: *const KeySwitchingKey,
    level: SecurityLevel,
) -> *mut std::os::raw::c_char {
    let result_json_str = serde_json::to_string(&KeyObject { payload:  (unsafe { &*key_ptr }).clone(), security_level: level }).unwrap();
    CString::new(result_json_str).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_ksk_from_json_str(json_str: *const std::os::raw::c_char) -> *mut KeySwitchingKey {
    let c_str = unsafe { CStr::from_ptr(json_str) };
    let rust_str = c_str.to_str().unwrap();
    let key_obj: KeyObject<KeySwitchingKey> = serde_json::from_str(rust_str).unwrap();
    Box::into_raw(Box::new(key_obj.payload.clone()))
}


#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_free_string(ptr: *mut std::os::raw::c_char) {
    // 1. 포인터가 유효한지 확인합니다.
    if ptr.is_null() {
        return;
    }
    
    // 2. C의 문자열 포인터(*mut c_char)를 다시 Rust의 CString으로 변환합니다.
    // CString::from_raw()는 포인터의 소유권을 다시 가져옵니다.
    let c_string = unsafe { CString::from_raw(ptr) };

    // 3. 함수가 종료되면서 c_string 변수가 범위를 벗어납니다(goes out of scope).
    // 이때 Rust의 메모리 관리자가 자동으로 CString이 차지하던 메모리를 안전하게 해제합니다.
    drop(c_string);
}