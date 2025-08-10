// src/ffi.rs

use std::ffi::{CString, CStr};
use std::os::raw::{c_char, c_void}; // c_void 추가
use std::fs::File;
use std::io::{BufWriter, Read, BufReader};

use crate::core::{
    keys::BootstrapKey, Ciphertext, keys::EvaluationKey, Polynomial, keys::PublicKey, QfheParameters, 
    keys::RelinearizationKey, keys::SecretKey, SecurityLevel, keys::MasterKey, keys::Salt,
};
use crate::hal::{CpuBackend, HardwareBackend};
use chacha20::cipher::KeyIvInit;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::OsRng;
use serde::Deserialize;
use crate::serialization::{CipherObject, KeyType, Key, parse_key_binary};
use serde::{Serialize, de::DeserializeOwned};

use chacha20::{XChaCha20, Key as XChaCha20Key, XNonce, cipher::StreamCipher};

// --- Context Structs ---

pub struct EncryptionContext {
    params: QfheParameters<'static>,
    public_key: PublicKey,
}

pub struct DecryptionContext {
    params: QfheParameters<'static>,
    secret_key: SecretKey,
}

pub struct EvaluationContext {
    params: QfheParameters<'static>,
    relinearization_key: Option<Box<RelinearizationKey>>,
    bootstrap_key: Option<Box<BootstrapKey>>,
    evaluation_key_conj: Option<Box<EvaluationKey>>,
}

// --- Key Generation ---

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_generate_essential_keys(
    level: SecurityLevel,
    master_key_ptr: *const u8,
    salt_ptr: *const u8,
    sk_out: *mut *mut SecretKey,
    pk_out: *mut *mut PublicKey,
    rlk_out: *mut *mut RelinearizationKey,
) {
    let master_key = MasterKey((*unsafe { std::slice::from_raw_parts(master_key_ptr, 32) }).try_into().unwrap());
    let salt = Salt((*unsafe { std::slice::from_raw_parts(salt_ptr, 24) }).try_into().unwrap());
    let backend = CpuBackend;
    let params = level.get_params();

    // 결정론적 RNG 생성
    let mut chacha_rng = {
        let chacha_key = XChaCha20Key::from_slice(&master_key.0);
        let chacha_nonce = XNonce::from_slice(&salt.0);
        let mut cipher = XChaCha20::new(chacha_key, chacha_nonce);
        let mut seed = [0u8; 32];
        cipher.apply_keystream(&mut seed);
        ChaCha20Rng::from_seed(seed)
    };
    
    let sk = backend.generate_secret_key(&mut chacha_rng, &params);
    let pk = backend.generate_public_key(&sk, &mut chacha_rng, &params);
    let rlk = backend.generate_relinearization_key(&sk, &mut chacha_rng, &params);

    unsafe { *sk_out = Box::into_raw(Box::new(sk)) };
    unsafe { *pk_out = Box::into_raw(Box::new(pk)) };
    unsafe { *rlk_out = Box::into_raw(Box::new(rlk)) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_generate_conjugation_key(
    level: SecurityLevel,
    sk_ptr: *const SecretKey,
    evk_conj_out: *mut *mut EvaluationKey,
) {
    let sk = unsafe { &*sk_ptr };
    let backend = CpuBackend;
    let params = level.get_params();
    let mut os_rng = ChaCha20Rng::from_os_rng(); 

    // 동형 켤레를 위한 평가 키 생성
    let s1_conj = {
        let mut s1_conj_poly = sk.s1.clone();
        for i in 0..params.polynomial_degree {
            for j in 0..params.modulus_q.len() {
                let q_j = params.modulus_q[j];
                s1_conj_poly.coeffs[i].x[j] = q_j.wrapping_sub(s1_conj_poly.coeffs[i].x[j]);
                s1_conj_poly.coeffs[i].y[j] = q_j.wrapping_sub(s1_conj_poly.coeffs[i].y[j]);
                s1_conj_poly.coeffs[i].z[j] = q_j.wrapping_sub(s1_conj_poly.coeffs[i].z[j]);
            }
        }
        s1_conj_poly
    };
    let evk_conj = backend.generate_evaluation_key(&s1_conj, sk, &mut os_rng, &params);
    unsafe { *evk_conj_out = Box::into_raw(Box::new(evk_conj)) };
}


#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_generate_bootstrap_key(
    level: SecurityLevel,
    sk_ptr: *const SecretKey,
    pk_ptr: *const PublicKey, // ✅ 공개키 포인터를 인자로 받도록 추가
    bk_out: *mut *mut BootstrapKey,
) {
    let sk = unsafe { &*sk_ptr };
    let pk = unsafe { &*pk_ptr }; // ✅ 공개키 참조
    let backend = CpuBackend;
    let params = level.get_params();
    let mut os_rng = ChaCha20Rng::from_os_rng();

    // ✅ 부트스트래핑 키 생성 시 pk를 전달
    let bk = backend.generate_bootstrap_key(sk, pk, &mut os_rng, &params);
    unsafe { *bk_out = Box::into_raw(Box::new(bk)) };
}

// --- Context Management ---

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_create_encryption_context(level: SecurityLevel, pk: *const PublicKey) -> *mut EncryptionContext {
    Box::into_raw(Box::new(EncryptionContext {
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
    evk_conj: *const EvaluationKey,
) -> *mut EvaluationContext {
    Box::into_raw(Box::new(EvaluationContext {
        params: level.get_params(),
        relinearization_key: if rlk.is_null() { None } else { Some(Box::new((unsafe { &*rlk }).clone())) },
        bootstrap_key: if bk.is_null() { None } else { Some(Box::new((unsafe { &*bk }).clone())) },
        evaluation_key_conj: if evk_conj.is_null() { None } else { Some(Box::new((unsafe { &*evk_conj }).clone())) },
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_destroy_evaluation_context(ctx: *mut EvaluationContext) {
    if !ctx.is_null() { drop(unsafe { Box::from_raw(ctx) }); }
}

// --- Core HE Functions ---

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_encrypt(context: *const EncryptionContext, message: u64) -> *mut Ciphertext {
    let ctx = unsafe { &*context };
    let backend = CpuBackend;
    let mut ephemeral_rng = ChaCha20Rng::from_os_rng();
    let ct = backend.encrypt(message, &ctx.public_key, &mut ephemeral_rng, &ctx.params);
    Box::into_raw(Box::new(ct))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_decrypt(context: *const DecryptionContext, ct: *const Ciphertext) -> u64 {
    let ctx = unsafe { &*context };
    let backend = CpuBackend;
    backend.decrypt(unsafe { &*ct }, &ctx.secret_key, &ctx.params)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_homomorphic_add(ct1: *const Ciphertext, ct2: *const Ciphertext, level: SecurityLevel) -> *mut Ciphertext {
    let backend = CpuBackend;
    let params = level.get_params();
    let res = backend.homomorphic_add(unsafe { &*ct1 }, unsafe { &*ct2 }, &params);
    Box::into_raw(Box::new(res))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_homomorphic_mul(context: *const EvaluationContext, ct1: *const Ciphertext, ct2: *const Ciphertext) -> *mut Ciphertext {
    let ctx = unsafe { &*context };
    let backend = CpuBackend;
    let rlk = ctx.relinearization_key.as_ref().expect("RelinearizationKey is required for multiplication.");
    let res = backend.homomorphic_mul(unsafe { &*ct1 }, unsafe { &*ct2 }, rlk, &ctx.params);
    Box::into_raw(Box::new(res))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_bootstrap(context: *const EvaluationContext, ct: *const Ciphertext, test_poly: *const Polynomial) -> *mut Ciphertext {
    let ctx = unsafe { &*context };
    let backend = CpuBackend;
    let bk = ctx.bootstrap_key.as_ref().expect("BootstrapKey is required for bootstrapping.");
    let res = backend.bootstrap(unsafe { &*ct }, unsafe { &*test_poly }, bk, &ctx.params);
    Box::into_raw(Box::new(res))
}

// --- Helper for C Demos ---
#[unsafe(no_mangle)]
pub extern "C" fn qfhe_create_test_poly_f_2x(level: SecurityLevel) -> *mut Polynomial {
    let params = level.get_params();
    let mut test_poly = Polynomial::zero(params.polynomial_degree, params.modulus_q.len());
    let lut_scaling = params.scaling_factor_delta / (2 * params.polynomial_degree as u128);
    for i in 0..(params.plaintext_modulus as usize) {
         let val = (2 * i as u128) % params.plaintext_modulus as u128;
         let scaled_val = val * lut_scaling;
         test_poly.coeffs[i].w = crate::core::rns::integer_to_rns(scaled_val, &params.modulus_q);
    }
    Box::into_raw(Box::new(test_poly))
}


// --- Serialization / Deserialization ---

// FFI 함수 반환 타입 정의
#[repr(C)]
pub enum QfheResult {
    Success = 0,
    IoError = -1,
    JsonParseError = -2,
    NullPointerError = -3,
    Utf8Error = -4,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_key_to_file(
    key_ptr: *const c_void, // C의 void* 역할
    key_type: KeyType,
    level: SecurityLevel,
    path_str: *const c_char,
) -> QfheResult {
    if path_str.is_null() || key_ptr.is_null() {
        return QfheResult::NullPointerError;
    }
    
    let path = match unsafe { CStr::from_ptr(path_str).to_str() } {
        Ok(p) => p,
        Err(_) => return QfheResult::Utf8Error,
    };

    let file = match File::create(path) {
        Ok(f) => f,
        Err(_) => return QfheResult::IoError,
    };

    let writer = BufWriter::new(file);

    let result = match key_type {
        KeyType::SK => serde_json::to_writer(writer, unsafe { &*(key_ptr as *const SecretKey) }),
        KeyType::PK => serde_json::to_writer(writer, unsafe { &*(key_ptr as *const PublicKey) }),
        KeyType::RLK => serde_json::to_writer(writer, unsafe { &*(key_ptr as *const RelinearizationKey) }),
        KeyType::BK => serde_json::to_writer(writer, unsafe { &*(key_ptr as *const BootstrapKey) }),
        KeyType::EVK => serde_json::to_writer(writer, unsafe { &*(key_ptr as *const EvaluationKey) }),
    };

    match result {
        Ok(_) => QfheResult::Success,
        Err(_) => QfheResult::IoError
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_key_to_file_binary(
    key_ptr: *const c_void,
    key_type: KeyType,
    level: SecurityLevel, // ✅ 레벨 파라미터 추가
    path_str: *const c_char,
) -> QfheResult {
    // ... (null check) ...
    if path_str.is_null() || key_ptr.is_null() {
        return QfheResult::NullPointerError;
    }
    
    let path = match unsafe { CStr::from_ptr(path_str).to_str() } {
        Ok(p) => p,
        Err(_) => return QfheResult::Utf8Error,
    };

    let file = match File::create(path) {
        Ok(f) => f,
        Err(_) => return QfheResult::IoError,
    };

    let mut writer = BufWriter::new(file);

    // ✅ 새로운 직렬화 함수 호출
    let result = match key_type {
        KeyType::SK => unsafe { &*(key_ptr as *const SecretKey) }.serialize_to_binary(level, &mut writer),
        KeyType::PK => unsafe { &*(key_ptr as *const PublicKey) }.serialize_to_binary(level, &mut writer),
        KeyType::RLK => unsafe { &*(key_ptr as *const RelinearizationKey) }.serialize_to_binary(level, &mut writer),
        KeyType::BK => unsafe { &*(key_ptr as *const BootstrapKey) }.serialize_to_binary(level, &mut writer),
        KeyType::EVK => unsafe { &*(key_ptr as *const EvaluationKey) }.serialize_to_binary(level, &mut writer)
    };
    
    if result.is_ok() { QfheResult::Success } else { QfheResult::IoError }
}



#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_key_from_file(
    key_type: KeyType,
    key_out: *mut *mut c_void,
    path_str: *const c_char,
) -> QfheResult { // C의 void* 역할
    if path_str.is_null() || key_out.is_null() {
        return QfheResult::NullPointerError;
    }

    // 2. 경로 문자열 변환
    let path = match unsafe { CStr::from_ptr(path_str).to_str() } {
        Ok(p) => p,
        Err(_) => return QfheResult::Utf8Error,
    };

    // 3. 파일 읽기
    let json_str = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return QfheResult::IoError,
    };

    match key_type {
        KeyType::SK => {
            match SecretKey::deserialize(&mut serde_json::Deserializer::from_str(&json_str)) {
                Ok(key_obj) => {
                    unsafe { *key_out = Box::into_raw(Box::new(key_obj)) as *mut c_void }
                    QfheResult::Success
                },
                Err(_) => {
                    unsafe { *key_out = std::ptr::null_mut() };
                    QfheResult::JsonParseError
                }
            }
        },
        KeyType::PK => {
            match PublicKey::deserialize(&mut serde_json::Deserializer::from_str(&json_str)) {
                Ok(key_obj) => {
                    unsafe { *key_out = Box::into_raw(Box::new(key_obj)) as *mut c_void }
                    QfheResult::Success
                },
                Err(_) => {
                    unsafe { *key_out = std::ptr::null_mut() };
                    QfheResult::JsonParseError
                }
            }
        },
        KeyType::RLK => {
            match RelinearizationKey::deserialize(&mut serde_json::Deserializer::from_str(&json_str)) {
                Ok(key_obj) => {
                    unsafe { *key_out = Box::into_raw(Box::new(key_obj)) as *mut c_void }
                    QfheResult::Success
                },
                Err(_) => {
                    unsafe { *key_out = std::ptr::null_mut() };
                    QfheResult::JsonParseError
                }
            }
        },
        KeyType::BK => {
            match BootstrapKey::deserialize(&mut serde_json::Deserializer::from_str(&json_str)) {
                Ok(key_obj) => {
                    unsafe { *key_out = Box::into_raw(Box::new(key_obj)) as *mut c_void }
                    QfheResult::Success
                },
                Err(_) => {
                    unsafe { *key_out = std::ptr::null_mut() };
                    QfheResult::JsonParseError
                }
            }
        },
        KeyType::EVK => {
            match EvaluationKey::deserialize(&mut serde_json::Deserializer::from_str(&json_str)) {
                Ok(key_obj) => {
                    unsafe { *key_out = Box::into_raw(Box::new(key_obj)) as *mut c_void }
                    QfheResult::Success
                },
                Err(_) => {
                    unsafe { *key_out = std::ptr::null_mut() };
                    QfheResult::JsonParseError
                }
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_key_from_file_binary(
    key_out: *mut *mut c_void,
    // ✅ KeyType은 더 이상 필요 없음. 헤더에 정보가 포함되기 때문.
    // key_type: KeyType, 
    path_str: *const c_char,
) -> QfheResult {
    // ... (null check) ...
    if path_str.is_null() || key_out.is_null() {
        return QfheResult::NullPointerError;
    }

    // 2. 경로 문자열 변환
    let path = match unsafe { CStr::from_ptr(path_str).to_str() } {
        Ok(p) => p,
        Err(_) => return QfheResult::Utf8Error,
    };
    let file = match File::open(path) {
        Ok(f) => f, Err(_) => return QfheResult::IoError,
    };
    let mut reader = BufReader::new(file);

    let result = parse_key_binary(&mut reader);

    if result.is_err() {
        return QfheResult::IoError;
    }

    let (security_level, key_type, payload) = result.unwrap();
    unsafe {
        *key_out = match key_type {
            KeyType::SK => SecretKey::deserialize_from_payload(&payload).map(|k| Box::into_raw(Box::new(k)) as *mut c_void).unwrap_or(std::ptr::null_mut()),
            KeyType::PK => PublicKey::deserialize_from_payload(&payload).map(|k| Box::into_raw(Box::new(k)) as *mut c_void).unwrap_or(std::ptr::null_mut()),
            KeyType::RLK => RelinearizationKey::deserialize_from_payload(&payload).map(|k| Box::into_raw(Box::new(k)) as *mut c_void).unwrap_or(std::ptr::null_mut()),
            KeyType::EVK => EvaluationKey::deserialize_from_payload(&payload).map(|k| Box::into_raw(Box::new(k)) as *mut c_void).unwrap_or(std::ptr::null_mut()),
            KeyType::BK => BootstrapKey::deserialize_from_payload(&payload).map(|k| Box::into_raw(Box::new(k)) as *mut c_void).unwrap_or(std::ptr::null_mut())
        };
    }
    QfheResult::Success
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_ciphertext_to_file(
    ct_ptr: *const Ciphertext, // C의 void* 역할
    level: SecurityLevel,
    path_str: *const c_char,
) -> QfheResult {
    if path_str.is_null() || ct_ptr.is_null() {
        return QfheResult::NullPointerError;
    }

    let path = match unsafe { CStr::from_ptr(path_str).to_str() } {
        Ok(p) => p,
        Err(_) => return QfheResult::Utf8Error,
    };

    let file = match File::create(path) {
        Ok(f) => f,
        Err(_) => return QfheResult::IoError,
    };

    let writer = BufWriter::new(file);

    match serde_json::to_writer(writer, &CipherObject {security_level: level, payload: (unsafe { &*ct_ptr }).clone()}) {
        Ok(_) => QfheResult::Success,
        Err(_) => QfheResult::IoError
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_ciphertext_from_file(
    ct_out: *mut *mut Ciphertext, // 성공 시 Ciphertext 포인터를 저장할 위치
    path_str: *const c_char,
) -> QfheResult {
    // 1. 입력 포인터 유효성 검사
    if path_str.is_null() || ct_out.is_null() {
        return QfheResult::NullPointerError;
    }

    // 2. 경로 문자열 변환
    let path = match unsafe { CStr::from_ptr(path_str).to_str() } {
        Ok(p) => p,
        Err(_) => return QfheResult::Utf8Error,
    };

    // 3. 파일 읽기
    let json_str = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return QfheResult::IoError,
    };

    // 4. JSON 역직렬화
    match CipherObject::deserialize(&mut serde_json::Deserializer::from_str(&json_str)) {
        Ok(ct_obj) => {
            unsafe { *ct_out = Box::into_raw(Box::new(ct_obj.payload)) };
            QfheResult::Success
        }
        Err(_) => {
            unsafe { *ct_out = std::ptr::null_mut() };
            QfheResult::JsonParseError
        }
    }
}

// --- Memory Management ---

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_secret_key_destroy(obj: *mut SecretKey) { if !obj.is_null() { drop(unsafe { Box::from_raw(obj) }); } }
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_public_key_destroy(obj: *mut PublicKey) { if !obj.is_null() { drop(unsafe { Box::from_raw(obj) }); } }
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_relinearization_key_destroy(obj: *mut RelinearizationKey) { if !obj.is_null() { drop(unsafe { Box::from_raw(obj) }); } }
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_evaluation_key_destroy(obj: *mut EvaluationKey) { if !obj.is_null() { drop(unsafe { Box::from_raw(obj) }); } }
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_bootstrap_key_destroy(obj: *mut BootstrapKey) { if !obj.is_null() { drop(unsafe { Box::from_raw(obj) }); } }
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_ciphertext_destroy(obj: *mut Ciphertext) { if !obj.is_null() { drop(unsafe { Box::from_raw(obj) }); } }
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_polynomial_destroy(obj: *mut Polynomial) { if !obj.is_null() { drop(unsafe { Box::from_raw(obj) }); } }
