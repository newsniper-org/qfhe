// src/ffi.rs

use std::ffi::{CString, CStr};
use std::os::raw::c_char;
use std::fs::File;
use std::io::{BufWriter, Read};

use crate::core::{
    keys::BootstrapKey, Ciphertext, keys::EvaluationKey, Polynomial, keys::PublicKey, QfheParameters, 
    keys::RelinearizationKey, keys::SecretKey, SecurityLevel, keys::MasterKey, keys::Salt, keys::generate_keys,
};
use crate::hal::{CpuBackend, HardwareBackend};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::OsRng;
use serde::Deserialize;
use crate::serialization::{KeyObject, CipherObject, Capsule, KeyType, Key};
use serde::{Serialize, de::DeserializeOwned};

// --- Context Structs ---

pub struct EncryptionContext {
    params: QfheParameters<'static, 'static, 'static>,
    public_key: PublicKey,
}

pub struct DecryptionContext {
    params: QfheParameters<'static, 'static, 'static>,
    secret_key: SecretKey,
}

pub struct EvaluationContext {
    params: QfheParameters<'static, 'static, 'static>,
    relinearization_key: Option<Box<RelinearizationKey>>,
    bootstrap_key: Option<Box<BootstrapKey>>,
    evaluation_key_conj: Option<Box<EvaluationKey>>,
}

// --- Key Generation ---

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_generate_keys(
    level: SecurityLevel,
    master_key_ptr: *const u8,
    salt_ptr: *const u8,
    sk_out: *mut *mut SecretKey,
    pk_out: *mut *mut PublicKey,
    rlk_out: *mut *mut RelinearizationKey,
    evk_conj_out: *mut *mut EvaluationKey,
    bk_out: *mut *mut BootstrapKey,
) {
    let master_key = MasterKey((*unsafe { std::slice::from_raw_parts(master_key_ptr, 32) }).try_into().unwrap());
    let salt = Salt((*unsafe { std::slice::from_raw_parts(salt_ptr, 24) }).try_into().unwrap());
    let backend = CpuBackend;

    let (sk, pk, rlk, evk_conj, bk) = generate_keys(level, &master_key, &salt, &backend);

    unsafe { *sk_out = Box::into_raw(Box::new(sk)) };
    unsafe { *pk_out = Box::into_raw(Box::new(pk)) };
    unsafe { *rlk_out = Box::into_raw(Box::new(rlk)) };
    unsafe { *evk_conj_out = Box::into_raw(Box::new(evk_conj)) };
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





#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_key_to_file(
    key_ptr: *const u8, // C의 void* 역할
    key_type: KeyType,
    level: SecurityLevel,
    path_str: *const c_char,
) -> i32 {
    let path = unsafe { CStr::from_ptr(path_str).to_str().unwrap() };
    let file = match File::create(path) {
        Ok(f) => f,
        Err(_) => return -1,
    };
    let writer = BufWriter::new(file);

    let result = match key_type {
        KeyType::SK => serde_json::to_writer(writer, &KeyObject::new(unsafe { &*(key_ptr as *const SecretKey) }.clone(), level)),
        KeyType::PK => serde_json::to_writer(writer, &KeyObject::new(unsafe { &*(key_ptr as *const PublicKey) }.clone(), level)),
        KeyType::RLK => serde_json::to_writer(writer, &KeyObject::new(unsafe { &*(key_ptr as *const RelinearizationKey) }.clone(), level)),
        KeyType::BK => serde_json::to_writer(writer, &KeyObject::new(unsafe { &*(key_ptr as *const BootstrapKey) }.clone(), level)),
        KeyType::EVK => serde_json::to_writer(writer, &KeyObject::new(unsafe { &*(key_ptr as *const EvaluationKey) }.clone(), level)),
    };

    if result.is_ok() { 0 } else { -1 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_key_from_file(
    key_type: KeyType,
    path_str: *const c_char,
) -> *mut u8 { // C의 void* 역할
    let path = unsafe { CStr::from_ptr(path_str).to_str().unwrap() };
    let json_str: String = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match key_type {
        KeyType::SK => {
            let key_obj: KeyObject<SecretKey> = serde_json::from_str(json_str.as_str()).unwrap();
            Box::into_raw(Box::new(key_obj.clone_payload())) as *mut u8
        },
        KeyType::PK => {
            let key_obj: KeyObject<PublicKey> = serde_json::from_str(json_str.as_str()).unwrap();
            Box::into_raw(Box::new(key_obj.clone_payload())) as *mut u8
        },
        KeyType::RLK => {
            let key_obj: KeyObject<RelinearizationKey> = serde_json::from_str(json_str.as_str()).unwrap();
            Box::into_raw(Box::new(key_obj.clone_payload())) as *mut u8
        },
        KeyType::BK => {
            let key_obj: KeyObject<BootstrapKey> = serde_json::from_str(json_str.as_str()).unwrap();
            Box::into_raw(Box::new(key_obj.clone_payload())) as *mut u8
        },
        KeyType::EVK => {
            let key_obj: KeyObject<EvaluationKey> = serde_json::from_str(json_str.as_str()).unwrap();
            Box::into_raw(Box::new(key_obj.clone_payload())) as *mut u8
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_serialize_ciphertext_to_file(
    ct_ptr: *const Ciphertext, // C의 void* 역할
    level: SecurityLevel,
    path_str: *const c_char,
) -> i32 {
    let path = unsafe { CStr::from_ptr(path_str).to_str().unwrap() };
    let file = match File::create(path) {
        Ok(f) => f,
        Err(_) => return -1,
    };
    let writer = BufWriter::new(file);

    let result = serde_json::to_writer(writer, &CipherObject {security_level: level, payload: (unsafe { &*ct_ptr }).clone()});

    if result.is_ok() { 0 } else { -1 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_deserialize_ciphertext_from_file(path_str: *const c_char) -> *mut Ciphertext {
    let path = unsafe { CStr::from_ptr(path_str).to_str().unwrap() };
    let json_str: String = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let ct_obj: CipherObject = serde_json::from_str(json_str.as_str()).unwrap();
    Box::into_raw(Box::new(ct_obj.payload))
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
