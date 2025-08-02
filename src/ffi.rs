// SimdPolynomial을 사용하도록 use 문을 수정합니다.
use crate::core::{
    Ciphertext, QfheEngine, SimdPolynomial, Quaternion, SecretKey, SecurityLevel, QfheParameters,
    RelinearizationKey, BootstrapKey, KeySwitchingKey
};
use crate::hal::{CpuBackend, HardwareBackend};
use rand::Rng;

// QfheContext 구조체는 변경할 필요가 없습니다.
// 내부 필드들의 타입(SecretKey 등) 정의가 이미 core/mod.rs에서 SimdPolynomial을 사용하도록 변경되었기 때문입니다.
#[repr(C)]
pub struct QfheContext {
    backend: Box<dyn HardwareBackend>,
    secret_key: SecretKey,
    relinearization_key: RelinearizationKey,
    bootstrap_key: BootstrapKey,
    keyswitching_key: KeySwitchingKey,
    params: QfheParameters,
}

// QfheEngine 트레이트 구현부도 시그니처는 동일하므로 변경할 필요가 없습니다.
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

    fn bootstrap(&self, ct: &Ciphertext, test_poly: &SimdPolynomial) -> Ciphertext {
        self.backend.bootstrap(ct, test_poly, &self.bootstrap_key, &self.keyswitching_key, &self.params)
    }

    fn modulus_switch(&self, ct: &Ciphertext) -> Ciphertext {
        self.backend.modulus_switch(ct, &self.params)
    }
}

// [수정] 컨텍스트 생성 시, SimdPolynomial 구조에 맞게 비밀키를 초기화합니다.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qfhe_context_create(level: SecurityLevel) -> *mut QfheContext {
    let params = level.get_params();
    let mut rng = rand::thread_rng();
    
    let secret_key_vec = (0..params.module_dimension_k).map(|_| {
        let n = params.polynomial_degree;
        let mut w = vec![0u128; n];
        let mut x = vec![0u128; n];
        let mut y = vec![0u128; n];
        let mut z = vec![0u128; n];

        for i in 0..n {
            let val: i128 = rng.gen_range(-1..=1);
            let val_mod_q = val.rem_euclid(params.modulus_q as i128) as u128;
            w[i] = val_mod_q;
            x[i] = val_mod_q;
            y[i] = val_mod_q;
            z[i] = val_mod_q;
        }

        SimdPolynomial { w, x, y, z }
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