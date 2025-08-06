use crate::core::{polynomial::Polynomial, Ciphertext, GgswCiphertext, SecurityLevel};
use crate::hal::HardwareBackend;

use chacha20::{
    XChaCha20,
    Key as ChaCha20Key,
    XNonce as ChaCha20XNonce // Use XNonce for 24-byte nonces
};
use chacha20::cipher::{KeyIvInit, StreamCipher};

use serde::{Serialize, Deserialize};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// 재선형화(Relinearization)를 위한 키입니다.
/// 비밀키의 제곱(s^2)을 암호화한 값입니다.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelinearizationKey(pub Vec<Ciphertext>);

/// 비밀키는 4원수들의 벡터입니다.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretKey(pub Vec<Polynomial>);

/// 키 스위칭(Key Switching)을 위한 키입니다.
/// 가젯 분해를 사용하여 생성됩니다.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeySwitchingKey {
    pub key: Vec<Vec<Ciphertext>>,
}

/// 프로그래머블 부트스트래핑(Programmable Bootstrapping)을 위한 키입니다.
/// LWE 비밀키를 GGSW 형태로 암호화한 것입니다.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapKey {
    pub ggsw_vector: Vec<GgswCiphertext>,
}



/// 공개키 구조체. (b, a) 쌍으로 구성됩니다.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub a_vec: Vec<Polynomial>, // 기존 a_vec과 동일한 역할
    pub b: Polynomial,
}


/// 32바이트(256비트)의 고엔트로피 마스터 키
#[derive(Clone, Serialize, Deserialize)]
pub struct MasterKey(pub [u8; 32]);

/// 16바이트(128비트)의 공개 솔트
#[derive(Clone, Serialize, Deserialize)]
pub struct Salt(pub [u8; 24]);

pub fn generate_keys<B : HardwareBackend<'static, 'static, 'static>>(
    level: SecurityLevel,
    master_key: &MasterKey,
    salt: &Salt,
    backend: &B
) -> (SecretKey, PublicKey, KeySwitchingKey, RelinearizationKey, BootstrapKey) {
    // 1. 마스터 키와 솔트(for nonce) 로드
    let master_key_slice = master_key.0;
    let salt_slice = salt.0; // This is your 24-byte salt
    let chacha20_key = ChaCha20Key::from_slice(&master_key_slice);
    
    // ❗ FIX: Use XNonce which is specifically for 24-byte nonces.
    let chacha20_nonce = ChaCha20XNonce::from_slice(&salt_slice);

    // 2. 확장 엔진(XChaCha20)으로 시드(Seed) 생성
    // ❗ FIX: Explicitly initialize XChaCha20 instead of the base ChaCha20.
    let mut cipher = XChaCha20::new(&chacha20_key, &chacha20_nonce);
    let mut seed = [0u8; 32];
    cipher.apply_keystream(&mut seed);
    
    // 3. 샘플링 엔진(CSPRNG) 초기화
    let mut sampling_rng = ChaCha20Rng::from_seed(seed);

    // 4. 결정론적 키 생성 (This part remains the same)
    let params = level.get_params();
    let sk = backend.generate_secret_key(&mut sampling_rng, &params);
    
    #[cfg(debug_assertions)]
    println!("Secret key generated.");

    let pk = backend.generate_public_key(&sk, &mut sampling_rng, &params);

    #[cfg(debug_assertions)]
    println!("Public key generated.");

    let rlk = backend.generate_relinearization_key(&sk, &mut sampling_rng, &params);

    #[cfg(debug_assertions)]
    println!("Relinearization key generated.");

    let ksk = backend.generate_key_switching_key(&sk, &sk, &mut sampling_rng, &params);

    #[cfg(debug_assertions)]
    println!("Key-switching key generated.");
    
    let bk = backend.generate_bootstrap_key(&sk, &mut sampling_rng, &params);

    #[cfg(debug_assertions)]
    println!("Bootstrap key generated.");
    

    (sk, pk, ksk, rlk, bk)
}