use crate::core::{polynomial::Polynomial, Ciphertext, GgswCiphertext, SecurityLevel};
use crate::hal::HardwareBackend;

use chacha20::{
    XChaCha20,
    Key as ChaCha20Key,
    XNonce as ChaCha20XNonce
};
use chacha20::cipher::{KeyIvInit, StreamCipher};

use serde::{Serialize, Deserialize};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// 재선형화(Relinearization)를 위한 키입니다.
/// 비밀키 s1의 제곱(s1^2)을 암호화한 값입니다.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelinearizationKey(pub Vec<Ciphertext>); // 내부 구조는 동형곱셈 구현 시 구체화

/// ✅ RLWE: 비밀키는 두 개의 다항식 (s1, s2)로 구성됩니다.
/// s1은 암/복호화에, s2는 동형 오토모피즘에 사용됩니다.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretKey {
    pub s1: Polynomial,
    pub s2: Polynomial
}

/// 키 스위칭(Key Switching) 및 오토모피즘을 위한 평가 키입니다.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationKey(pub Vec<Ciphertext>);


/// 프로그래머블 부트스트래핑(Programmable Bootstrapping)을 위한 키입니다.
/// LWE 비밀키를 GGSW 형태로 암호화한 것입니다.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapKey {
    pub ggsw_vector: Vec<GgswCiphertext>,
}

/// ✅ RLWE: 공개키는 (b, a) 쌍으로 구성됩니다.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub b: Polynomial,
    pub a: Polynomial,
}


/// 32바이트(256비트)의 고엔트로피 마스터 키
#[derive(Clone, Serialize, Deserialize)]
pub struct MasterKey(pub [u8; 32]);

/// 24바이트(192비트)의 공개 솔트
#[derive(Clone, Serialize, Deserialize)]
pub struct Salt(pub [u8; 24]);

/// ✅ RLWE: `generate_keys` 함수 구현
pub fn generate_keys<B : HardwareBackend<'static, 'static>>(
    level: SecurityLevel,
    master_key: &MasterKey,
    salt: &Salt,
    backend: &B
) -> (SecretKey, PublicKey, RelinearizationKey, EvaluationKey, BootstrapKey) {
    // 1. 마스터 키와 솔트로 결정론적 시드 생성
    let master_key_slice = master_key.0;
    let salt_slice = salt.0;
    let chacha20_key = ChaCha20Key::from_slice(&master_key_slice);
    let chacha20_nonce = ChaCha20XNonce::from_slice(&salt_slice);
    let mut cipher = XChaCha20::new(&chacha20_key, &chacha20_nonce);
    let mut seed = [0u8; 32];
    cipher.apply_keystream(&mut seed);
    
    // 2. 시드로 샘플링 RNG 초기화
    let mut sampling_rng = ChaCha20Rng::from_seed(seed);

    // 3. 백엔드를 통해 각 키 생성
    let params = level.get_params();
    let sk = backend.generate_secret_key(&mut sampling_rng, &params);
    let pk = backend.generate_public_key(&sk, &mut sampling_rng, &params);
    
    let rlk = backend.generate_relinearization_key(&sk, &mut sampling_rng, &params);
    
    // 동형 켤레를 위한 평가 키 생성 (s1_conj -> s1)
    let mut s1_conj = sk.s1.clone();
    for i in 0..params.polynomial_degree {
        for j in 0..params.modulus_q.len() {
            let q_j = params.modulus_q[j];
            s1_conj.coeffs[i].x[j] = q_j.wrapping_sub(s1_conj.coeffs[i].x[j]);
            s1_conj.coeffs[i].y[j] = q_j.wrapping_sub(s1_conj.coeffs[i].y[j]);
            s1_conj.coeffs[i].z[j] = q_j.wrapping_sub(s1_conj.coeffs[i].z[j]);
        }
    }
    let evk = backend.generate_evaluation_key(&s1_conj, &sk, &mut sampling_rng, &params);
    
    let bk = backend.generate_bootstrap_key(&sk, &mut sampling_rng, &params);

    (sk, pk, rlk, evk, bk)
}