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