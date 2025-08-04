use crate::core::{Ciphertext, polynomial::Polynomial, GgswCiphertext};

/// 재선형화(Relinearization)를 위한 키입니다.
/// 비밀키의 제곱(s^2)을 암호화한 값입니다.
#[derive(Clone, Debug)]
pub struct RelinearizationKey(pub Vec<Ciphertext>);

/// 비밀키는 4원수들의 벡터입니다.
pub struct SecretKey(pub Vec<Polynomial>);

/// 키 스위칭(Key Switching)을 위한 키입니다.
/// 가젯 분해를 사용하여 생성됩니다.
#[derive(Clone, Debug)]
pub struct KeySwitchingKey {
    pub key: Vec<Vec<Ciphertext>>,
}

/// 프로그래머블 부트스트래핑(Programmable Bootstrapping)을 위한 키입니다.
/// LWE 비밀키를 GGSW 형태로 암호화한 것입니다.
#[derive(Clone, Debug)]
pub struct BootstrapKey {
    pub ggsw_vector: Vec<GgswCiphertext>,
}