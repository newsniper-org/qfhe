use crate::core::{Ciphertext, Polynomial};

/// 재선형화(Relinearization)를 위한 키입니다.
/// 비밀키의 제곱(s^2)을 암호화한 값입니다.
#[derive(Clone, Debug)]
pub struct RelinearizationKey(pub Vec<Ciphertext>);

/// 비밀키는 4원수들의 벡터입니다.
pub struct SecretKey(pub Vec<Polynomial>);