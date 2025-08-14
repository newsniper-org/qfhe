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

use crate::serialization::get_bincode_options;
use std::io::{SeekFrom, BufWriter, BufReader, Seek, Read};
use std::fs::File;

use bincode::Options;

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


/// 프로그래머블 부트스트래핑(Programmable Bootstrapping)을 위한 키입니다.
/// LWE 비밀키를 GGSW 형태로 암호화한 것입니다.
// ✅ FIX: On-Disk Bootstrap Key를 관리하는 새로운 구조체
pub struct OnDiskBootstrapKey {
    key_file: BufReader<File>,
    index_file: BufReader<File>,
}

impl OnDiskBootstrapKey {
    pub fn new(key_path: &str, index_path: &str) -> Result<Self, std::io::Error> {
        let key_file = BufReader::new(File::open(key_path)?);
        let index_file = BufReader::new(File::open(index_path)?);
        Ok(Self { key_file, index_file })
    }

    // i번째 GGSW 암호문을 디스크에서 직접 읽어옵니다.
    pub fn get(&mut self, i: usize) -> Result<GgswCiphertext, std::io::Error> {
        let mut offset_buf = [0u8; 8];
        self.index_file.seek(SeekFrom::Start((i * 8) as u64))?;
        self.index_file.read_exact(&mut offset_buf)?;
        let offset = u64::from_be_bytes(offset_buf);

        self.key_file.seek(SeekFrom::Start(offset))?;
        get_bincode_options()
            .deserialize_from(&mut self.key_file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}