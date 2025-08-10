use core::error;
use std::{ffi::{c_char, CStr}, fs::File, io::{BufWriter, Read, Write}, str::FromStr};
use serde::{Serialize, Deserialize, de::DeserializeOwned};

use crate::{core::{keys::{BootstrapKey, PublicKey, RelinearizationKey}, Ciphertext, GgswCiphertext, Polynomial, Quaternion, keys::SecretKey, SecurityLevel}, EvaluationKey};

use bincode::Options;

const MAGIC_NUMBER: u32 = 0x51464845; // "QFHE"
const FORMAT_VERSION: u16 = 1;

/// Big-Endian 설정을 사용하는 bincode 옵션을 반환하는 헬퍼 함수입니다.
fn get_bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_big_endian()
        .with_fixint_encoding() // 정수 크기를 명시적으로 인코딩하여 호환성을 높입니다.
}

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum KeyType {
    SK = 0b000u16, PK = 0b001u16, RLK = 0b010u16, EVK = 0b011u16, BK = 0b100u16
}

pub fn parse_key_binary(
        reader: &mut impl Read,
) -> Result<(SecurityLevel, KeyType, Vec<u8>), std::io::Error> {
    // 1. 헤더 읽기 (Big-Endian)
    let mut u32_buf = [0u8; 4];
    let mut u16_buf = [0u8; 2];
    let mut u64_buf = [0u8; 8];

    reader.read_exact(&mut u32_buf)?;
    let magic = u32::from_be_bytes(u32_buf);
    if magic != MAGIC_NUMBER {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid magic number"));
    }

    reader.read_exact(&mut u16_buf)?;
    let version = u16::from_be_bytes(u16_buf);
    if version != FORMAT_VERSION {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unsupported format version"));
    }
    
    reader.read_exact(&mut u16_buf)?;
    let metadata_flags = u16::from_be_bytes(u16_buf);
    let (level_bits, key_type_bits, _others) = ((metadata_flags | 0x0003u16), (metadata_flags | 0x003Cu16) >> 2, (metadata_flags | 0xFFC0u16) >> 5);

    let security_level = match level_bits {
        0x0000u16 => SecurityLevel::L128,
        0x0001u16 => SecurityLevel::L192,
        0x0002u16 => SecurityLevel::L256,
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unsupported security level"))
    };

    let key_type = match key_type_bits {
        0x0000u16 => KeyType::SK,
        0x0001u16 => KeyType::PK,
        0x0002u16 => KeyType::RLK,
        0x0003u16 => KeyType::EVK,
        0x0004u16 => KeyType::BK,
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unsupported key type"))
    };

    reader.read_exact(&mut u64_buf)?;
    let payload_len = u64::from_be_bytes(u64_buf);

    // 2. 페이로드 읽기
    let mut payload = vec![0; payload_len as usize];
    reader.read_exact(&mut payload)?;

    Ok((security_level, key_type, payload))
}

pub trait Key: Serialize + DeserializeOwned {
    const KEY_TYPE: KeyType;

    fn serialize_to_binary(
        &self,
        level: SecurityLevel,
        writer: &mut impl Write,
    ) -> Result<(), std::io::Error> {
        // 1. 페이로드를 메모리 버퍼에 먼저 직렬화 (✅ Big-Endian 설정 사용)
        let payload = get_bincode_options()
            .serialize(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
        let payload_len = payload.len() as u64;

        // 2. 메타데이터 비트플래그 생성
        let level_bits = match level {
            SecurityLevel::L128 => 0b00u16,
            SecurityLevel::L192 => 0b01u16,
            SecurityLevel::L256 => 0b10u16,
        } << 0;
        let key_type_bits = (Self::KEY_TYPE as u16) << 2;
        let metadata_flags = level_bits | key_type_bits;

        // 3. 헤더 필드를 Big-Endian으로 쓰기
        writer.write_all(&MAGIC_NUMBER.to_be_bytes())?;
        writer.write_all(&FORMAT_VERSION.to_be_bytes())?;
        writer.write_all(&metadata_flags.to_be_bytes())?;
        writer.write_all(&payload_len.to_be_bytes())?;

        // 4. 페이로드 쓰기
        writer.write_all(&payload)?;

        Ok(())
    }

    // 3. 페이로드 역직렬화 (✅ Big-Endian 설정 사용)
    fn deserialize_from_payload(payload: &Vec<u8>) -> Result<Self, std::io::Error>;
}

impl Key for SecretKey {
    const KEY_TYPE: KeyType = KeyType::SK;
    
    fn deserialize_from_payload(payload: &Vec<u8>) -> Result<SecretKey, std::io::Error> {
        get_bincode_options()
            .deserialize(&payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl Key for PublicKey {
    const KEY_TYPE: KeyType = KeyType::PK;
    
    fn deserialize_from_payload(payload: &Vec<u8>) -> Result<PublicKey, std::io::Error> {
        get_bincode_options()
            .deserialize(&payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl Key for RelinearizationKey {
    const KEY_TYPE: KeyType = KeyType::RLK;
    
    fn deserialize_from_payload(payload: &Vec<u8>) -> Result<RelinearizationKey, std::io::Error> {
        get_bincode_options()
            .deserialize(&payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl Key for EvaluationKey {
    const KEY_TYPE: KeyType = KeyType::EVK;
    
    fn deserialize_from_payload(payload: &Vec<u8>) -> Result<EvaluationKey, std::io::Error> {
        get_bincode_options()
            .deserialize(&payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl Key for BootstrapKey {
    const KEY_TYPE: KeyType = KeyType::BK;
    
    fn deserialize_from_payload(payload: &Vec<u8>) -> Result<BootstrapKey, std::io::Error> {
        get_bincode_options()
            .deserialize(&payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}


impl Serialize for SecurityLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        let lv = match *self {
            SecurityLevel::L128 => 128u64,
            SecurityLevel::L192 => 192u64,
            SecurityLevel::L256 => 256u64
        };
        lv.serialize::<S>(serializer)
    }
}

#[derive(Debug)]
pub struct NotSupportedSecurityLevelError(pub u64);

impl error::Error for NotSupportedSecurityLevelError {}

impl std::fmt::Display for NotSupportedSecurityLevelError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}-bit security Level not supported!", self.0)
    }
}

impl<'de> Deserialize<'de> for SecurityLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as serde::Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de> {
        let result = u64::deserialize::<D>(deserializer);
        if let Ok(parsed) = result {
            match parsed {
                128u64 => Ok(SecurityLevel::L128),
                192u64 => Ok(SecurityLevel::L192),
                256u64 => Ok(SecurityLevel::L256),
                _ => Err(NotSupportedSecurityLevelError(parsed)).map_err(serde::de::Error::custom)
            }
        } else {
            let err = result.err().unwrap();
            Err(err)
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CipherObject {
    pub security_level: SecurityLevel,
    pub payload: Ciphertext
}