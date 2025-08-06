use core::error;
use serde::{Serialize, Deserialize};

use crate::core::{SecretKey, keys::{BootstrapKey, KeySwitchingKey, RelinearizationKey, PublicKey}, Ciphertext, GgswCiphertext, Polynomial, Quaternion, SecurityLevel};

use hexstring::{HexString, Case};

pub enum KeyType {
    Sk, Pk, Rlk, Bk, Ksk
}

pub trait Key {
}

impl Key for SecretKey {}
impl Key for RelinearizationKey {}
impl Key for KeySwitchingKey {}
impl Key for BootstrapKey {}

impl Key for PublicKey {}


impl Serialize for SecurityLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        let lv = match *self {
            SecurityLevel::L128 => 128u64,
            SecurityLevel::L160 => 160u64,
            SecurityLevel::L192 => 192u64,
            SecurityLevel::L224 => 224u64,
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
                160u64 => Ok(SecurityLevel::L160),
                192u64 => Ok(SecurityLevel::L192),
                224u64 => Ok(SecurityLevel::L224),
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
pub struct KeyObject<K : Key> {
    security_level: SecurityLevel,
    payload: K
}

impl<'de, K: Key + Serialize + Deserialize<'de> + Clone> KeyObject<K> {
    pub fn new(payload: K, security_level: SecurityLevel) -> Self {
        Self {
            security_level,
            payload: payload.clone()
        }
    }

    pub fn clone_payload(&self) -> K {
        self.payload.clone()
    }
}



#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CipherObject {
    pub security_level: SecurityLevel,
    pub payload: Ciphertext
}