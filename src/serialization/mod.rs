use core::error;
use std::{ffi::{c_char, CStr}, fs::File, io::{BufWriter, Read}, str::FromStr};
use serde::{Serialize, Deserialize};

use crate::{core::{keys::{BootstrapKey, PublicKey, RelinearizationKey}, Ciphertext, GgswCiphertext, Polynomial, Quaternion, keys::SecretKey, SecurityLevel}, EvaluationKey};

use hexstring::{HexString, Case};

#[repr(C)]
pub enum KeyType {
    SK, PK, RLK, BK, EVK
}


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
pub struct CipherObject {
    pub security_level: SecurityLevel,
    pub payload: Ciphertext
}