use core::error;
use std::str::pattern::SearchStep;

use serde::{Serialize, Deserialize};

use crate::core::{SecretKey, keys::{BootstrapKey, KeySwitchingKey, RelinearizationKey, PublicKey}, Ciphertext, GgswCiphertext, Polynomial, Quaternion, SecurityLevel};

use hexstring::{HexString, Case};


pub trait Key {

    fn from_parsed(parsed: HexString<{Case::Upper}>, security_level: SecurityLevel) -> Result<Self, serde::de::Error>;
    fn to_serialize(&self, security_level: SecurityLevel) -> HexString<{Case::Upper}>;
}

impl Key for SecretKey {
    
    fn from_parsed(parsed: HexString<{Case::Upper}>, security_level: SecurityLevel) -> Result<Self, serde::de::Error> {
        let params = security_level.get_params();
        let levels = params.gadget_levels_l;
        let rns_basis_size = params.modulus_q.len();
        let correct_size = params.module_dimension_k * params.polynomial_degree * rns_basis_size * 4usize;
        let decoded = Vec::<u64>::try_from(parsed);
        if let Ok(vect) = decoded {
            if vect.len() != correct_size {
                serde::de::Error::custom("The payload is somehow damaged!")
            }
            let vec_quat = (0..correct_size).step_by(4 * rns_basis_size).map(|i| {
                let w = vect[i..i+rns_basis_size].iter().collect::<Vec<u64>>();
                let x = vect[i+rns_basis_size..i + 2*rns_basis_size].iter().collect::<Vec<u64>>();
                let y = vect[i + 2*rns_basis_size..i + 3*rns_basis_size].iter().collect::<Vec<u64>>();
                let z = vect[i + 3*rns_basis_size..i + 4*rns_basis_size].iter().collect::<Vec<u64>>();
                Quaternion {w,x,y,z}
            }).collect::<Vec<Quaternion>>();
            let vec_poly = (0..(params.module_dimension_k * params.polynomial_degree)).step(params.polynomial_degree).map(|k| {
                Polynomial {
                    coeffs: vec_quat[k..(k+params.polynomial_degree)].iter().collect()
                }
            }).collect::<Vec<Polynomial>>();
            Ok(SecretKey(vec_poly))
        } else {
            decoded
        }
        
    }

    fn to_serialize(&self, security_level: SecurityLevel) -> HexString<{Case::Upper}> {
        let all_u64s = self.0.iter().map(|p| p.coeffs).flatten().map(|quat| vec![quat.w, quat.x, quat.y, quat.z].iter().flatten().map(|&x| x).collect::<Vec<>>()).flatten().collect::<Vec<>>();
        let encoded_polys: HexString::<{Case::Upper}> = HexString::<{Case::Upper}>::from(all_u64s);
        encoded_polys
    }
}

impl Key for RelinearizationKey {
    fn from_parsed(parsed: HexString<{Case::Upper}>, security_level: SecurityLevel) -> Result<Self, serde::de::Error> {
        let params = security_level.get_params();
        let levels = params.gadget_levels_l;
        let rns_basis_size = params.modulus_q.len();
        let correct_ciphertext_size = (params.module_dimension_k+1) * params.polynomial_degree * rns_basis_size * 4usize;
        let correct_ciphertext_count = (params.module_dimension_k * params.module_dimension_k * levels);
        let correct_size = correct_ciphertext_count * correct_ciphertext_size;
        let decoded = Vec::<u64>::try_from(parsed);
        if let Ok(vect) = decoded {
            if vect.len() != correct_size {
                serde::de::Error::custom("The payload is somehow damaged!")
            }
            let vec_quat = (0..correct_size).step_by(4 * rns_basis_size).map(|i| {
                let w = vect[i..i+rns_basis_size].iter().collect::<Vec<u64>>();
                let x = vect[i+rns_basis_size..i + 2*rns_basis_size].iter().collect::<Vec<u64>>();
                let y = vect[i + 2*rns_basis_size..i + 3*rns_basis_size].iter().collect::<Vec<u64>>();
                let z = vect[i + 3*rns_basis_size..i + 4*rns_basis_size].iter().collect::<Vec<u64>>();
                Quaternion {w,x,y,z}
            }).collect::<Vec<Quaternion>>();
            let vec_poly = (0..(correct_ciphertext_count*(params.module_dimension_k+1) * params.polynomial_degree)).step(params.polynomial_degree).map(|k| {
                Polynomial {
                    coeffs: vec_quat[k..(k+params.polynomial_degree)].iter().collect()
                }
            }).collect::<Vec<Polynomial>>();
            let vec_ct = (0..correct_ciphertext_count*(params.module_dimension_k+1)).step(params.module_dimension_k+1).map(|c| {
                let a_vec = vec_poly[c..(c+params.module_dimension_k)].iter().collect();
                Ciphertext {
                    a_vec,
                    b: vec_poly[c+params.module_dimension_k],
                    modulus_level: 0
                }
            }).collect::<Vec<Ciphertext>>();
            Ok(RelinearizationKey(vec_ct))
        } else {
            decoded
        }
    }

    fn to_serialize(&self, security_level: SecurityLevel) -> HexString<{Case::Upper}> {
        let all_quaternions = self.0.iter().map(|&ct| {
            let mut result = ct.a_vec.clone();
            result.append(vec![ct.b]);
            result
        }).flatten().map(|p| p.coeffs).flatten().collect::<Vec<Quaternion>>();
        let all_u64s = all_quaternions.iter().map(|quat| vec![quat.w, quat.x, quat.y, quat.z].iter().flatten().map(|&x| x).collect::<Vec<>>()).flatten().collect::<Vec<>>();
        let encoded_polys: HexString::<{Case::Upper}> = HexString::<{Case::Upper}>::from(all_u64s);
        encoded_polys
    }
}

impl Key for KeySwitchingKey {
    
    fn from_parsed(parsed: HexString<{Case::Upper}>, security_level: SecurityLevel) -> Result<Self, serde::de::Error> {
        let params = security_level.get_params();
        let levels = params.gadget_levels_l;
        let rns_basis_size = params.modulus_q.len();
        let correct_ciphertext_size = (params.module_dimension_k+1) * params.polynomial_degree * rns_basis_size * 4usize;
        let correct_ciphertext_count = params.module_dimension_k* levels;
        let correct_size = correct_ciphertext_count * correct_ciphertext_size;
        let decoded = Vec::<u64>::try_from(parsed);
        if let Ok(vect) = decoded {
            if vect.len() != correct_size {
                serde::de::Error::custom("The payload is somehow damaged!")
            }
            let vec_quat = (0..correct_size).step_by(4 * rns_basis_size).map(|i| {
                let w = vect[i..i+rns_basis_size].iter().collect::<Vec<u64>>();
                let x = vect[i+rns_basis_size..i + 2*rns_basis_size].iter().collect::<Vec<u64>>();
                let y = vect[i + 2*rns_basis_size..i + 3*rns_basis_size].iter().collect::<Vec<u64>>();
                let z = vect[i + 3*rns_basis_size..i + 4*rns_basis_size].iter().collect::<Vec<u64>>();
                Quaternion {w,x,y,z}
            }).collect::<Vec<Quaternion>>();
            let vec_poly = (0..(correct_ciphertext_count*(params.module_dimension_k+1) * params.polynomial_degree)).step(params.polynomial_degree).map(|k| {
                Polynomial {
                    coeffs: vec_quat[k..(k+params.polynomial_degree)].iter().collect()
                }
            }).collect::<Vec<Polynomial>>();
            let vec_ct = (0..correct_ciphertext_count*(params.module_dimension_k+1)).step(params.module_dimension_k+1).map(|c| {
                let a_vec = vec_poly[c..(c+params.module_dimension_k)].iter().collect();
                Ciphertext {
                    a_vec,
                    b: vec_poly[c+params.module_dimension_k],
                    modulus_level: 0
                }
            }).collect::<Vec<Ciphertext>>();
            let mat_ct = (0..correct_ciphertext_count).step(levels).map(|ci| {
                let inner = vec_ct[ci..(ci+levels)].iter().map(|c| c.clone()).collect::<Vec<Ciphertext>>();
                inner
            }).collect::<Vec<Vec<Ciphertext>>>();
            Ok(KeySwitchingKey { key: mat_ct })
        } else {
            decoded
        }
    }

    fn to_serialize(&self, security_level: SecurityLevel) -> HexString<{Case::Upper}> {
        let all_u64s = self.key.iter().flatten().map(|&ct| {
            let mut result = ct.a_vec.clone();
            result.append(ct.b);
            result
        }).flatten().map(|p| {
            p.coeffs
        }).flatten().map(|q| {
            let f = [q.w, q.x, q.y, q.z].iter().flatten().map(|&x| x);
            f
        }).flatten().collect::<Vec<u64>>();
        let encoded_polys: HexString::<{Case::Upper}> = HexString::<{Case::Upper}>::from(all_u64s);
        encoded_polys
    }
}

impl Key for BootstrapKey {
    
    fn from_parsed(parsed: HexString<{Case::Upper}>, security_level: SecurityLevel) -> Result<Self, serde::de::Error> {
        let params = security_level.get_params();
        let levels = params.gadget_levels_l;
        let rns_basis_size = params.modulus_q.len();
        let correct_ciphertext_size = (params.module_dimension_k+1) * params.polynomial_degree * rns_basis_size * 4usize;
        let correct_ciphertext_count = params.polynomial_degree * levels;
        let correct_size = correct_ciphertext_count * correct_ciphertext_size;
        let decoded = Vec::<u64>::try_from(parsed);
        if let Ok(vect) = decoded {
                if vect.len() != correct_size {
                serde::de::Error::custom("The payload is somehow damaged!")
            }
            let vec_quat = (0..correct_size).step_by(4 * rns_basis_size).map(|i| {
                let w = vect[i..i+rns_basis_size].iter().collect::<Vec<u64>>();
                let x = vect[i+rns_basis_size..i + 2*rns_basis_size].iter().collect::<Vec<u64>>();
                let y = vect[i + 2*rns_basis_size..i + 3*rns_basis_size].iter().collect::<Vec<u64>>();
                let z = vect[i + 3*rns_basis_size..i + 4*rns_basis_size].iter().collect::<Vec<u64>>();
                Quaternion {w,x,y,z}
            }).collect::<Vec<Quaternion>>();
            let vec_poly = (0..(correct_ciphertext_count*(params.module_dimension_k+1) * params.polynomial_degree)).step(params.polynomial_degree).map(|k| {
                Polynomial {
                    coeffs: vec_quat[k..(k+params.polynomial_degree)].iter().collect()
                }
            }).collect::<Vec<Polynomial>>();
            let vec_ct = (0..correct_ciphertext_count*(params.module_dimension_k+1)).step(params.module_dimension_k+1).map(|c| {
                let a_vec = vec_poly[c..(c+params.module_dimension_k)].iter().collect();
                Ciphertext {
                    a_vec,
                    b: vec_poly[c+params.module_dimension_k],
                    modulus_level: 0
                }
            }).collect::<Vec<Ciphertext>>();
            let mat_ct = (0..correct_ciphertext_count).step(levels).map(|ci| {
                let levels = vec_ct[ci..(ci+levels)].iter().map(|c| c.clone()).collect::<Vec<Ciphertext>>();
                GgswCiphertext { levels }
            }).collect::<Vec<GgswCiphertext>>();
            Ok(BootstrapKey { ggsw_vector: mat_ct })
        } else {
            decoded
        }
    }

    fn to_serialize(&self, security_level: SecurityLevel) -> HexString<{Case::Upper}> {
        let all_cts = self.ggsw_vector.iter().map(|&gct| {
            gct.levels
        }).flatten().collect::<Vec<Ciphertext>>();
        let all_u64s = all_cts.iter().map(|&ct| {
            let mut result = ct.a_vec.clone();
            result.append(ct.b);
            result
        }).flatten().map(|p| {
            p.coeffs
        }).flatten().map(|q| {
            let f = [q.w, q.x, q.y, q.z].iter().flatten().map(|&x| x);
            f
        }).flatten().collect::<Vec<u64>>();
        let encoded_polys: HexString::<{Case::Upper}> = HexString::<{Case::Upper}>::from(all_u64s);
        encoded_polys
    }  
}

impl Key for PublicKey {
    fn from_parsed(parsed: HexString<{Case::Upper}>, security_level: SecurityLevel) -> Result<Self, serde::de::Error> {
        let params = security_level.get_params();
        let levels = params.gadget_levels_l;
        let rns_basis_size = params.modulus_q.len();
        let module_dimension_k = params.module_dimension_k;
        let correct_size = (module_dimension_k+1) * params.polynomial_degree * rns_basis_size * 4usize;
        let decoded = Vec::<u64>::try_from(parsed);
        if let Ok(vect) = decoded {
            if vect.len() != correct_size {
                serde::de::Error::custom("The payload is somehow damaged!")
            }
            let vec_quat = (0..correct_size).step_by(4 * rns_basis_size).map(|i| {
                let w = vect[i..i+rns_basis_size].iter().collect::<Vec<u64>>();
                let x = vect[i+rns_basis_size..i + 2*rns_basis_size].iter().collect::<Vec<u64>>();
                let y = vect[i + 2*rns_basis_size..i + 3*rns_basis_size].iter().collect::<Vec<u64>>();
                let z = vect[i + 3*rns_basis_size..i + 4*rns_basis_size].iter().collect::<Vec<u64>>();
                Quaternion {w,x,y,z}
            }).collect::<Vec<Quaternion>>();
            let vec_poly = (0..((module_dimension_k+1) * params.polynomial_degree)).step(params.polynomial_degree).map(|k| {
                Polynomial {
                    coeffs: vec_quat[k..(k+params.polynomial_degree)].iter().collect()
                }
            }).collect::<Vec<Polynomial>>();
            Ok(Self {
                a: vec_poly[0..module_dimension_k].iter().collect::<Vec<Polynomial>>().clone(),
                b: vec_poly[module_dimension_k].clone()
            })
        } else {
            decoded
        }
        
    }

    fn to_serialize(&self, security_level: SecurityLevel) -> HexString<{Case::Upper}> {
        let mut all_polys = self.a.clone();
        all_polys.append(self.b);
        let all_u64s = all_polys.iter().map(|p| p.coeffs).flatten().map(|quat| vec![quat.w, quat.x, quat.y, quat.z].iter().flatten().map(|&x| x).collect::<Vec<_>>()).flatten().collect::<Vec<>>();
        let encoded_polys: HexString::<{Case::Upper}> = HexString::<{Case::Upper}>::from(all_u64s);
        encoded_polys
    }
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

impl fmt::Display for NotSupportedSecurityLevelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-bit security Level not supported!", self.0)
    }
}

impl Deserialize for SecurityLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
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
            result
        }
    }
}

#[derive(Clone, Debug)]
pub struct KeyObject<K : Key> {
    security_level: SecurityLevel,
    payload: K
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncodedKeyObject {
    security_level: SecurityLevel,
    encoded_payload: HexString<{Case::Upper}>
}

impl<K: Key> KeyObject<K> {
    fn from_parsed(parsed: EncodedKeyObject) -> Result<Self, serde::de::Error> {
        let pl = K::from_parsed(parsed.encoded_payload, parsed.security_level);
        if let Ok(payload) = pl {
            Ok(Self {
                security_level: parsed.security_level,
                payload
            })
        } else {
            pl.map_err(serde::de::Error::custom)
        }
    }
    fn to_serialize(&self) -> EncodedKeyObject {
        EncodedKeyObject { security_level: self.security_level, encoded_payload: self.payload.to_serialize(self.security_level) }
    }
}


impl<K: Key> Deserialize for KeyObject<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        let result = EncodedKeyObject::deserialize::<D>(deserializer);
        if let Ok(parsed) = result {
            let deserialized = Self::from_parsed(parsed);
            if let Ok(key_object) = deserialized {
                Ok(key_object)
            } else {
                deserialized.map_err(serde::de::Error::custom)
            }
        } else {
            result.map_err(serde::de::Error::custom)
        }
    }
}






#[derive(Clone, Debug)]
pub struct CipherObject {
    security_level: SecurityLevel,
    payload: Ciphertext
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncodedCipherObject {
    security_level: SecurityLevel,
    modulus_level: u64,
    encoded_polys: HexString<{Case::Upper}>
}

impl Deserialize for CipherObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        let result = EncodedCipherObject::deserialize::<D>(deserializer);
        if let Ok(parsed) = result {
            let decoded = Vec::<u64>::try_from(parsed.encoded_polys);
            if let Ok(vect) = decoded {
                let params = parsed.security_level.get_params();
                let rns_basis_size = params.modulus_q.len();
                let correct_size = (params.module_dimension_k+1) * params.polynomial_degree * rns_basis_size * 4usize;
                if vect.len() != correct_size {
                    serde::de::Error::custom("The payload is somehow damaged!")
                }
                let vec_quat = (0..correct_size).step_by(4 * rns_basis_size).map(|i| {
                    let w = vect[i..i+rns_basis_size].iter().collect::<Vec<u64>>();
                    let x = vect[i+rns_basis_size..i + 2*rns_basis_size].iter().collect::<Vec<u64>>();
                    let y = vect[i + 2*rns_basis_size..i + 3*rns_basis_size].iter().collect::<Vec<u64>>();
                    let z = vect[i + 3*rns_basis_size..i + 4*rns_basis_size].iter().collect::<Vec<u64>>();
                    Quaternion {w,x,y,z}
                }).collect::<Vec<Quaternion>>();
                let vec_poly = (0..((params.module_dimension_k+1) * params.polynomial_degree)).step(params.polynomial_degree).map(|k| {
                    Polynomial {
                        coeffs: vec_quat[k..(k+params.polynomial_degree)].iter().collect()
                    }
                }).collect::<Vec<Polynomial>>();
                Ok(CipherObject {
                    security_level: parsed.security_level,
                    payload: Ciphertext { a_vec: vec_poly[0..params.module_dimension_k], b: vec_poly[params.module_dimension_k], modulus_level: parsed.modulus_level as usize }
                })
            } else {
                serde::de::Error::custom("The payload is somehow damaged!")
            }
        } else {
            result
        }
    }
}

impl Serialize for CipherObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        let all_quaternions = [self.payload.a_vec, vec![self.payload.b]].iter().flatten().map(|p| p.coeffs).flatten().collect::<Vec<Quaternion>>();
        let all_u64s = all_quaternions.iter().map(|quat| vec![quat.w, quat.x, quat.y, quat.z].iter().flatten().collect::<Vec<u64>>()).flatten().collect::<Vec<u64>>();
        let encoded_polys: HexString::<{Case::Upper}> = HexString::<{Case::Upper}>::from(all_u64s);
        let encoded_object = EncodedCipherObject {
            security_level: self.security_level,
            modulus_level: self.payload.modulus_level,
            encoded_polys
        };
        encoded_object.serialize::<S>(serializer)
    }
}