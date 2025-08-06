// newsniper-org/qfhe/qfhe-wip-cpu-simple/src/core/quaternion.rs

use std::ops::{Add, Sub, Mul};

use serde::{Serialize, Deserialize};

// 각 쿼터니언 성분이 RNS 표현을 가집니다.
#[derive(Clone, Debug, Default)]
pub struct Quaternion {
    pub w: Vec<u64>,
    pub x: Vec<u64>,
    pub y: Vec<u64>,
    pub z: Vec<u64>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct SerializableQuaternion(Vec<u64>,Vec<u64>,Vec<u64>,Vec<u64>);

impl Serialize for Quaternion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        let tmp = SerializableQuaternion(self.w.clone(), self.x.clone(), self.y.clone(), self.z.clone() );
        tmp.serialize::<S>(serializer)
    }
}

impl<'de> Deserialize<'de> for Quaternion {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as serde::Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de> {
        let result = SerializableQuaternion::deserialize::<D>(deserializer);
        if let Ok(q) = result {
            Ok(Quaternion { w: q.0.clone(), x: q.1.clone(), y: q.2.clone(), z: q.3.clone() })
        } else {
            let err = result.err().unwrap();
            Err(err)
        }
    }
}

impl Quaternion {
    // RNS 기저 크기에 맞춰 0으로 초기화
    pub fn zero(rns_basis_size: usize) -> Self {
        Self {
            w: vec![0; rns_basis_size],
            x: vec![0; rns_basis_size],
            y: vec![0; rns_basis_size],
            z: vec![0; rns_basis_size],
        }
    }
}
