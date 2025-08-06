// newsniper-org/qfhe/qfhe-wip-cpu-simple/src/core/polynomial.rs

use serde::{Deserialize, Serialize};

use super::quaternion::Quaternion;

#[derive(Clone, Debug)]
pub struct Polynomial {
    pub coeffs: Vec<Quaternion>,
}

impl Polynomial {
    pub fn zero(degree: usize, rns_basis_size: usize) -> Self {
        Polynomial {
            coeffs: vec![Quaternion::zero(rns_basis_size); degree],
        }
    }
}

impl Serialize for Polynomial {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        self.coeffs.serialize::<S>(serializer)
    }
}

impl<'de> Deserialize<'de> for Polynomial {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as serde::Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de> {
        let result = Vec::<Quaternion>::deserialize::<D>(deserializer);
        if let Ok(coeffs) = result {
            Ok(Self { coeffs })
        } else {
            let err = result.err().unwrap();
            Err(err)
        }
    }
}