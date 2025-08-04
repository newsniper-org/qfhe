// newsniper-org/qfhe/qfhe-wip-cpu-simple/src/core/polynomial.rs

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
