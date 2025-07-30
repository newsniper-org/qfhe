use super::quaternion::Quaternion;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct Polynomial {
    pub coeffs: Vec<Quaternion>,
}

impl Polynomial {
    // 영 다항식을 생성합니다.
    pub fn zero(degree: usize) -> Self {
        Polynomial {
            coeffs: vec![Quaternion::zero(); degree],
        }
    }
}