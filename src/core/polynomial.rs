#[derive(Clone, Debug)]
#[repr(align(64))]
pub struct SimdPolynomial {
    pub w: Vec<u128>,
    pub x: Vec<u128>,
    pub y: Vec<u128>,
    pub z: Vec<u128>,
}

impl SimdPolynomial {
    pub fn zero(degree: usize) -> Self {
        SimdPolynomial {
            w: vec![0; degree],
            x: vec![0; degree],
            y: vec![0; degree],
            z: vec![0; degree],
        }
    }
}
