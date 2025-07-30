use super::quaternion::Quaternion;
use crate::QfheParameters;

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

    pub fn decompose(&self, base: u128, l: usize, params: &QfheParameters) -> Vec<Polynomial> {
        let n = params.polynomial_degree;
        let mut decomposed_polys = vec![Polynomial::zero(n); l];

        for i in 0..n {
            let coeff = self.coeffs[i]; // 분해할 계수(4원수)

            // 각 4원수(w, x, y, z) 성분에 대해 분해를 수행합니다.
            let mut w = coeff.w;
            let mut x = coeff.x;
            let mut y = coeff.y;
            let mut z = coeff.z;

            for j in 0..l {
                let w_j = w % base;
                w /= base;
                let x_j = x % base;
                x /= base;
                let y_j = y % base;
                y /= base;
                let z_j = z % base;
                z /= base;

                decomposed_polys[j].coeffs[i] = Quaternion { w: w_j, x: x_j, y: y_j, z: z_j };
            }
        }

        decomposed_polys
    }
}