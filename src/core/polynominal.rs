use super::quaternion::Quaternion;
use crate::QfheParameters;


use num_complex::Complex;

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

    /// 4원수 다항식을 두 개의 복소수 다항식으로 분해
    pub fn to_complex_polynomials(&self) -> (Vec<Complex<u64>>, Vec<Complex<u64>>) {
        let n = self.coeffs.len();
        let mut p1 = Vec::with_capacity(n);
        let mut p2 = Vec::with_capacity(n);

        for q_coeff in &self.coeffs {
            let (c1, c2) = q_coeff.to_complex_pair();
            // u128을 u64로 변환 (NTT 모듈러스에 맞게)
            p1.push(Complex::new(c1.re as u64, c1.im as u64));
            p2.push(Complex::new(c2.re as u64, c2.im as u64));
        }
        (p1, p2)
    }

    /// 두 개의 복소수 다항식으로부터 4원수 다항식을 재구성
    pub fn from_complex_polynomials(p1: &[Complex<u64>], p2: &[Complex<u64>]) -> Self {
        let coeffs = p1.iter().zip(p2.iter()).map(|(c1, c2)| {
            // u64를 u128로 변환
            let c1_u128 = Complex::new(c1.re as u128, c1.im as u128);
            let c2_u128 = Complex::new(c2.re as u128, c2.im as u128);
            Quaternion::from_complex_pair(&c1_u128, &c2_u128)
        }).collect();
        Self { coeffs }
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