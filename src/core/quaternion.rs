use std::ops::{Add, Sub, Mul};

use num_complex::Complex;

use rand::Rng;

// QFHE의 기본 연산을 위한 4원수(Quaternion)를 정의합니다.
// SIMD 연산에 최적화될 수 있는 구조입니다. [8, 9]
#[derive(Clone, Debug, Copy, Default)]
pub struct Quaternion {
    pub w: u128,
    pub x: u128,
    pub y: u128,
    pub z: u128,
}


// 4원수 연산 구현
impl Quaternion {
    pub fn new(w: u128, x: u128, y: u128, z: u128) -> Self {
        Self { w, x, y, z }
    }

    pub fn zero() -> Self {
        Self::default()
    }

    // u128 스칼라 값으로부터 4원수를 생성합니다.
    pub fn from_scalar(s: u128) -> Self {
        Quaternion { w: s, x: 0, y: 0, z: 0 }
    }

    pub fn random(rng: &mut impl Rng, modulus: u128) -> Self {
        Self {
            w: rng.random_range(0..modulus),
            x: rng.random_range(0..modulus),
            y: rng.random_range(0..modulus),
            z: rng.random_range(0..modulus),
        }
    }

    /// 4원수를 두 개의 복소수로 분해: q = c1 + c2*j
    pub fn to_complex_pair(&self) -> (Complex<u128>, Complex<u128>) {
        (Complex::new(self.w, self.x), Complex::new(self.y, self.z))
    }

    /// 두 개의 복소수로부터 4원수를 재구성
    pub fn from_complex_pair(c1: &Complex<u128>, c2: &Complex<u128>) -> Self {
        Self::new(c1.re, c1.im, c2.re, c2.im)
    }

    pub fn add(self, other: Self) -> Self {
        Self {
            w: (self.w + other.w),
            x: (self.x + other.x),
            y: (self.y + other.y),
            z: (self.z + other.z),
        }
    }

    pub fn sub(self, other: Self) -> Self {
        Self {
            w: (self.w - other.w),
            x: (self.x - other.x),
            y: (self.y - other.y),
            z: (self.z - other.z),
        }
    }

    pub fn mul(self, rhs: Self) -> Self {
        // 임시 변수를 사용하여 wrapping_sub으로 인한 중간값 문제를 방지합니다.
        let s0 = self.w; let s1 = self.x; let s2 = self.y; let s3 = self.z;
        let o0 = rhs.w; let o1 = rhs.x; let o2 = rhs.y; let o3 = rhs.z;

        // w = s0*o0 - s1*o1 - s2*o2 - s3*o3
        let w = s0.wrapping_mul(o0)
           .wrapping_sub(s1.wrapping_mul(o1))
           .wrapping_sub(s2.wrapping_mul(o2))
           .wrapping_sub(s3.wrapping_mul(o3));

        // x = s0*o1 + s1*o0 + s2*o3 - s3*o2
        let x = s0.wrapping_mul(o1)
           .wrapping_add(s1.wrapping_mul(o0))
           .wrapping_add(s2.wrapping_mul(o3))
           .wrapping_sub(s3.wrapping_mul(o2));

        // y = s0*o2 - s1*o3 + s2*o0 + s3*o1
        let y = s0.wrapping_mul(o2)
           .wrapping_sub(s1.wrapping_mul(o3))
           .wrapping_add(s2.wrapping_mul(o0))
           .wrapping_add(s3.wrapping_mul(o1));

        // z = s0*o3 + s1*o2 - s2*o1 + s3*o0
        let z = s0.wrapping_mul(o3)
           .wrapping_add(s1.wrapping_mul(o2))
           .wrapping_sub(s2.wrapping_mul(o1))
           .wrapping_add(s3.wrapping_mul(o0));

        Self { w, x, y, z }
    }
    
    pub fn scale(self, scalar: u128) -> Self {
        Self {
            w: (self.w * scalar),
            x: (self.x * scalar),
            y: (self.y * scalar),
            z: (self.z * scalar),
        }
    }
}

impl Mul for Quaternion {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self::mul(self, rhs)
    }
}

impl Add for Quaternion {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::add(self, rhs)
    }
}

impl Sub for Quaternion {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::sub(self, rhs)
    }
}