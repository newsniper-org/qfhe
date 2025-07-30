use std::ops::{Add, Sub, Mul};

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

    pub fn mul(self, other: Self) -> Self {
        Self {
            w: (self.w * other.w - self.x * other.x - self.y * other.y - self.z * other.z),
            x: (self.w * other.x + self.x * other.w + self.y * other.z - self.z * other.y),
            y: (self.w * other.y - self.x * other.z + self.y * other.w + self.z * other.x),
            z: (self.w * other.z + self.x * other.y - self.y * other.x + self.z * other.w),
        }
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