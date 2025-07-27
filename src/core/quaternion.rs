use std::ops::{Add, Sub, Mul};

// Q-FHE의 기본 연산을 위한 4원수(Quaternion)를 정의합니다.
// SIMD 연산에 최적화될 수 있는 구조입니다. [8, 9]
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Quaternion { // 암호문 계수(coefficient)를 위한 소수 모듈러스
    pub w: u64, pub x: u64, pub y: u64, pub z: u64,
}

// 4원수 연산 구현
impl Quaternion {
    pub fn new(w: u64, x: u64, y: u64, z: u64) -> Self {
        Self { w, x, y, z }
    }

    pub fn zero() -> Self {
        Self { w: 0, x: 0, y: 0, z: 0 }
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
    
    pub fn scale(self, scalar: u64) -> Self {
        Self {
            w: (self.w * scalar),
            x: (self.x * scalar),
            y: (self.y * scalar),
            z: (self.z * scalar),
        }
    }

    pub fn from_scalar(s: u64) -> Self {
        Self { w: s, x: 0, y: 0, z: 0 }
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