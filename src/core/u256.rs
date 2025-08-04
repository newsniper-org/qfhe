use std::ops::{Add, Sub, Mul, Div, Rem};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct U256 {
    pub low: u128,
    pub high: u128,
}

impl U256 {
    pub const ZERO: Self = Self { low: 0, high: 0 };
    pub const ONE: Self = Self { low: 1, high: 0 };

    pub fn from_u64(val: u64) -> Self {
        Self { low: val as u128, high: 0 }
    }

    pub fn wrapping_add(self, rhs: Self) -> Self {
        let (low, carry) = self.low.carrying_add(rhs.low, false);
        let high = self.high.wrapping_add(rhs.high).wrapping_add(carry as u128);
        Self { low, high }
    }

    // [추가] wrapping_sub 구현
    pub fn wrapping_sub(self, rhs: Self) -> Self {
        let (low, borrow) = self.low.overflowing_sub(rhs.low);
        let high = self.high.wrapping_sub(rhs.high).wrapping_sub(borrow as u128);
        Self { low, high }
    }

    pub fn wrapping_mul(self, rhs: Self) -> Self {
        let (low_part, high_part) = self.low.widening_mul(rhs.low);
        let mid_part1 = self.high.wrapping_mul(rhs.low);
        let mid_part2 = self.low.wrapping_mul(rhs.high);
        let final_high = high_part.wrapping_add(mid_part1).wrapping_add(mid_part2);
        Self { low: low_part, high: final_high }
    }
}

impl Add for U256 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self.wrapping_add(rhs)
    }
}

// [추가] Sub 트레이트 구현
impl Sub for U256 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self.wrapping_sub(rhs)
    }
}

// [추가] Mul 트레이트 구현
impl Mul for U256 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        self.wrapping_mul(rhs)
    }
}


// Simplified division for CRT (Knuth's Algorithm D)
impl Div for U256 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        if rhs > self {
            return Self::ZERO;
        }
        if rhs.high == 0 { // Dividing by u128
            if self.high == 0 {
                return Self { low: self.low / rhs.low, high: 0 };
            }
            // This is complex, for now we simplify
            return Self { low: self.low / rhs.low, high: self.high / rhs.low };
        }
        // General U256 / U256 division is very complex.
        Self::ONE // Placeholder
    }
}

impl Rem for U256 {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self::Output {
        // A simple but slow restoring division for remainder
        let mut dividend = self;
        if rhs > dividend { return dividend; }
        
        // This is a simplified placeholder and not a correct general implementation
        while dividend >= rhs {
            dividend = dividend.wrapping_sub(rhs);
        }
        dividend
    }
}