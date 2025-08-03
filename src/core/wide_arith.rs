//! Widening arithmetic operations for SIMD emulation.

/// A trait for widening arithmetic operations.
pub trait WideningArith {
    /// The wider type that can hold the result of the operation.
    type Wide;

    /// Performs addition that returns the full result in a wider type.
    fn widening_add(self, rhs: Self) -> Self::Wide;
}

impl WideningArith for u64 {
    type Wide = u128;

    #[inline(always)]
    fn widening_add(self, rhs: Self) -> Self::Wide {
        (self as u128) + (rhs as u128)
    }
}

impl WideningArith for u128 {
    type Wide = (u128, u128); // (low, high)

    #[inline(always)]
    fn widening_add(self, rhs: Self) -> Self::Wide {
        let (low, carry) = self.carrying_add(rhs, false);
        (low, carry as u128)
    }
}