#[cfg(any(
    all(test, not(target_arch = "wasm32")),
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
use core::ops::{Add, Mul, Neg, Sub};
#[cfg(any(
    all(test, not(target_arch = "wasm32")),
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
pub(in crate::kernels) mod base;
#[cfg(any(
    all(test, not(target_arch = "wasm32")),
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
pub(in crate::kernels) mod extension;
#[cfg(any(
    test,
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
pub(crate) mod scalar;
#[cfg(all(
    target_arch = "wasm32",
    feature = "wasm-prover",
    target_feature = "simd128"
))]
pub(in crate::kernels) mod simd;

#[cfg(any(
    all(test, not(target_arch = "wasm32")),
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
pub(in crate::kernels) trait SmallField:
    Copy
    + Eq
    + Send
    + Sync
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
{
    const ZERO: Self;
    const ONE: Self;

    #[inline(always)]
    fn double(self) -> Self {
        self + self
    }
    #[inline(always)]
    fn square(self) -> Self {
        self * self
    }
    #[inline(always)]
    fn dot(a: Self, b: Self, c: Self, d: Self) -> Self {
        a * b + c * d
    }
    fn inverse(self) -> Option<Self>;

    #[inline(always)]
    fn pair_mul(a: Self, b: Self, c: Self, d: Self) -> (Self, Self) {
        (a * c, b * d)
    }
    #[inline(always)]
    fn pair_square(a: Self, b: Self) -> (Self, Self) {
        Self::pair_mul(a, b, a, b)
    }
    type Scratch;
    fn scratch(capacity: usize) -> Self::Scratch;
    fn invert_batch_in(values: &mut [Self], scratch: &mut Self::Scratch);
}

#[cfg(any(
    all(test, not(target_arch = "wasm32")),
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
pub(in crate::kernels) fn batch_inverse_with_prefix<F: SmallField>(
    values: &mut [F],
    products: &mut Vec<F>,
) {
    products.clear();
    let mut product = F::ONE;
    for &value in values.iter() {
        products.push(product);
        if value != F::ZERO {
            product = product * value;
        }
    }
    let Some(mut inverse) = product.inverse() else {
        return;
    };
    for (value, prefix) in values.iter_mut().zip(products.iter().copied()).rev() {
        if *value != F::ZERO {
            let next = inverse * (*value);
            *value = inverse * prefix;
            inverse = next;
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../../tests/unit/field.rs"]
mod tests;
