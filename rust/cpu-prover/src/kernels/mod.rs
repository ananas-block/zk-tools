#[cfg(any(
    all(test, not(target_arch = "wasm32")),
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
pub(crate) mod curve;
pub(crate) mod fft;
pub(crate) mod field;
pub(crate) mod msm;
#[cfg(any(
    test,
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
pub(crate) mod pairing;

#[cfg(feature = "parallel")]
pub(crate) fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA + Send,
    B: FnOnce() -> RB + Send,
    RA: Send,
    RB: Send,
{
    rayon::join(a, b)
}

#[cfg(not(feature = "parallel"))]
pub(crate) fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA,
    B: FnOnce() -> RB,
{
    (a(), b())
}

#[cfg(all(
    test,
    target_arch = "wasm32",
    feature = "test-support",
    feature = "wasm-prover"
))]
#[path = "../../tests/wasm/kernels.rs"]
mod wasm_tests;
