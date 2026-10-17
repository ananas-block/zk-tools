//! Groth16's blinded B-in-G1 terms cancel exactly in C.
use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ff::Zero;

/// Preserve the original short circuit and error order: r=0 ignores B errors,
/// otherwise a missing constant query term precedes an accumulator error.
pub(super) fn unblinded_b<E>(
    r: Fr,
    query: &[G1Affine],
    accumulator: Result<G1Projective, E>,
    beta: G1Affine,
    missing: impl FnOnce() -> E,
) -> Result<G1Projective, E> {
    if r.is_zero() {
        return Ok(G1Projective::zero());
    }
    let first = query.first().copied().ok_or_else(missing)?;
    Ok(first + accumulator? + beta)
}

pub(super) fn c(
    a: G1Projective,
    b_unblinded: G1Projective,
    r: Fr,
    s: Fr,
    l: G1Projective,
    h: G1Projective,
) -> G1Projective {
    #[cfg(all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    ))]
    {
        super::curve::finish_c(a, b_unblinded, r, s, l, h)
    }
    #[cfg(not(all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )))]
    {
        a * s + b_unblinded * r + l + h
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/unit/proof_finish.rs"]
mod tests;
