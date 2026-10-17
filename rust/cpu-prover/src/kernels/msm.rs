#[cfg(not(all(
    target_arch = "wasm32",
    feature = "wasm-prover",
    target_feature = "simd128"
)))]
use crate::Error;
#[cfg(not(all(
    target_arch = "wasm32",
    feature = "wasm-prover",
    target_feature = "simd128"
)))]
use ark_bn254::Fr;
#[cfg(not(all(
    target_arch = "wasm32",
    feature = "wasm-prover",
    target_feature = "simd128"
)))]
use ark_ec::{AffineRepr, VariableBaseMSM};
#[cfg(all(
    feature = "parallel",
    target_family = "wasm",
    not(all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    ))
))]
use ark_ff::BigInteger;
#[cfg(not(all(
    target_arch = "wasm32",
    feature = "wasm-prover",
    target_feature = "simd128"
)))]
use ark_ff::BigInteger256;
#[cfg(not(all(
    target_arch = "wasm32",
    feature = "wasm-prover",
    target_feature = "simd128"
)))]
use ark_relations::gr1cs::SynthesisError;
#[cfg(all(
    feature = "parallel",
    target_family = "wasm",
    not(all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    ))
))]
use rayon::prelude::*;
#[cfg(any(
    all(test, not(target_arch = "wasm32")),
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
mod affine;
#[cfg(all(
    target_arch = "wasm32",
    feature = "wasm-prover",
    target_feature = "simd128"
))]
pub(crate) use affine::PreparedKey;

#[cfg(not(all(
    target_arch = "wasm32",
    feature = "wasm-prover",
    target_feature = "simd128"
)))]
pub(crate) fn query_msm<G>(query: &[G], assignment: &[BigInteger256]) -> Result<G::Group, Error>
where
    G: AffineRepr<ScalarField = Fr>,
    G::Group: VariableBaseMSM<MulBase = G>,
{
    let bases = query.get(1..).ok_or(SynthesisError::AssignmentMissing)?;
    Ok(msm::<G::Group>(bases, assignment))
}

#[cfg(not(all(feature = "parallel", target_family = "wasm")))]
#[cfg(not(all(
    target_arch = "wasm32",
    feature = "wasm-prover",
    target_feature = "simd128"
)))]
pub(crate) fn msm<G>(bases: &[G::MulBase], scalars: &[BigInteger256]) -> G
where
    G: VariableBaseMSM<ScalarField = Fr>,
{
    G::msm_bigint(bases, scalars)
}

#[cfg(all(feature = "parallel", target_family = "wasm"))]
#[cfg(not(all(
    target_arch = "wasm32",
    feature = "wasm-prover",
    target_feature = "simd128"
)))]
pub(crate) fn msm<G>(bases: &[G::MulBase], scalars: &[BigInteger256]) -> G
where
    G: VariableBaseMSM<ScalarField = Fr>,
{
    (0..BigInteger256::NUM_LIMBS)
        .rev()
        .fold(G::zero(), |mut sum, limb| {
            for _ in 0..u64::BITS {
                sum.double_in_place();
            }
            let limbs: Vec<u64> = scalars
                .par_iter()
                .map(|scalar| scalar.0.get(limb).copied().unwrap_or_default())
                .collect();
            sum + G::msm_u64(bases, &limbs)
        })
}
