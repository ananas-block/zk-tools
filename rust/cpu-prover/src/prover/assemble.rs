use ark_bn254::{Fr, G1Projective, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger256, PrimeField};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::gr1cs::SynthesisError;
use ark_std::cfg_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(not(all(
    target_arch = "wasm32",
    feature = "wasm-prover",
    target_feature = "simd128"
)))]
use crate::kernels::msm::{msm, query_msm};
use crate::kernels::{fft::CircomReduction, join};
use crate::Error;
use crate::{Proof, ProvingKey, R1csMatrices};

pub(crate) fn create_proof(
    proving_key: &ProvingKey,
    r: Fr,
    s: Fr,
    matrices: &R1csMatrices,
    full_assignment: &[Fr],
    evaluations: [Vec<Fr>; 3],
    #[cfg(all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    ))]
    prepared: &crate::kernels::msm::PreparedKey,
) -> Result<Proof, Error> {
    let num_inputs = matrices.num_instance_variables;
    let (h_scalars, scalars) = prepare_scalars(matrices, full_assignment, evaluations)?;
    let assignment = scalars.get(1..).ok_or(SynthesisError::AssignmentMissing)?;
    let aux_assignment = scalars
        .get(num_inputs..)
        .ok_or(SynthesisError::AssignmentMissing)?;

    #[cfg(not(all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )))]
    let ((h_acc, l_aux_acc), ((a_acc, b_g1_acc), b_g2_acc)) = join(
        || {
            join(
                || msm::<G1Projective>(&proving_key.h_query, &h_scalars),
                || msm::<G1Projective>(&proving_key.l_query, aux_assignment),
            )
        },
        || {
            join(
                || {
                    join(
                        || query_msm(&proving_key.a_query, assignment),
                        || query_msm(&proving_key.b_g1_query, assignment),
                    )
                },
                || query_msm(&proving_key.b_g2_query, assignment),
            )
        },
    );

    #[cfg(all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    ))]
    let ((h_acc, l_aux_acc), ((a_acc, b_g1_acc), b_g2_acc)) = join(
        || {
            join(
                || prepared.h.msm(&h_scalars),
                || prepared.l.msm(aux_assignment),
            )
        },
        || {
            join(
                || {
                    join(
                        || prepared.a.query(assignment).ok_or_else(missing_assignment),
                        || prepared.b1.query(assignment).ok_or_else(missing_assignment),
                    )
                },
                || prepared.b2.query(assignment).ok_or_else(missing_assignment),
            )
        },
    );
    finish_proof(
        proving_key,
        r,
        s,
        h_acc,
        l_aux_acc,
        a_acc,
        b_g1_acc,
        b_g2_acc,
    )
}

pub(super) fn prepare_scalars(
    matrices: &R1csMatrices,
    full_assignment: &[Fr],
    evaluations: [Vec<Fr>; 3],
) -> Result<(Vec<BigInteger256>, Vec<BigInteger256>), Error> {
    let num_inputs = matrices.num_instance_variables;

    #[cfg(not(all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )))]
    let h = CircomReduction::witness_map_from_evaluations::<Fr, GeneralEvaluationDomain<Fr>>(
        evaluations,
        num_inputs,
        matrices.num_constraints,
        full_assignment,
    )?;
    #[cfg(all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    ))]
    let h = {
        let inputs = full_assignment
            .get(..num_inputs)
            .ok_or(SynthesisError::AssignmentMissing)?;
        let inputs: Vec<_> = inputs
            .iter()
            .copied()
            .map(crate::kernels::field::scalar::from_ark)
            .collect();
        let evaluations = evaluations.map(|values| {
            values
                .into_iter()
                .map(crate::kernels::field::scalar::from_ark)
                .collect()
        });
        CircomReduction::witness_map_from_evaluations::<
            crate::kernels::field::scalar::Scalar,
            GeneralEvaluationDomain<crate::kernels::field::scalar::Scalar>,
        >(evaluations, num_inputs, matrices.num_constraints, &inputs)?
    };
    let (h_scalars, scalars) = join(|| bigints(&h), || bigints(full_assignment));
    Ok((h_scalars, scalars))
}

pub(super) fn finish_proof(
    proving_key: &ProvingKey,
    r: Fr,
    s: Fr,
    h_acc: G1Projective,
    l_aux_acc: G1Projective,
    a_acc: Result<G1Projective, Error>,
    b_g1_acc: Result<G1Projective, Error>,
    b_g2_acc: Result<G2Projective, Error>,
) -> Result<Proof, Error> {
    let vk = &proving_key.vk;

    let delta_r = proving_key.delta_g1 * r;
    let g_a = delta_r + first(&proving_key.a_query)? + a_acc? + vk.alpha_g1;

    let g1_b = super::finish::unblinded_b(
        r,
        &proving_key.b_g1_query,
        b_g1_acc,
        proving_key.beta_g1,
        || Error::Internal(SynthesisError::AssignmentMissing).into(),
    )?;

    let delta_s = vk.delta_g2 * s;
    let g2_b = delta_s + first(&proving_key.b_g2_query)? + b_g2_acc? + vk.beta_g2;

    let g_c = super::finish::c(g_a, g1_b, r, s, l_aux_acc, h_acc);
    Ok(Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    })
}

#[cfg(all(
    target_arch = "wasm32",
    feature = "wasm-prover",
    target_feature = "simd128"
))]
fn missing_assignment() -> Error {
    Error::Internal(SynthesisError::AssignmentMissing).into()
}

pub(super) fn bigints<F: PrimeField<BigInt = BigInteger256>>(values: &[F]) -> Vec<BigInteger256> {
    cfg_iter!(values).map(|value| value.into_bigint()).collect()
}

fn first<G: AffineRepr>(query: &[G]) -> Result<G, Error> {
    Ok(query
        .first()
        .copied()
        .ok_or(Error::Internal(SynthesisError::AssignmentMissing))?)
}
