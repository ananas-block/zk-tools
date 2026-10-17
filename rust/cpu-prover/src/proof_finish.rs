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
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::{AdditiveGroup, Field};
    use ark_std::UniformRand;

    fn reference_b(
        delta: G1Affine,
        s: Fr,
        r: Fr,
        query: &[G1Affine],
        acc: Result<G1Projective, &'static str>,
        beta: G1Affine,
    ) -> Result<G1Projective, &'static str> {
        if r.is_zero() {
            return Ok(G1Projective::zero());
        }
        Ok(delta * s + query.first().copied().ok_or("missing")? + acc? + beta)
    }

    #[test]
    fn finish_matches_original_blinded_formula() {
        let mut rng = ark_std::test_rng();
        for sample in 0..8 {
            let delta = if sample == 0 {
                G1Affine::identity()
            } else {
                G1Projective::rand(&mut rng).into_affine()
            };
            let a_unblinded = G1Projective::rand(&mut rng);
            let beta = G1Projective::rand(&mut rng).into_affine();
            let first = G1Projective::rand(&mut rng).into_affine();
            let accumulator = G1Projective::rand(&mut rng);
            let l = G1Projective::rand(&mut rng);
            let h = G1Projective::rand(&mut rng);
            let cases = [
                Fr::ZERO,
                Fr::ONE,
                -Fr::ONE,
                Fr::rand(&mut rng),
                Fr::rand(&mut rng),
            ];
            for r in cases {
                for s in cases {
                    let a = delta * r + a_unblinded;
                    let blinded =
                        reference_b(delta, s, r, &[first], Ok(accumulator), beta).unwrap();
                    let expected = a * s + blinded * r - delta * (r * s) + l + h;
                    let b =
                        unblinded_b(r, &[first], Ok::<_, &str>(accumulator), beta, || "missing")
                            .unwrap();
                    assert_eq!(
                        c(a, b, r, s, l, h),
                        expected,
                        "sample {sample}, r={r}, s={s}"
                    );
                }
            }
        }
    }

    #[test]
    fn b_error_order_and_zero_randomizer_match_reference() {
        let mut rng = ark_std::test_rng();
        let delta = G1Projective::rand(&mut rng).into_affine();
        let beta = G1Projective::rand(&mut rng).into_affine();
        let first = G1Projective::rand(&mut rng).into_affine();
        let accumulator = G1Projective::rand(&mut rng);
        for r in [Fr::ZERO, Fr::ONE, -Fr::ONE, Fr::rand(&mut rng)] {
            for query in [&[][..], &[first][..]] {
                for acc in [Ok(accumulator), Err("accumulator")] {
                    let original = reference_b(delta, Fr::ONE, r, query, acc, beta);
                    let candidate = unblinded_b(r, query, acc, beta, || "missing");
                    assert_eq!(candidate.as_ref().err(), original.as_ref().err());
                    if r.is_zero() {
                        assert!(candidate.unwrap().is_zero());
                    } else if query.is_empty() {
                        assert_eq!(candidate.unwrap_err(), "missing");
                    } else if acc.is_err() {
                        assert_eq!(candidate.unwrap_err(), "accumulator");
                    } else {
                        assert_eq!(candidate.unwrap() + delta, original.unwrap());
                    }
                }
            }
        }
    }
}
