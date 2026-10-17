use super::*;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, UniformRand};

#[test]
fn base_field_matches_original_arithmetic() {
    let mut rng = ark_std::test_rng();
    for _ in 0..100_000 {
        let a = ark_bn254::Fq::rand(&mut rng);
        let b = ark_bn254::Fq::rand(&mut rng);
        let fa = field(a);
        let fb = field(b);
        assert_eq!((fa * fb).0, (a * b).0);
        assert_eq!(fa.square().0, a.square().0);
        assert_eq!(
            Fq::sum_of_products(&[fa, fb], &[fb, fa]).0,
            (a * b + b * a).0
        );
    }
}

#[test]
fn pairing_and_tower_match_original_with_infinity() {
    let mut rng = ark_std::test_rng();
    for mode in 0..24 {
        let p = if mode % 6 == 0 {
            ark_bn254::G1Affine::identity()
        } else {
            ark_bn254::G1Projective::rand(&mut rng).into_affine()
        };
        let q = if mode % 7 == 0 {
            ark_bn254::G2Affine::identity()
        } else {
            ark_bn254::G2Projective::rand(&mut rng).into_affine()
        };
        let expected = ark_bn254::Bn254::pairing(p, q).0;
        let actual = Engine::pairing(g1(p), g2(q)).0;
        assert_eq!(actual, tower(expected), "mode={mode}");
        let expected = ark_bn254::Bn254::multi_pairing([p, -p], [q, q]).0;
        let actual = Engine::multi_pairing([g1(p), g1(-p)], [g2(q), g2(q)]).0;
        assert_eq!(actual, tower(expected), "multi mode={mode}");
        assert_eq!(
            g1(p).is_in_correct_subgroup_assuming_on_curve(),
            p.is_in_correct_subgroup_assuming_on_curve()
        );
        assert_eq!(
            g2(q).is_in_correct_subgroup_assuming_on_curve(),
            q.is_in_correct_subgroup_assuming_on_curve()
        );
    }
}

#[test]
fn groth16_acceptance_and_rejection_match_original() {
    let mut rng = ark_std::test_rng();
    let p = ark_bn254::G1Projective::generator();
    let q = ark_bn254::G2Projective::generator();
    for mode in 0..12 {
        let alpha = Fr::rand(&mut rng);
        let beta = Fr::rand(&mut rng);
        let x = Fr::rand(&mut rng);
        let c = if mode == 0 {
            Fr::ZERO
        } else {
            Fr::rand(&mut rng)
        };
        let vk = ark_groth16::VerifyingKey {
            alpha_g1: (p * alpha).into_affine(),
            beta_g2: (q * beta).into_affine(),
            gamma_g2: q.into_affine(),
            delta_g2: q.into_affine(),
            gamma_abc_g1: vec![p.into_affine(), p.double().into_affine()],
        };
        // e(A,Q) = e(alphaP,betaQ) * e((1+2x)P,Q) * e(cP,Q).
        let proof = ark_groth16::Proof {
            a: (p * (alpha * beta + Fr::ONE + x.double() + c)).into_affine(),
            b: q.into_affine(),
            c: (p * c).into_affine(),
        };
        let original = ark_groth16::prepare_verifying_key(&vk);
        let prepared = prepare(&vk);
        assert!(
            ark_groth16::Groth16::<ark_bn254::Bn254>::verify_proof(&original, &proof, &[x])
                .unwrap()
        );
        assert!(verify(&prepared, &proof, &[x]).unwrap());
        let changed = x + Fr::ONE;
        assert!(!ark_groth16::Groth16::<ark_bn254::Bn254>::verify_proof(
            &original,
            &proof,
            &[changed]
        )
        .unwrap());
        assert!(!verify(&prepared, &proof, &[changed]).unwrap());
        let mut changed = proof.clone();
        changed.a = (changed.a.into_group() + p).into_affine();
        assert!(
            !ark_groth16::Groth16::<ark_bn254::Bn254>::verify_proof(&original, &changed, &[x])
                .unwrap()
        );
        assert!(!verify(&prepared, &changed, &[x]).unwrap());
    }
}

#[test]
fn subgroup_rejection_survives_raw_coordinate_conversion() {
    let mut rng = ark_std::test_rng();
    let mut rejected = 0;
    for _ in 0..64 {
        if let Some(point) =
            ark_bn254::G2Affine::get_point_from_x_unchecked(ark_bn254::Fq2::rand(&mut rng), false)
        {
            assert!(point.is_on_curve());
            let expected = point.is_in_correct_subgroup_assuming_on_curve();
            assert_eq!(
                g2(point).is_in_correct_subgroup_assuming_on_curve(),
                expected
            );
            if !expected {
                rejected += 1;
            }
        }
    }
    assert!(
        rejected > 0,
        "oracle must exercise points outside the G2 subgroup"
    );
}
