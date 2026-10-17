use super::*;
use ark_bn254::Fq;
use ark_ec::CurveGroup;
use ark_ff::{AdditiveGroup, Field, UniformRand, Zero};

#[test]
fn joint_finish_matches_ark_randomized_projective_inputs() {
    let mut rng = ark_std::test_rng();
    let edge = [
        Fr::ZERO,
        Fr::ONE,
        -Fr::ONE,
        Fr::from(2u64),
        Fr::from(1u64 << 63),
    ];
    for sample in 0..32 {
        let affine = ark_bn254::G1Projective::rand(&mut rng).into_affine();
        let z = Fq::rand(&mut rng);
        let a = if sample == 0 {
            ark_bn254::G1Projective::zero()
        } else {
            ark_bn254::G1Projective::new_unchecked(
                affine.x * z.square(),
                affine.y * z.square() * z,
                z,
            )
        };
        let b = match sample % 4 {
            0 => ark_bn254::G1Projective::zero(),
            1 => a,
            2 => -a,
            _ => ark_bn254::G1Projective::rand(&mut rng),
        };
        let l = ark_bn254::G1Projective::rand(&mut rng);
        let h = if sample % 3 == 0 {
            -l
        } else {
            ark_bn254::G1Projective::rand(&mut rng)
        };
        let cases = if sample < 5 {
            edge.to_vec()
        } else {
            vec![Fr::rand(&mut rng), Fr::rand(&mut rng)]
        };
        for &r in &cases {
            for &s in &cases {
                let expected = a * s + b * r + l + h;
                assert_eq!(
                    finish_c(a, b, r, s, l, h).into_affine(),
                    expected.into_affine(),
                    "sample {sample}, r={r}, s={s}"
                );
            }
        }
    }
}
