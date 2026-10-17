use super::*;
use ark_ff::AdditiveGroup;
proptest::proptest! {
    #[test]
    fn field_products_shrink_to_replayable_inputs(a in proptest::prelude::any::<[u8; 32]>(), b in proptest::prelude::any::<[u8; 32]>()) {
        let a = Fq::from_le_bytes_mod_order(&a);
        let b = Fq::from_le_bytes_mod_order(&b);
        proptest::prop_assert_eq!((F9::encode(a) * F9::encode(b)).decode(), a * b);
    }
}

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_std::UniformRand;
#[test]
fn reused_batch_inverse_handles_zero_and_fresh_values() {
    fn check<F: SmallField, A: Field>(encode: fn(A) -> F, decode: fn(F) -> A) {
        let mut rng = ark_std::test_rng();
        let mut scratch = F::scratch(1024);
        for length in [0, 1, 2, 129, 3, 512, 0, 127] {
            for mode in 0..3 {
                let original: Vec<A> = (0..length)
                    .map(|index| {
                        if mode == 0 || (mode == 1 && index % 3 == 0) {
                            A::ZERO
                        } else {
                            A::rand(&mut rng)
                        }
                    })
                    .collect();
                let expected: Vec<_> = original
                    .iter()
                    .map(|value| value.inverse().unwrap_or(A::ZERO))
                    .collect();
                let mut actual: Vec<_> = original.into_iter().map(encode).collect();
                F::invert_batch_in(&mut actual, &mut scratch);
                let actual: Vec<_> = actual.into_iter().map(decode).collect();
                assert_eq!(actual, expected, "length={length}, mode={mode}");
            }
        }
    }
    check(F9::encode, F9::decode);
    check(F92::encode, F92::decode);
}

#[test]
fn field_arithmetic_matches_arkworks() {
    let mut rng = ark_std::test_rng();
    assert_eq!(F9::ONE.decode(), Fq::ONE);
    for _ in 0..100_000 {
        let a = Fq::rand(&mut rng);
        let b = Fq::rand(&mut rng);
        let x = F9::encode(a);
        let y = F9::encode(b);
        assert_eq!(x.decode(), a);
        assert_eq!((x + y).decode(), a + b);
        assert_eq!((x - y).decode(), a - b);
        assert_eq!((-x).decode(), -a);
        assert_eq!((x * y).decode(), a * b);
        assert_eq!(F9::dot(x, y, x, y).decode(), a * b + a * b);
    }
    let mut values: Vec<_> = (0..1000)
        .map(|i| {
            if i % 7 == 0 {
                F92::ZERO
            } else {
                F92::encode(ark_bn254::Fq2::rand(&mut rng))
            }
        })
        .collect();
    let expected: Vec<_> = values
        .iter()
        .map(|v| v.decode().inverse().unwrap_or(ark_bn254::Fq2::ZERO))
        .collect();
    invert_batch(&mut values);
    assert_eq!(
        values.iter().copied().map(F92::decode).collect::<Vec<_>>(),
        expected
    );
    for _ in 0..1000 {
        let a = ark_bn254::Fq2::rand(&mut rng);
        let b = ark_bn254::Fq2::rand(&mut rng);
        let x = F92::encode(a);
        let y = F92::encode(b);
        assert_eq!((x * y).decode(), a * b);
        assert_eq!(x.square().decode(), a.square());
        assert_eq!(x.inverse().map(F92::decode), a.inverse());
    }
}
#[test]
fn buckets_and_scalar_edges_match_arkworks() {
    use ark_ec::PrimeGroup;
    let base = ark_bn254::G1Projective::generator().into_affine();
    let point = Affine {
        x: F9::encode(base.x),
        y: F9::encode(base.y),
        infinity: false,
    };
    let cases = vec![
        vec![],
        vec![Affine::ZERO],
        vec![point],
        vec![point, point],
        vec![point, point.negate()],
        vec![point, point.negate(), point],
        vec![point; 257],
        vec![point.negate(); 256],
    ];
    let mut offset = 0;
    let ranges: Vec<_> = cases
        .iter()
        .map(|case| {
            let start = offset;
            offset += case.len();
            start..offset
        })
        .collect();
    let expected: Vec<_> = cases
        .iter()
        .map(|case| {
            let mut p = Projective::ZERO;
            for &a in case {
                p.add_mixed(a);
            }
            ark_bn254::G1Projective::new_unchecked(p.x.decode(), p.y.decode(), p.z.decode())
        })
        .collect();
    let sums = sum_buckets(cases.into_iter().flatten().collect(), &ranges);
    for (sum, expected) in sums.into_iter().zip(expected) {
        let actual = if sum.infinity {
            ark_bn254::G1Affine::identity()
        } else {
            ark_bn254::G1Affine::new_unchecked(sum.x.decode(), sum.y.decode())
        };
        assert_eq!(actual, expected.into_affine());
    }
    let scalars = vec![
        BigInteger256::zero(),
        BigInteger256::from(1u64),
        Fr::MODULUS,
        BigInteger256::new([u64::MAX; 4]),
        BigInteger256::new([0, 0, 0, 1 << 63]),
    ];
    let entries: Vec<_> = scalars.iter().copied().map(|s| (point, s)).collect();
    let expected: ark_bn254::G1Projective = scalars.iter().map(|s| base.mul_bigint(*s)).sum();
    assert_eq!(msm_g1(&vec![base; scalars.len()], &scalars), expected);
    for width in 2..=13 {
        let p = pippenger(&entries, width, 256);
        let actual =
            ark_bn254::G1Projective::new_unchecked(p.x.decode(), p.y.decode(), p.z.decode());
        assert_eq!(actual, expected, "width {width}");
    }
}

#[test]
fn prepared_key_matches_fresh_scalar_msm() {
    let mut rng = ark_std::test_rng();
    let g1: Vec<_> = (0..129)
        .map(|i| {
            if i % 7 == 0 {
                ark_bn254::G1Affine::identity()
            } else {
                ark_bn254::G1Projective::rand(&mut rng).into_affine()
            }
        })
        .collect();
    let g2: Vec<_> = (0..129)
        .map(|i| {
            if i % 7 == 0 {
                ark_bn254::G2Affine::identity()
            } else {
                ark_bn254::G2Projective::rand(&mut rng).into_affine()
            }
        })
        .collect();
    let cache = PreparedKey::new(&g1, &g1, &g1, &g1, &g2);
    for _ in 0..3 {
        let mut scalars: Vec<_> = (0..129).map(|_| Fr::rand(&mut rng).into_bigint()).collect();
        scalars[0] = Fr::ZERO.into_bigint();
        scalars[1] = Fr::ONE.into_bigint();
        scalars[2] = (-Fr::ONE).into_bigint();
        scalars[3] = BigInteger256::from(u64::MAX);
        assert_eq!(
            cache.h.msm(&scalars),
            ark_bn254::G1Projective::msm_bigint(&g1, &scalars)
        );
        assert_eq!(cache.l.msm(&scalars), cache.h.msm(&scalars));
        assert_eq!(
            cache.a.query(&scalars[1..]).unwrap(),
            ark_bn254::G1Projective::msm_bigint(&g1[1..], &scalars[1..])
        );
        assert_eq!(
            cache.b1.query(&scalars[1..]).unwrap(),
            cache.a.query(&scalars[1..]).unwrap()
        );
        assert_eq!(
            cache.b2.query(&scalars[1..]).unwrap(),
            ark_bn254::G2Projective::msm_bigint(&g2[1..], &scalars[1..])
        );
    }
    let empty = PreparedKey::new(&[], &[], &[], &[], &[]);
    assert!(empty.a.query(&[]).is_none());
    assert!(empty.b2.query(&[]).is_none());
}

#[test]
fn msm_matches_arkworks() {
    let mut rng = ark_std::test_rng();
    for n in [0, 1, 2, 16, 128, 257] {
        let scalars: Vec<_> = (0..n)
            .map(|i| match i % 8 {
                0 => Fr::ZERO.into_bigint(),
                1 => Fr::ONE.into_bigint(),
                2 => (-Fr::ONE).into_bigint(),
                _ => Fr::rand(&mut rng).into_bigint(),
            })
            .collect();
        let g1: Vec<_> = (0..n)
            .map(|i| {
                if i % 7 == 0 {
                    ark_bn254::G1Affine::identity()
                } else {
                    ark_bn254::G1Projective::rand(&mut rng).into_affine()
                }
            })
            .collect();
        let g2: Vec<_> = (0..n)
            .map(|i| {
                if i % 7 == 0 {
                    ark_bn254::G2Affine::identity()
                } else {
                    ark_bn254::G2Projective::rand(&mut rng).into_affine()
                }
            })
            .collect();
        assert_eq!(
            msm_g1(&g1, &scalars),
            ark_bn254::G1Projective::msm_bigint(&g1, &scalars)
        );
        assert_eq!(
            msm_g2(&g2, &scalars),
            ark_bn254::G2Projective::msm_bigint(&g2, &scalars)
        );
    }
}

fn msm<F: SmallField>(bases: &[Affine<F>], scalars: &[BigInteger256]) -> Projective<F> {
    msm_internal(bases, scalars, None)
}

fn msm_g1(bases: &[ark_bn254::G1Affine], scalars: &[BigInteger256]) -> ark_bn254::G1Projective {
    original_g1(msm(&convert_g1(bases), scalars))
}

fn msm_g2(bases: &[ark_bn254::G2Affine], scalars: &[BigInteger256]) -> ark_bn254::G2Projective {
    original_g2(msm(&convert_g2(bases), scalars))
}

fn invert_batch<F: SmallField>(values: &mut [F]) {
    let mut scratch = F::scratch(values.len());
    F::invert_batch_in(values, &mut scratch);
}
