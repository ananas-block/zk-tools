use super::*;
use super::{base::F9, extension::F92};
use ark_bn254::Fq;
use ark_ff::{AdditiveGroup, Field, PrimeField};
proptest::proptest! {
    #[test]
    fn field_products_shrink_to_replayable_inputs(a in proptest::prelude::any::<[u8; 32]>(), b in proptest::prelude::any::<[u8; 32]>()) {
        let a = Fq::from_le_bytes_mod_order(&a);
        let b = Fq::from_le_bytes_mod_order(&b);
        proptest::prop_assert_eq!((F9::encode(a) * F9::encode(b)).decode(), a * b);
    }
}

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

fn invert_batch<F: SmallField>(values: &mut [F]) {
    let mut scratch = F::scratch(values.len());
    F::invert_batch_in(values, &mut scratch);
}
