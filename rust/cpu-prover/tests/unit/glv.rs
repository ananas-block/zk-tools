use super::*;
use ark_ff::{BigInteger, PrimeField, UniformRand};
fn check<P: Bn254Glv>() {
    let mut rng = ark_std::test_rng();
    let mut cases = vec![
        BigInteger256::zero(),
        BigInteger256::from(1u64),
        BigInteger256::new([u64::MAX; 4]),
        Fr::MODULUS,
    ];
    for bit in 0..256 {
        let mut value = BigInteger256::from(1u64);
        value <<= bit;
        cases.push(value);
    }
    cases.extend((0..10000).map(|_| Fr::rand(&mut rng).into_bigint()));
    for k in cases {
        let ((s1, k1), (s2, k2)) = decompose::<P>(k);
        assert!(
            k1.num_bits() <= 130 && k2.num_bits() <= 130,
            "component bound {k:?}, {k1:?}, {k2:?}"
        );
        let a = Fr::from_bigint(k1).unwrap();
        let b = Fr::from_bigint(k2).unwrap();
        let a = if s1 { a } else { -a };
        let b = if s2 { b } else { -b };
        assert_eq!(
            a + P::LAMBDA * b,
            Fr::from_le_bytes_mod_order(&k.to_bytes_le())
        );
    }
}
#[test]
fn fixed_glv_g1_recomposes() {
    check::<g1::Config>();
}
#[test]
fn fixed_glv_g2_recomposes() {
    check::<g2::Config>();
}
