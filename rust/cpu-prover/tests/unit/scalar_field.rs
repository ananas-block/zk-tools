use super::*;
proptest::proptest! {
    #[test]
    fn scalar_products_shrink_to_replayable_inputs(a in proptest::prelude::any::<[u8; 32]>(), b in proptest::prelude::any::<[u8; 32]>()) {
        use ark_ff::PrimeField;
        let a = Fr::from_le_bytes_mod_order(&a);
        let b = Fr::from_le_bytes_mod_order(&b);
        proptest::prop_assert_eq!((from_ark(a) * from_ark(b)).0, (a * b).0);
    }
}

use ark_ff::{Field, UniformRand};
#[test]
fn scalar_arithmetic_and_fft_match_arkworks() {
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    let mut rng = ark_std::test_rng();
    for _ in 0..100_000 {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let fa = from_ark(a);
        let fb = from_ark(b);
        assert_eq!((fa * fb).0, (a * b).0);
        assert_eq!(fa.square().0, a.square().0);
        assert_eq!(
            Scalar::sum_of_products(&[fa, fb], &[fb, fa]).0,
            (a * b + b * a).0
        );
    }
    for n in [1, 2, 8, 64, 1024, 8192] {
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        let cpu_domain = GeneralEvaluationDomain::<Scalar>::new(n).unwrap();
        assert_eq!(domain.size(), cpu_domain.size());
        assert_eq!(domain.element(1).0, cpu_domain.element(1).0);
        let original: Vec<_> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let mut native = original.clone();
        let mut cpu: Vec<_> = original.iter().copied().map(from_ark).collect();
        domain.fft_in_place(&mut native);
        cpu_domain.fft_in_place(&mut cpu);
        assert_eq!(
            native.iter().map(|f| f.0).collect::<Vec<_>>(),
            cpu.iter().map(|f| f.0).collect::<Vec<_>>()
        );
        cpu_domain.ifft_in_place(&mut cpu);
        assert_eq!(
            original.iter().map(|f| f.0).collect::<Vec<_>>(),
            cpu.iter().map(|f| f.0).collect::<Vec<_>>()
        );
    }
}
