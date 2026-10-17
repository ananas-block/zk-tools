//! Release gates for proof correctness and zero-knowledge blinding.
use super::*;
use crate::{CircomReduction, R1csMatrices};
use ark_bn254::Bn254;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_groth16::{r1cs_to_qap::R1CSToQAP, Groth16};
use ark_poly::EvaluationDomain;
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, Matrix, SynthesisError},
    lc,
};
use ark_serialize::CanonicalSerialize;
use proptest::prelude::*;
use std::{collections::HashSet, sync::OnceLock};

const ROWS: usize = 8;
#[derive(Clone, Copy)]
struct Product {
    x: Fr,
    y: Fr,
}
impl ConstraintSynthesizer<Fr> for Product {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| Ok(self.x))?;
        let y = cs.new_witness_variable(|| Ok(self.y))?;
        let z = cs.new_input_variable(|| Ok(self.x * self.y))?;
        for _ in 0..ROWS {
            cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + y, || lc!() + z)?;
        }
        Ok(())
    }
}

// Independent reference uses arkworks' prover/MSMs and ordinary inverse/forward
// FFTs, without the prepared matrix plan, SIMD field, or fused coset transform.
struct ReferenceReduction;
impl R1CSToQAP for ReferenceReduction {
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError> {
        CircomReduction::instance_map_with_evaluation::<F, D>(cs, t)
    }
    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        zt: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        CircomReduction::h_query_scalars::<F, D>(max_power, t, zt, delta_inverse)
    }
    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &[Matrix<F>],
        inputs: usize,
        constraints: usize,
        assignment: &[F],
    ) -> Result<Vec<F>, SynthesisError> {
        let a_rows = matrices.first().ok_or(SynthesisError::ArityMismatch)?;
        let b_rows = matrices.get(1).ok_or(SynthesisError::ArityMismatch)?;
        let evaluate = |row: &Vec<(F, usize)>| {
            row.iter().try_fold(F::zero(), |sum, (coefficient, index)| {
                assignment
                    .get(*index)
                    .map(|v| sum + *coefficient * v)
                    .ok_or(SynthesisError::AssignmentMissing)
            })
        };
        let mut a = a_rows
            .iter()
            .take(constraints)
            .map(evaluate)
            .collect::<Result<Vec<_>, _>>()?;
        let mut b = b_rows
            .iter()
            .take(constraints)
            .map(evaluate)
            .collect::<Result<Vec<_>, _>>()?;
        let mut c: Vec<_> = a.iter().zip(&b).map(|(a, b)| *a * b).collect();
        let domain =
            D::new(constraints + inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let shift = D::new(2 * domain.size())
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?
            .element(1);
        a.extend_from_slice(
            assignment
                .get(..inputs)
                .ok_or(SynthesisError::AssignmentMissing)?,
        );
        for values in [&mut a, &mut b, &mut c] {
            values.resize(domain.size(), F::zero());
            domain.ifft_in_place(values);
            D::distribute_powers_and_mul_by_const(values, shift, F::one());
            domain.fft_in_place(values);
        }
        Ok(a.iter()
            .zip(&b)
            .zip(&c)
            .map(|((a, b), c)| *a * b - c)
            .collect())
    }
}

fn product_matrices() -> R1csMatrices {
    R1csMatrices::new(
        [
            vec![vec![(Fr::one(), 2)]; ROWS],
            vec![vec![(Fr::one(), 3)]; ROWS],
            vec![vec![(Fr::one(), 1)]; ROWS],
        ],
        2,
        2,
        ROWS,
    )
}

struct Fixture {
    keys: Arc<Keys>,
    prover: Prover,
}
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let matrices = product_matrices();
        let keys = Arc::new(Keys::from_bytes(include_bytes!("../fixtures/product.pk")).unwrap());
        let matrices = Arc::new(PreparedMatrices::new(matrices).unwrap());
        let prover = Prover::new(Arc::clone(&keys), matrices).unwrap();
        Fixture { keys, prover }
    })
}
fn assignment(x: Fr, y: Fr) -> [Fr; 4] {
    [Fr::one(), x * y, x, y]
}
fn reference(x: Fr, y: Fr, r: Fr, s: Fr) -> Proof {
    Groth16::<Bn254, ReferenceReduction>::create_proof_with_reduction(
        Product { x, y },
        fixture().keys.proving_key(),
        r,
        s,
    )
    .unwrap()
}
fn scripted_proof(values: &[Fr], r: Fr, s: Fr) -> Proof {
    let mut draws = [r, s].into_iter();
    let proof = fixture()
        .prover
        .prove_with_entropy(values, |bytes| {
            let scalar = draws.next().expect("exactly two independent entropy draws");
            bytes.copy_from_slice(&scalar.into_bigint().to_bytes_le());
            Ok(())
        })
        .unwrap();
    assert!(
        draws.next().is_none(),
        "both randomizers must consume entropy"
    );
    proof
}
fn bytes(value: impl CanonicalSerialize) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).unwrap();
    bytes
}

#[test]
fn security_blinding_obeys_all_three_groth16_equations() {
    let f = fixture();
    let (x, y) = (Fr::from(7u64), Fr::from(11u64));
    let values = assignment(x, y);
    let plain = reference(x, y, Fr::zero(), Fr::zero());
    let pk = f.keys.proving_key();
    // Compute B in G1 independently from the key and full witness assignment.
    let b1_plain = pk
        .b_g1_query
        .iter()
        .zip(&values)
        .fold(pk.beta_g1.into_group(), |sum, (base, value)| {
            sum + *base * value
        });
    for (r, s) in [
        (Fr::one(), Fr::from(2u64)),
        (-Fr::one(), Fr::from(17u64)),
        (Fr::from(99u64), -Fr::one()),
    ] {
        let proof = scripted_proof(&values, r, s);
        assert_eq!(
            proof.a,
            (plain.a.into_group() + pk.delta_g1 * r).into_affine()
        );
        assert_eq!(
            proof.b,
            (plain.b.into_group() + pk.vk.delta_g2 * s).into_affine()
        );
        assert_eq!(
            proof.c,
            (plain.c.into_group() + plain.a * s + b1_plain * r + pk.delta_g1 * (r * s))
                .into_affine()
        );
        assert_ne!(proof.a, plain.a, "r must blind A");
        assert_ne!(proof.b, plain.b, "s must blind B");
        assert_ne!(proof.c, plain.c, "blinding must propagate into C");
        assert_eq!(proof, reference(x, y, r, s));
    }
    let a = scripted_proof(&values, Fr::one(), Fr::from(2u64));
    let r_changed = scripted_proof(&values, Fr::from(3u64), Fr::from(2u64));
    let s_changed = scripted_proof(&values, Fr::one(), Fr::from(5u64));
    assert_ne!(a.a, r_changed.a);
    assert_eq!(a.b, r_changed.b);
    assert_ne!(a.c, r_changed.c);
    assert_eq!(a.a, s_changed.a);
    assert_ne!(a.b, s_changed.b);
    assert_ne!(a.c, s_changed.c);
}

#[test]
fn security_production_proofs_refresh_both_blindings_for_repeated_private_inputs() {
    let f = fixture();
    let (x, y) = (Fr::from(7u64), Fr::from(11u64));
    let values = assignment(x, y);
    let plain = reference(x, y, Fr::zero(), Fr::zero());
    let (mut a_seen, mut b_seen, mut c_seen) = (HashSet::new(), HashSet::new(), HashSet::new());
    for _ in 0..32 {
        // Actual production OsRng API, with an unchanged key and private witness.
        let proof = f.prover.prove(&values).unwrap();
        assert_ne!(proof.a, plain.a);
        assert_ne!(proof.b, plain.b);
        assert_ne!(proof.c, plain.c);
        assert!(a_seen.insert(bytes(proof.a)), "reused r");
        assert!(b_seen.insert(bytes(proof.b)), "reused s");
        assert!(c_seen.insert(bytes(proof.c)), "reused blinded C");
        assert!(Groth16::<Bn254>::verify_proof(
            &ark_groth16::prepare_verifying_key(&f.keys.proving_key().vk),
            &proof,
            &[x * y]
        )
        .unwrap());
    }
}

#[test]
fn security_zero_failed_and_noncanonical_entropy_never_returns_a_proof() {
    let f = fixture();
    let values = assignment(Fr::from(7u64), Fr::from(11u64));
    for zero_draw in [0, 1] {
        let mut draw = 0;
        let result = f.prover.prove_with_entropy(&values, |bytes| {
            bytes.fill(0);
            if draw != zero_draw {
                bytes[0] = 1;
            }
            draw += 1;
            Ok(())
        });
        assert!(matches!(result, Err(Error::InvalidProofRandomness)));
    }
    for fail_draw in [0, 1] {
        let mut draw = 0;
        let result = f.prover.prove_with_entropy(&values, |bytes| {
            if draw == fail_draw {
                return Err(ark_std::rand::Error::new(std::io::Error::other(
                    "entropy unavailable",
                )));
            }
            bytes.fill(0);
            bytes[0] = 1;
            draw += 1;
            Ok(())
        });
        assert!(matches!(result, Err(Error::RandomnessUnavailable)));
    }
    let mut draws = 0;
    let result = f.prover.prove_with_entropy(&values, |bytes| {
        draws += 1;
        bytes.fill(255);
        Ok(())
    });
    assert!(matches!(result, Err(Error::InvalidProofRandomness)));
    assert_eq!(
        draws, 128,
        "broken entropy must terminate without modulo reduction"
    );
    // Rejection sampling must retry a noncanonical scalar, not reduce it modulo r.
    let mut draws = 0;
    let r = Fr::from(13u64);
    let s = Fr::from(19u64);
    let proof = f
        .prover
        .prove_with_entropy(&values, |bytes| {
            draws += 1;
            match draws {
                1 => bytes.fill(255),
                2 => bytes.copy_from_slice(&r.into_bigint().to_bytes_le()),
                3 => bytes.copy_from_slice(&s.into_bigint().to_bytes_le()),
                _ => panic!("unexpected entropy draw"),
            };
            Ok(())
        })
        .unwrap();
    assert_eq!(draws, 3);
    assert_eq!(proof, reference(Fr::from(7u64), Fr::from(11u64), r, s));
    assert!(
        f.prover.prove(&values).is_ok(),
        "entropy failures must leave prepared state usable"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn functional_equivalence_and_blinding_match_independent_reference(
        x in any::<[u8;32]>(),y in any::<[u8;32]>(),r in any::<[u8;32]>(),s in any::<[u8;32]>()
    ) {
        let x=Fr::from_le_bytes_mod_order(&x);let y=Fr::from_le_bytes_mod_order(&y);
        let r=Fr::from_le_bytes_mod_order(&r);let s=Fr::from_le_bytes_mod_order(&s);
        prop_assume!(!r.is_zero() && !s.is_zero());
        let proof=scripted_proof(&assignment(x,y),r,s);
        prop_assert_eq!(&proof,&reference(x,y,r,s));
        let plain=reference(x,y,Fr::zero(),Fr::zero());
        prop_assert_eq!(proof.a,(plain.a.into_group()+fixture().keys.proving_key().delta_g1*r).into_affine());
        prop_assert_eq!(proof.b,(plain.b.into_group()+fixture().keys.proving_key().vk.delta_g2*s).into_affine());
        prop_assert!(Groth16::<Bn254>::verify_proof(&ark_groth16::prepare_verifying_key(&fixture().keys.proving_key().vk),&proof,&[x*y]).unwrap());
    }
}

/// Regenerate the explicitly insecure browser test key and reference proofs.
#[cfg(feature = "setup")]
#[test]
#[ignore = "fixture generator; run explicitly when changing the test circuit"]
fn write_wasm_fixtures() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&directory).unwrap();
    let keys = Keys::with_insecure_test_setup(&product_matrices()).unwrap();
    std::fs::write(directory.join("product.pk"), keys.to_bytes().unwrap()).unwrap();
    let (x, y) = (Fr::from(7u64), Fr::from(11u64));
    for (name, r, s) in [
        ("product.fixed-proof", Fr::from(13u64), Fr::from(19u64)),
        ("product.zero-proof", Fr::zero(), Fr::zero()),
    ] {
        let proof = Groth16::<Bn254, ReferenceReduction>::create_proof_with_reduction(
            Product { x, y },
            keys.proving_key(),
            r,
            s,
        )
        .unwrap();
        std::fs::write(directory.join(name), bytes(proof)).unwrap();
    }
}
