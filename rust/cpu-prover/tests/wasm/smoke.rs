//! Standalone WASM checks: no Zolana DSL, Solana formatter, or Go bridge.
use super::*;
use ark_bn254::Bn254;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use wasm_bindgen_test::wasm_bindgen_test;

fn fixture() -> (Prover, Arc<Keys>) {
    let a = vec![vec![(Fr::one(), 2)]; 8];
    let b = vec![vec![(Fr::one(), 3)]; 8];
    let c = vec![vec![(Fr::one(), 1)]; 8];
    let matrices = Arc::new(PreparedMatrices::new(R1csMatrices::new([a, b, c], 2, 2, 8)).unwrap());
    let keys = Arc::new(Keys::from_bytes(include_bytes!("../fixtures/product.pk")).unwrap());
    (Prover::new(Arc::clone(&keys), matrices).unwrap(), keys)
}
fn assignment() -> [Fr; 4] {
    [Fr::one(), Fr::from(77u64), Fr::from(7u64), Fr::from(11u64)]
}
fn encoded(value: impl CanonicalSerialize) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).unwrap();
    bytes
}
fn plain() -> Proof {
    Proof::deserialize_compressed(include_bytes!("../fixtures/product.zero-proof").as_slice())
        .unwrap()
}

#[wasm_bindgen_test]
fn wasm_keys_validate_checksum_and_encoding() {
    use sha2::{Digest, Sha256};
    let bytes = include_bytes!("../fixtures/product.pk");
    assert!(Keys::from_bytes_checked(bytes, &Sha256::digest(bytes).into()).is_ok());
    assert!(matches!(
        Keys::from_bytes_checked(bytes, &[0; 32]),
        Err(Error::KeyChecksumMismatch)
    ));
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(Keys::from_bytes(&trailing).is_err());
    assert!(Keys::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    assert!(Keys::from_zkey_bytes(b"invalid", fixture().0.matrices.matrices()).is_err());
}

#[wasm_bindgen_test]
fn wasm_production_blinding_refreshes_every_component() {
    let (prover, keys) = fixture();
    let values = assignment();
    let zero = plain();
    let (mut a, mut b, mut c) = (
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );
    for _ in 0..8 {
        let proof = prover.prove(&values).unwrap();
        assert!(pairing::verify(
            &pairing::prepare(keys.verifying_key()),
            &proof,
            &[values[1]]
        )
        .unwrap());
        assert_ne!(proof.a, zero.a);
        assert_ne!(proof.b, zero.b);
        assert_ne!(proof.c, zero.c);
        assert!(a.insert(encoded(proof.a)));
        assert!(b.insert(encoded(proof.b)));
        assert!(c.insert(encoded(proof.c)));
        // The reference verifier uses ordinary arkworks arithmetic in this module.
        assert!(ark_groth16::Groth16::<Bn254>::verify_proof(
            &ark_groth16::prepare_verifying_key(keys.verifying_key()),
            &proof,
            &[values[1]]
        )
        .unwrap());
    }
}

#[wasm_bindgen_test]
fn wasm_fixed_blinding_matches_independent_native_proof() {
    let (prover, _) = fixture();
    let (r, s) = (Fr::from(13u64), Fr::from(19u64));
    let mut draws = [r, s].into_iter();
    let proof = prover
        .prove_with_entropy(&assignment(), |bytes| {
            bytes.copy_from_slice(&draws.next().unwrap().into_bigint().to_bytes_le());
            Ok(())
        })
        .unwrap();
    assert!(draws.next().is_none());
    assert_eq!(
        encoded(proof),
        include_bytes!("../fixtures/product.fixed-proof")
    );
}

#[wasm_bindgen_test]
fn wasm_both_zero_blindings_and_failed_entropy_reject() {
    let (prover, _) = fixture();
    for zero_draw in [0, 1] {
        let mut draw = 0;
        let result = prover.prove_with_entropy(&assignment(), |bytes| {
            bytes.fill(0);
            if draw != zero_draw {
                bytes[0] = 1;
            }
            draw += 1;
            Ok(())
        });
        assert!(matches!(result, Err(Error::InvalidProofRandomness)));
    }
    let result = prover.prove_with_entropy(&assignment(), |_| {
        Err(ark_std::rand::Error::from(
            std::num::NonZeroU32::new(ark_std::rand::Error::CUSTOM_START).unwrap(),
        ))
    });
    assert!(matches!(result, Err(Error::RandomnessUnavailable)));
    assert!(prover.prove(&assignment()).is_ok());
}

#[wasm_bindgen_test]
fn wasm_invalid_assignments_reject_and_prepared_state_recovers() {
    let (prover, _) = fixture();
    assert!(matches!(
        prover.prove(&assignment()[..3]),
        Err(Error::ProofInputsForAnotherCircuit)
    ));
    let mut values = assignment();
    values[0] = Fr::zero();
    assert!(matches!(
        prover.prove(&values),
        Err(Error::ProofInputsForAnotherCircuit)
    ));
    values = assignment();
    values[1] += Fr::one();
    assert!(matches!(
        prover.prove(&values),
        Err(Error::UnsatisfiedConstraint { row: 0 })
    ));
    assert!(prover.prove(&assignment()).is_ok());
}

#[wasm_bindgen_test]
fn wasm_scalar_and_pairing_kernels_match_reference() {
    assert!(scalar_field::scalar_self_test(0x7a12de05, 1024));
    assert!(pairing::self_test(0x3df97a21, 8));
    let minus_one = (-Fr::one()).into_bigint().to_bytes_le();
    assert_eq!(
        scalar_field::scalar_fixture(&minus_one, &minus_one).unwrap(),
        Fr::one().into_bigint().to_bytes_le()
    );
}

#[cfg(target_feature = "simd128")]
#[wasm_bindgen_test]
fn wasm_real_simd_base_field_matches_reference() {
    assert!(curve::simd_self_test(0x7a12de05, 1024));
    let minus_one = (-ark_bn254::Fq::one()).into_bigint().to_bytes_le();
    let expected = ark_bn254::Fq::one().into_bigint().to_bytes_le().repeat(2);
    assert_eq!(
        curve::base_field_fixture(&minus_one, &minus_one).unwrap(),
        expected
    );
}
