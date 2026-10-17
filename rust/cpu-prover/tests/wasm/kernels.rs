#[cfg(target_feature = "simd128")]
use super::field::base as curve;
use super::{field::scalar as scalar_field, pairing};
use ark_bn254::Fr;
use ark_ff::{BigInteger, One, PrimeField};
use wasm_bindgen_test::wasm_bindgen_test;

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
