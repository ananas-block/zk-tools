use super::*;
use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;
fn keys() -> Keys {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    Keys::from(ProvingKey {
        vk: VerifyingKey {
            alpha_g1: g1,
            beta_g2: g2,
            gamma_g2: g2,
            delta_g2: g2,
            gamma_abc_g1: vec![g1; 2],
        },
        beta_g1: g1,
        delta_g1: g1,
        a_query: vec![g1; 2],
        b_g1_query: vec![g1; 2],
        b_g2_query: vec![g2; 2],
        h_query: vec![g1],
        l_query: vec![g1],
    })
}

#[test]
fn canonical_keys_preserve_points_and_setup_provenance() {
    for imported_zkey in [false, true] {
        let keys = Keys {
            imported_zkey,
            ..keys()
        };
        let bytes = keys.to_bytes().unwrap();
        let reloaded = Keys::from_bytes(&bytes).unwrap();
        assert_eq!(reloaded.proving_key, keys.proving_key);
        assert_eq!(reloaded.verifying_key(), keys.verifying_key());
        assert_eq!(reloaded.imported_zkey, imported_zkey);
    }
}

#[test]
fn canonical_keys_reject_invalid_points_and_incomplete_encodings() {
    let mut keys = keys();
    let bytes = keys.to_bytes().unwrap();
    let (_, truncated) = bytes.split_last().unwrap();
    assert!(Keys::from_bytes(truncated).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Keys::from_bytes(&trailing).is_err());

    keys.proving_key.vk.alpha_g1 =
        G1Affine::new_unchecked(ark_bn254::Fq::from(1u64), ark_bn254::Fq::from(1u64));
    assert!(Keys::from_bytes(&keys.to_bytes().unwrap()).is_err());
}

#[test]
fn canonical_keys_check_the_pinned_checksum_before_parsing() {
    use sha2::{Digest, Sha256};

    let bytes = keys().to_bytes().unwrap();
    let checksum = Sha256::digest(&bytes).into();
    assert!(Keys::from_bytes_checked(&bytes, &checksum).is_ok());
    let error = Keys::from_bytes_checked(b"corrupt key", &checksum)
        .err()
        .unwrap();
    assert!(matches!(error, Error::KeyChecksumMismatch));
}
