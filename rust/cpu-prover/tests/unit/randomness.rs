use super::*;
#[test]
fn broken_entropy_rejects_instead_of_producing_zero_blinding() {
    assert!(matches!(
        sample_blinding(|bytes| {
            bytes.fill(0);
            Ok(())
        })
        .unwrap_err(),
        Error::InvalidProofRandomness
    ));
    assert!(matches!(
        sample_blinding(|bytes| {
            bytes.fill(255);
            Ok(())
        })
        .unwrap_err(),
        Error::InvalidProofRandomness
    ));
    assert!(matches!(
        sample_blinding(|_| Err(ark_std::rand::Error::new(std::io::Error::other(
            "entropy unavailable"
        ))))
        .unwrap_err(),
        Error::RandomnessUnavailable
    ));
}
