use crate::Error;
use ark_bn254::Fr;
use ark_ff::{Field, Zero};

fn sample_blinding(
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ark_std::rand::Error>,
) -> Result<Fr, Error> {
    // Canonical rejection sampling preserves uniformity. Bound retries so a
    // broken source cannot hang; zero is an error, not an unblinded proof.
    for _ in 0..128 {
        let mut bytes = [0u8; 32];
        fill(&mut bytes).map_err(|_| Error::RandomnessUnavailable)?;
        if let Some(value) = Fr::from_random_bytes(&bytes) {
            if value.is_zero() {
                return Err(Error::InvalidProofRandomness.into());
            }
            return Ok(value);
        }
    }
    Err(Error::InvalidProofRandomness.into())
}

pub(crate) fn proof_randomizers_with(
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ark_std::rand::Error>,
) -> Result<(Fr, Fr), Error> {
    Ok((sample_blinding(&mut fill)?, sample_blinding(&mut fill)?))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod randomness_tests {
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
}
