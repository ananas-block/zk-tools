use crate::{zkey::Zkey, Error, ProvingKey, R1csMatrices, VerifyingKey};
#[cfg(feature = "setup")]
use ark_bn254::Bn254;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Canonical arkworks key and the imported-ceremony marker used by existing files.
pub struct Keys {
    pub(crate) proving_key: ProvingKey,
    imported_zkey: bool,
}

impl From<ProvingKey> for Keys {
    fn from(proving_key: ProvingKey) -> Self {
        Self {
            proving_key,
            imported_zkey: false,
        }
    }
}

impl Keys {
    pub fn proving_key(&self) -> &ProvingKey {
        &self.proving_key
    }
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.proving_key.vk
    }
    pub fn imported_zkey(&self) -> bool {
        self.imported_zkey
    }
    /// Serializes the ceremony-import flag followed by the proving key using
    /// arkworks' canonical uncompressed encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        self.imported_zkey
            .serialize_uncompressed(&mut bytes)
            .map_err(Error::KeySerialization)?;
        self.proving_key
            .serialize_uncompressed(&mut bytes)
            .map_err(Error::KeySerialization)?;
        Ok(bytes)
    }

    /// Reads canonical key bytes, validating curve and subgroup membership.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, Error> {
        let imported_zkey =
            bool::deserialize_uncompressed(&mut bytes).map_err(Error::KeySerialization)?;
        let proving_key =
            ProvingKey::deserialize_uncompressed(&mut bytes).map_err(Error::KeySerialization)?;
        if !bytes.is_empty() {
            return Err(
                Error::KeySerialization(ark_serialize::SerializationError::InvalidData).into(),
            );
        }
        Ok(Self {
            imported_zkey,
            proving_key,
        })
    }

    /// Checks a key against a trusted SHA-256 before deserializing it.
    pub fn from_bytes_checked(bytes: &[u8], checksum: &[u8; 32]) -> Result<Self, Error> {
        use sha2::{Digest, Sha256};

        if Sha256::digest(bytes).as_slice() != checksum {
            return Err(Error::KeyChecksumMismatch.into());
        }
        Self::from_bytes(bytes)
    }

    pub fn from_zkey_bytes(bytes: &[u8], matrices: &R1csMatrices) -> Result<Self, Error> {
        matrices.validate()?;
        let zkey = Zkey::read(bytes)?;
        zkey.check_circuit(matrices)?;
        Ok(Self {
            proving_key: zkey.proving_key,
            imported_zkey: true,
        })
    }

    #[cfg(feature = "setup")]
    pub fn with_insecure_test_setup(matrices: &R1csMatrices) -> Result<Self, Error> {
        matrices.validate()?;
        use ark_std::rand::{rngs::StdRng, SeedableRng};
        Ok(Self::from(ark_groth16::Groth16::<
            Bn254,
            crate::CircomReduction,
        >::generate_random_parameters_with_reduction(
            crate::matrices::Replay(matrices),
            &mut StdRng::seed_from_u64(0),
        )?))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
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
}
