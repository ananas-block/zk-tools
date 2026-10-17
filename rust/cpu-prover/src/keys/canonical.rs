use super::Keys;
use crate::{Error, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

impl Keys {
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
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../tests/unit/keys.rs"]
mod tests;
