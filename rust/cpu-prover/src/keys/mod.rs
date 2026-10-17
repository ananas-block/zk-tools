mod canonical;
mod zkey;

use crate::{Error, ProvingKey, R1csMatrices, VerifyingKey};
#[cfg(feature = "setup")]
use ark_bn254::Bn254;
use zkey::Zkey;

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
            crate::constraints::Replay(matrices),
            &mut StdRng::seed_from_u64(0),
        )?))
    }
}
