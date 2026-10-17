//! Reusable BN254 Groth16 CPU prover. No DSL, Solana, Go or GPU dependency.
pub mod build;
mod compiled_matrices;
mod error;
mod keys;
mod matrices;
mod proof;
mod proof_finish;
mod randomness;
mod reduction;
mod zkey;
pub use error::Error;
pub use keys::Keys;
pub use matrices::{PreparedMatrices, R1csMatrices};
pub use reduction::CircomReduction;
pub type Proof = ark_groth16::Proof<ark_bn254::Bn254>;
pub type ProvingKey = ark_groth16::ProvingKey<ark_bn254::Bn254>;
pub type VerifyingKey = ark_groth16::VerifyingKey<ark_bn254::Bn254>;

#[cfg(any(
    all(test, not(target_arch = "wasm32")),
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
mod curve;
#[cfg(any(
    all(test, not(target_arch = "wasm32")),
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
mod glv;
#[cfg(any(
    test,
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
mod pairing;
#[cfg(any(
    test,
    all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )
))]
mod scalar_field;

use ark_bn254::Fr;
use ark_std::rand::{rngs::OsRng, RngCore};
use std::sync::Arc;

/// Prepared immutable keys and matrices. Each call owns its witness workspace.
pub struct Prover {
    keys: Arc<Keys>,
    matrices: Arc<PreparedMatrices>,
    #[cfg(all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    ))]
    prepared_verifying_key: pairing::Prepared,
    #[cfg(not(all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    )))]
    prepared_verifying_key: ark_groth16::PreparedVerifyingKey<ark_bn254::Bn254>,
    #[cfg(all(
        target_arch = "wasm32",
        feature = "wasm-prover",
        target_feature = "simd128"
    ))]
    prepared_msm: curve::PreparedKey,
}

impl Prover {
    pub fn new(keys: Arc<Keys>, matrices: Arc<PreparedMatrices>) -> Result<Self, Error> {
        let raw = matrices.matrices();
        let pk = keys.proving_key();
        use ark_poly::EvaluationDomain;
        let domain = ark_poly::GeneralEvaluationDomain::<Fr>::new(
            raw.num_constraints + raw.num_instance_variables,
        )
        .ok_or(Error::KeysForAnotherCircuit)?;
        if pk.h_query.len() != domain.size()
            || raw.num_instance_variables != pk.vk.gamma_abc_g1.len()
            || raw.num_witness_variables != pk.l_query.len()
            || pk.a_query.len() != raw.num_instance_variables + raw.num_witness_variables
            || pk.b_g1_query.len() != pk.a_query.len()
            || pk.b_g2_query.len() != pk.a_query.len()
        {
            return Err(Error::KeysForAnotherCircuit);
        }
        #[cfg(all(
            target_arch = "wasm32",
            feature = "wasm-prover",
            target_feature = "simd128"
        ))]
        let prepared_verifying_key = pairing::prepare(&pk.vk);
        #[cfg(not(all(
            target_arch = "wasm32",
            feature = "wasm-prover",
            target_feature = "simd128"
        )))]
        let prepared_verifying_key = ark_groth16::prepare_verifying_key(&pk.vk);
        #[cfg(all(
            target_arch = "wasm32",
            feature = "wasm-prover",
            target_feature = "simd128"
        ))]
        let prepared_msm = curve::PreparedKey::new(
            &pk.h_query,
            &pk.l_query,
            &pk.a_query,
            &pk.b_g1_query,
            &pk.b_g2_query,
        );
        Ok(Self {
            keys,
            matrices,
            prepared_verifying_key,
            #[cfg(all(
                target_arch = "wasm32",
                feature = "wasm-prover",
                target_feature = "simd128"
            ))]
            prepared_msm,
        })
    }

    pub fn prove(&self, assignment: &[Fr]) -> Result<Proof, Error> {
        let mut rng = OsRng;
        self.prove_with_entropy(assignment, |bytes| rng.try_fill_bytes(bytes))
    }

    // Keep entropy injection private: callers cannot weaken production blinding.
    fn prove_with_entropy(
        &self,
        assignment: &[Fr],
        fill: impl FnMut(&mut [u8]) -> Result<(), ark_std::rand::Error>,
    ) -> Result<Proof, Error> {
        let evaluations = self.matrices.evaluate_checked(assignment)?;
        let (r, s) = randomness::proof_randomizers_with(fill)?;
        self.prove_evaluations(assignment, evaluations, r, s)
    }

    /// Explicit blinding is available only for differential tests and golden fixtures.
    #[cfg(any(test, feature = "test-support"))]
    pub fn prove_with_test_blinding(
        &self,
        assignment: &[Fr],
        r: Fr,
        s: Fr,
    ) -> Result<Proof, Error> {
        let evaluations = self.matrices.evaluate_checked(assignment)?;
        self.prove_evaluations(assignment, evaluations, r, s)
    }

    fn prove_evaluations(
        &self,
        assignment: &[Fr],
        evaluations: [Vec<Fr>; 3],
        r: Fr,
        s: Fr,
    ) -> Result<Proof, Error> {
        let proof = proof::create_proof(
            &self.keys.proving_key,
            r,
            s,
            self.matrices.matrices(),
            assignment,
            evaluations,
            #[cfg(all(
                target_arch = "wasm32",
                feature = "wasm-prover",
                target_feature = "simd128"
            ))]
            &self.prepared_msm,
        )?;
        let inputs = assignment
            .get(1..self.matrices.matrices().num_instance_variables)
            .ok_or(Error::ProofInputsForAnotherCircuit)?;
        self.verify(&proof, inputs)?;
        Ok(proof)
    }

    pub fn verify(&self, proof: &Proof, inputs: &[Fr]) -> Result<(), Error> {
        #[cfg(all(
            target_arch = "wasm32",
            feature = "wasm-prover",
            target_feature = "simd128"
        ))]
        let accepted = pairing::verify(&self.prepared_verifying_key, proof, inputs);
        #[cfg(not(all(
            target_arch = "wasm32",
            feature = "wasm-prover",
            target_feature = "simd128"
        )))]
        let accepted = ark_groth16::Groth16::<ark_bn254::Bn254>::verify_proof(
            &self.prepared_verifying_key,
            proof,
            inputs,
        );
        if !accepted.map_err(|_| Error::ProofRejected)? {
            return Err(Error::ProofRejected);
        }
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/proof/security.rs"]
mod security_tests;

#[cfg(all(
    test,
    target_arch = "wasm32",
    feature = "test-support",
    feature = "wasm-prover"
))]
#[path = "../tests/wasm/smoke.rs"]
mod wasm_tests;
