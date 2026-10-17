//! Reusable BN254 Groth16 CPU prover. No DSL, Solana, Go or GPU dependency.
#[path = "wasm_build.rs"]
pub mod build;
mod constraints;
mod error;
mod kernels;
mod keys;
mod prover;

pub use constraints::{PreparedMatrices, R1csMatrices};
pub use error::Error;
pub use kernels::fft::CircomReduction;
pub use keys::Keys;
pub use prover::Prover;
pub type Proof = ark_groth16::Proof<ark_bn254::Bn254>;
pub type ProvingKey = ark_groth16::ProvingKey<ark_bn254::Bn254>;
pub type VerifyingKey = ark_groth16::VerifyingKey<ark_bn254::Bn254>;
