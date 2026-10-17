use ark_relations::gr1cs::SynthesisError;

/// Errors contain engine data only. Frontends attach their circuit labels.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the Groth16 key cannot be serialized or deserialized: {0}")]
    KeySerialization(ark_serialize::SerializationError),
    #[error("the Groth16 key does not match its sha256 checksum")]
    KeyChecksumMismatch,
    #[error("the zkey is malformed: {0}")]
    InvalidZkey(&'static str),
    #[error("the zkey holds a corrupt {0} value")]
    CorruptZkeyValue(&'static str),
    #[error("the zkey is unfinished: no one has contributed to its setup")]
    UnfinishedZkey,
    #[error("the Groth16 keys belong to another circuit")]
    KeysForAnotherCircuit,
    #[error("the constraint matrices are malformed: {0}")]
    InvalidMatrices(&'static str),
    #[error("the proof inputs build another circuit than the prover's")]
    ProofInputsForAnotherCircuit,
    #[error("the assignment fails constraint {row}")]
    UnsatisfiedConstraint { row: usize },
    #[error("the proof does not verify under these keys")]
    ProofRejected,
    #[error("secure proof randomness is unavailable")]
    RandomnessUnavailable,
    #[error("the randomness source returned invalid or zero proof blinding")]
    InvalidProofRandomness,
    #[error("{0}")]
    ExportTooLarge(&'static str),
    #[error("{0}")]
    Internal(#[from] SynthesisError),
}
