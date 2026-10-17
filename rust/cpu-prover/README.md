# Rust CPU prover

`zk-tools-cpu-prover` is a standalone BN254 Groth16 engine for native Rust and browser WebAssembly. It accepts constraint matrices, a matching key and a full witness assignment (constant one, public variables, then private variables), and returns an arkworks Groth16 proof. Circuit synthesis, witness generation, JavaScript application bindings and Solana formatting belong to the caller. The existing Go/WASM and cgo bridges remain separate consumers of the upstream Go prover.

The engine owns prepared immutable keys and expression plans, FFT/quotient transforms, MSMs, proof assembly, proof verification and secure blinding. Each proof evaluates its own witness workspace. Browser builds with `wasm-prover` and `simd128` use portable SIMD; single-threaded builds require no shared memory or cross-origin isolation. `parallel` enables Rayon and requires the host to initialize a worker pool for threaded browser use. This crate does not initialize browser workers or select packages. No WebGPU backend is included.

```rust,no_run
use std::sync::Arc;
use zk_tools_cpu_prover::{Keys, PreparedMatrices, Prover, R1csMatrices};
# fn example(matrices: R1csMatrices, bytes: &[u8], checksum: &[u8;32], assignment: &[ark_bn254::Fr]) -> Result<(), zk_tools_cpu_prover::Error> {
let matrices = Arc::new(PreparedMatrices::new(matrices)?);
let keys = Arc::new(Keys::from_bytes_checked(bytes, checksum)?);
let prover = Prover::new(keys, matrices)?;
let proof = prover.prove(assignment)?;
# let _ = proof;
# Ok(()) }
```

Existing canonical key bytes and snarkjs ceremony zkeys are supported. zkey imports check the expected circuit coefficients and domain. The engine implements the Circom quotient/key convention used by the imported prover; this does not add Gnark commitment support or make arbitrary Gnark keys interchangeable with arkworks keys. Canonical files retain their existing imported-ceremony marker; that marker is not independently authenticated provenance. Pin the expected checksum from a trusted source.

Production proving draws fresh nonzero `r` and `s` through fallible OS/browser entropy and canonical rejection sampling. Entropy failure, zero scalars and a bounded run of noncanonical draws reject the proof. Explicit blinding exists only behind `test-support`. The `setup` feature's deterministic setup and the committed test keys are **insecure fixtures**, unsuitable for production.

## Checks

```sh
cargo test --locked --release
cargo test --locked --release --features setup
cargo test --locked --release --features setup,parallel
wasm-pack test --node --release . --locked --features wasm-prover,test-support
RUSTFLAGS='-C target-feature=+simd128' wasm-pack test --node --release . --locked --features wasm-prover,test-support
```

Test bodies live under `tests/unit/`, `tests/proof/` and `tests/wasm/`; shared keys and reference proofs live in `tests/fixtures/`. Private-kernel tests are compiled through conditional module declarations, so they do not require extra public APIs.

The security and proof-equivalence gates run in default native `cargo test` builds, with no test-setup feature required. The security gate checks all three Groth16 blinding equations against independently computed group operations, changes each randomizer separately, checks production entropy refreshes both randomizers, and rejects failed/zero/noncanonical entropy. A 64-case proof property test compares with the arkworks prover using an independent ordinary-FFT quotient transform. These checks support correctness; they are not a formal zero-knowledge proof or side-channel audit. Kernels use variable-time algorithms.

Standalone WASM tests load the committed fixture key, verify fresh proofs with the reference verifier, compare with native reference proof bytes under fixed blinding, reject malformed assignments/keys and failed blinding, and exercise scalar, pairing and real SIMD kernels. Node exercises the actual WASM binary; multi-engine browser tests and physical-device release checks remain in the DSL integration suite.

To regenerate only the intentionally insecure WASM fixtures:

```sh
cargo test --release --features setup --lib write_wasm_fixtures -- --ignored
```

## Build contract

Enable `simd128` for shipping browser builds. SIMD and scalar reference builds are separate binaries. Do not enable relaxed SIMD. `build::OPTIMIZED_WASM_CFG` permits early kernel inlining only when the final module receives the bounded Binaryen recipe accepted by `build::has_field_postpass`; enabling that cfg without the postlink pass can regress performance. The DSL's existing compiler invokes this policy and retains responsibility for wasm-pack packaging, memory/import contracts, and worker initialization.

The code was extracted from Zolana's CPU prover after the CPU-only correctness gate. See `IMPORT.md` for provenance. End-to-end performance benchmarks remain with the application circuits in Zolana; extraction itself adds no performance claim.
