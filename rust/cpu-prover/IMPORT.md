# Import provenance

The engine was extracted from `helius-labs/zolana`, branch `wasm-aeglos`, based on commit `2d9399e518a40e186b72a2cb038e5bfac4778793` plus its uncommitted CPU-only correctness follow-up. Original files at the extraction boundary are hashed in `import-source.json`.

Arithmetic, GLV, pairing verification, FFT, MSM and proof assembly were moved without selecting new algorithms. Generic canonical/zkey handling, matrix evaluation and randomness were separated from circuit-specific labels and Solana encodings. The `zolana_wasm_opt` cfg became `zk_tools_wasm_opt`, with the bounded postlink policy owned here. The prepared API validates matrix/key dimensions and the constant-one assignment. Frontend code remains responsible for witness synthesis, labels, public-input layout and application proof formatting.

New security and WASM tests accompany the extraction. The committed product key and reference proofs are intentionally insecure test fixtures. No WebGPU source is part of this crate; the separate experiment is maintained in Aeglos.

Imported code remains Apache-2.0.
