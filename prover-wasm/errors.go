package main

func errorResult(_ error) any {
	return map[string]any{"code": "wasm_backend_error", "error": "Prover operation failed"}
}
