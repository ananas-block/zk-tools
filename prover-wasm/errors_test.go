package main

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestErrorResultRedactsWitness(t *testing.T) {
	for _, failure := range []error{nil, errors.New("review-private-sentinel")} {
		encoded, err := json.Marshal(errorResult(failure))
		if err != nil || string(encoded) != `{"code":"wasm_backend_error","error":"Prover operation failed"}` {
			t.Fatal("backend error must contain only the stable code and message")
		}
	}
}
