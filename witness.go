package main

import (
	"github.com/consensys/gnark/constraint"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
)

func witnessNames(system constraint.ConstraintSystem) ([]string, []string, error) {
	circuit, ok := system.(*csbn254.R1CS)
	if !ok || len(circuit.Public) == 0 || circuit.Public[0] != "1" {
		return nil, nil, errKey
	}
	seen := make(map[string]bool, len(circuit.Public)+len(circuit.Secret))
	for _, names := range [][]string{circuit.Public, circuit.Secret} {
		for _, name := range names {
			if name == "" || seen[name] {
				return nil, nil, errKey
			}
			seen[name] = true
		}
	}
	return circuit.Public[1:], circuit.Secret, nil
}
