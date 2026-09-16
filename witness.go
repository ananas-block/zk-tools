package main

import (
	"encoding/json"
	"io"
	"math/big"
	"strings"

	"github.com/consensys/gnark/backend/witness"
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

func canonicalDecimal(value string, modulus *big.Int) (*big.Int, bool) {
	if len(value) == 0 || len(value) > len(modulus.String()) || (len(value) > 1 && value[0] == '0') {
		return nil, false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return nil, false
		}
	}
	number, ok := new(big.Int).SetString(value, 10)
	return number, ok && number.Cmp(modulus) < 0
}

func buildWitnessFromJSON(input string, system constraint.ConstraintSystem) (witness.Witness, error) {
	if len(input) > maxJSONBytes {
		return nil, errWitness
	}
	publicNames, secretNames, err := witnessNames(system)
	if err != nil {
		return nil, err
	}
	expected := make(map[string]bool, len(publicNames)+len(secretNames))
	for _, names := range [][]string{publicNames, secretNames} {
		for _, name := range names {
			expected[name] = true
		}
	}
	decoder := json.NewDecoder(strings.NewReader(input))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errWitness
	}
	valuesByName := make(map[string]*big.Int, len(expected))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, errWitness
		}
		name, ok := token.(string)
		if !ok || !expected[name] || valuesByName[name] != nil {
			return nil, errWitness
		}
		var encoded json.RawMessage
		if err := decoder.Decode(&encoded); err != nil || len(encoded) == 0 || encoded[0] != '"' {
			return nil, errWitness
		}
		var value string
		if err := json.Unmarshal(encoded, &value); err != nil {
			return nil, errWitness
		}
		number, ok := canonicalDecimal(value, system.Field())
		if !ok {
			return nil, errWitness
		}
		valuesByName[name] = number
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errWitness
	}
	if _, err := decoder.Token(); err != io.EOF || len(valuesByName) != len(expected) {
		return nil, errWitness
	}
	values := make(chan any, len(expected))
	for _, names := range [][]string{publicNames, secretNames} {
		for _, name := range names {
			values <- valuesByName[name]
		}
	}
	close(values)
	full, err := witness.New(system.Field())
	if err != nil {
		return nil, errWitness
	}
	if err := full.Fill(len(publicNames), len(secretNames), values); err != nil {
		return nil, errWitness
	}
	return full, nil
}
