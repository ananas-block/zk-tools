package main

import (
	"encoding/json"
	"io"
	"math/big"
	"strings"

	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// buildWitnessFromJSON reads a flattened witness, circuit variable names to
// canonical decimal strings, as the golden fixtures store it.
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
