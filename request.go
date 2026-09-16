package main

import (
	"encoding/json"
	"io"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
	"zolana/prover/prover/common"
	merge "zolana/prover/prover/merge"
	transfer "zolana/prover/prover/transfer_eddsa_only"
)

type requestParameters interface {
	ValidateShape() error
	CreateWitness() (frontend.Circuit, error)
}

func optionalRequestField(expected reflect.Type, name string, rail common.CircuitType) bool {
	switch expected {
	case reflect.TypeOf(transfer.TransferParametersJSON{}):
		return (name == "ringProgramId" && rail == common.TransferConfidentialCircuitType) ||
			(name == "publishedOutputOwnerPkHashes" && rail == common.TransferRingAuthorityCircuitType)
	case reflect.TypeOf(transfer.InputParamsJSON{}):
		return name == "isDummy"
	case reflect.TypeOf(transfer.OutputParamsJSON{}):
		return name == "isDummy" ||
			(name == "ownerPkHash" && rail == common.TransferConfidentialCircuitType) ||
			((name == "ownerPkHash" || name == "nullifierPk") && rail == common.TransferRingAuthorityCircuitType)
	case reflect.TypeOf(merge.MergeParametersJSON{}):
		return (name == "ringProgramId" || name == "outputRingDataHash") && rail == common.MergeCircuitType
	}
	return false
}

func validateJSONShape(decoder *json.Decoder, expected reflect.Type, depth int, rail common.CircuitType) error {
	if depth > 32 {
		return errRequest
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return errRequest
	}
	switch expected.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return errRequest
		}
		fields := make(map[string]reflect.Type, expected.NumField())
		for index := 0; index < expected.NumField(); index++ {
			field := expected.Field(index)
			fields[strings.Split(field.Tag.Get("json"), ",")[0]] = field.Type
		}
		seen := make(map[string]bool, len(fields))
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return errRequest
			}
			name, ok := token.(string)
			field, exists := fields[name]
			if !ok || !exists || seen[name] {
				return errRequest
			}
			seen[name] = true
			if err := validateJSONShape(decoder, field, depth+1, rail); err != nil {
				return err
			}
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
			return errRequest
		}
		for name := range fields {
			if !seen[name] && !optionalRequestField(expected, name, rail) {
				return errRequest
			}
		}
	case reflect.Slice:
		if token != json.Delim('[') {
			return errRequest
		}
		for decoder.More() {
			if err := validateJSONShape(decoder, expected.Elem(), depth+1, rail); err != nil {
				return err
			}
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			return errRequest
		}
	case reflect.String:
		value, ok := token.(string)
		if !ok || len(value) == 0 || len(value) > 256 {
			return errRequest
		}
	case reflect.Uint32:
		number, ok := token.(json.Number)
		if !ok {
			return errRequest
		}
		if _, err := strconv.ParseUint(number.String(), 10, 32); err != nil {
			return errRequest
		}
	default:
		return errRequest
	}
	return nil
}

func decodeRequest(input string, target any, rail common.CircuitType) error {
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.UseNumber()
	if err := validateJSONShape(decoder, reflect.TypeOf(target).Elem(), 0, rail); err != nil {
		return errRequest
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errRequest
	}
	if err := json.Unmarshal([]byte(input), target); err != nil {
		return errRequest
	}
	return nil
}

func validateParameterFields(value reflect.Value) bool {
	if value.Type() == reflect.TypeOf((*big.Int)(nil)) {
		if value.IsNil() {
			return true
		}
		number := value.Interface().(*big.Int)
		return number.Sign() >= 0 && number.Cmp(ecc.BN254.ScalarField()) < 0
	}
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		return !value.IsNil() && validateParameterFields(value.Elem())
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if !validateParameterFields(value.Field(index)) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if !validateParameterFields(value.Index(index)) {
				return false
			}
		}
	}
	return true
}

func requestAssignment(input string) (frontend.Circuit, error) {
	if len(input) > maxJSONBytes {
		return nil, errRequest
	}
	var envelope struct {
		CircuitType common.CircuitType `json:"circuitType"`
	}
	if err := json.Unmarshal([]byte(input), &envelope); err != nil {
		return nil, errRequest
	}
	var params requestParameters
	switch envelope.CircuitType {
	case common.TransferConfidentialCircuitType, common.TransferRingCircuitType, common.TransferRingAuthorityCircuitType:
		var encoded transfer.TransferParametersJSON
		if err := decodeRequest(input, &encoded, envelope.CircuitType); err != nil {
			return nil, err
		}
		assignment := new(transfer.TransferParameters)
		if err := assignment.UpdateWithJSON(encoded); err != nil {
			return nil, errRequest
		}
		params = assignment
	case common.MergeCircuitType, common.MergeRingCircuitType:
		var encoded merge.MergeParametersJSON
		if err := decodeRequest(input, &encoded, envelope.CircuitType); err != nil {
			return nil, err
		}
		assignment := new(merge.MergeParameters)
		if err := assignment.UpdateWithJSON(encoded); err != nil {
			return nil, errRequest
		}
		params = assignment
	default:
		return nil, errUnsupported
	}
	if !validateParameterFields(reflect.ValueOf(params)) {
		return nil, errRequest
	}
	if err := params.ValidateShape(); err != nil {
		return nil, errRequest
	}
	assignment, err := params.CreateWitness()
	if err != nil {
		return nil, errRequest
	}
	return assignment, nil
}

func assignmentNames(assignment frontend.Circuit) ([]string, []string, error) {
	var publicNames, secretNames []string
	_, err := schema.Walk(ecc.BN254.ScalarField(), assignment, reflect.TypeOf((*frontend.Variable)(nil)).Elem(),
		func(leaf schema.LeafInfo, value reflect.Value) error {
			if leaf.Visibility == schema.Public {
				publicNames = append(publicNames, leaf.FullName())
			} else if leaf.Visibility == schema.Secret {
				secretNames = append(secretNames, leaf.FullName())
			} else {
				return errShape
			}
			return nil
		})
	if err != nil {
		return nil, nil, errShape
	}
	return publicNames, secretNames, nil
}

func buildRequestWitness(input string, circuit *csbn254.R1CS) (witness.Witness, error) {
	assignment, err := requestAssignment(input)
	if err != nil {
		return nil, err
	}
	publicNames, secretNames, err := assignmentNames(assignment)
	if err != nil {
		return nil, err
	}
	expectedPublic, expectedSecret, err := witnessNames(circuit)
	if err != nil {
		return nil, err
	}
	if !matchingWitnessNames(publicNames, expectedPublic) || !matchingWitnessNames(secretNames, expectedSecret) {
		return nil, errShape
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, errRequest
	}
	return full, nil
}

func matchingWitnessNames(assignment, circuit []string) bool {
	if len(assignment) != len(circuit) {
		return false
	}
	for index, name := range circuit {
		parts := strings.Split(name, "_")
		for index, part := range parts {
			switch part {
			case "ZoneDataHash":
				parts[index] = "RingDataHash"
			case "ZoneProgramID":
				parts[index] = "RingProgramID"
			case "OutputZoneDataHash":
				parts[index] = "OutputRingDataHash"
			}
		}
		if assignment[index] != strings.Join(parts, "_") {
			return false
		}
	}
	return true
}

func circuitShape(circuit *csbn254.R1CS) (uint32, uint32, bool) {
	names := make(map[string]bool, len(circuit.Public)+len(circuit.Secret))
	for _, group := range [][]string{circuit.Public, circuit.Secret} {
		for _, name := range group {
			names[name] = true
		}
	}
	count := func(prefix string) uint32 {
		var length uint32
		for names[prefix+strconv.FormatUint(uint64(length), 10)] {
			length++
		}
		return length
	}
	if names["Public_PublicInputHash"] {
		inputs, outputs := count("Public_Nullifiers_"), count("Public_OutputHashes_")
		return inputs, outputs, inputs > 0 && outputs > 0
	}
	if names["PublicInputHash"] && names["OutputHash"] {
		inputs := count("Nullifiers_")
		return inputs, 1, inputs > 0
	}
	return 0, 0, false
}
