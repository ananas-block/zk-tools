package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	native "github.com/consensys/gnark/backend/groth16/bn254"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"
	"zolana/prover/prover/common"
	mergeprover "zolana/prover/prover/merge"
	transfer "zolana/prover/prover/transfer_eddsa_only"
)

const sentinel = "PRIVATE_SENTINEL_894713"
const validSquare = "{\"Secret\":\"3\",\"Public\":\"9\"}"

type squareCircuit struct {
	Secret frontend.Variable
	Public frontend.Variable `gnark:",public"`
}

func (circuit *squareCircuit) Define(api frontend.API) error {
	api.Println(sentinel, circuit.Secret)
	api.AssertIsEqual(api.Mul(circuit.Secret, circuit.Secret), circuit.Public)
	return nil
}

func compileCircuit(t *testing.T, assignment frontend.Circuit) *csbn254.R1CS {
	t.Helper()
	system, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, assignment, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	return system.(*csbn254.R1CS)
}

func squareSystem(t *testing.T) *preparedProver {
	t.Helper()
	system := compileCircuit(t, &squareCircuit{})
	pk, vk, err := groth16.Setup(system)
	if err != nil {
		t.Fatal(err)
	}
	prover := &preparedProver{cs: system, pk: pk.(*native.ProvingKey), vk: vk.(*native.VerifyingKey)}
	if err := prover.validateKeys(); err != nil {
		t.Fatal(err)
	}
	return prover
}

func writeSystem(t *testing.T, prover *preparedProver) [3]string {
	t.Helper()
	dir := t.TempDir()
	var paths [3]string
	for index, writer := range []io.WriterTo{prover.cs, prover.pk, prover.vk} {
		paths[index] = filepath.Join(dir, []string{"circuit.r1cs", "circuit.pk", "circuit.vk"}[index])
		file, err := os.Create(paths[index])
		if err != nil {
			t.Fatal(err)
		}
		_, err = writer.WriteTo(file)
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Fatal("write fixture")
		}
	}
	return paths
}

func TestStrictFlattenedWitness(t *testing.T) {
	system := compileCircuit(t, &squareCircuit{})
	modulus := ecc.BN254.ScalarField().String()
	cases := []string{
		"null", "[]", "{}", "", validSquare + "{}",
		"{\"Secret\":3.9,\"Public\":\"9\"}",
		"{\"Secret\":3,\"Public\":\"9\"}",
		"{\"Secret\":3e0,\"Public\":\"9\"}",
		"{\"Secret\":null,\"Public\":\"9\"}",
		"{\"Secret\":true,\"Public\":\"9\"}",
		"{\"Secret\":[],\"Public\":\"9\"}",
		"{\"Secret\":{},\"Public\":\"9\"}",
		"{\"Secret\":\"3\",\"Secret\":\"3\",\"Public\":\"9\"}",
		"{\"Secret\":\"3\",\"\\u0053ecret\":\"3\",\"Public\":\"9\"}",
		"{\"Secret\":\"3\",\"Public\":\"9\",\"" + sentinel + "\":\"3\"}",
		"{\"Public\":\"9\"}",
		"{\"Secret\":\"3\"}",
		"{\"secret\":\"3\",\"Public\":\"9\"}",
	}
	for _, value := range []string{"3.9", "-1", "-0", "+3", "03", " 3", "3 ", "3e0", "0x3", "", modulus, sentinel, "٣", strings.Repeat("9", 500)} {
		encoded, _ := json.Marshal(value)
		cases = append(cases, "{\"Secret\":"+string(encoded)+",\"Public\":\"9\"}")
	}
	for index, input := range cases {
		_, err := buildWitnessFromJSON(input, system)
		if err != errWitness {
			t.Fatalf("case %d: expected fixed witness error", index)
		}
		if strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "3.9") {
			t.Fatal("secret in error")
		}
	}
	for _, secret := range []string{"0", "3", new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1)).String()} {
		if _, err := buildWitnessFromJSON("{\"Secret\":\""+secret+"\",\"Public\":\"9\"}", system); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSensitiveErrorsAndLogging(t *testing.T) {
	if logger.Logger().GetLevel() != zerolog.Disabled {
		t.Fatal("gnark logger must be disabled at initialization")
	}
	prover := squareSystem(t)
	paths := writeSystem(t, prover)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = writer, writer
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	result, proveErr := proveOnce(paths[0], paths[1], "{\"Secret\":\"894713987654321\",\"Public\":\"9\"}")
	_ = writer.Close()
	logged, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil || len(logged) != 0 {
		t.Fatal("backend wrote sensitive diagnostics")
	}
	if proveErr != errBackend || result.proof != "" {
		t.Fatal("unsatisfied witness was not safely rejected")
	}
	_, panicErr := backendCall(func() (bool, error) { panic(sentinel) })
	if panicErr != errBackend {
		t.Fatal("panic payload escaped")
	}
	_, keyErr := loadPrepared(sentinel, sentinel, sentinel)
	if keyErr != errKey {
		t.Fatal("key path escaped")
	}
	ffiResult := gnark_prepared_load(nil, nil, nil)
	if ffiResult == nil || ffiResult.error == nil || ffiResult.handle != 0 {
		t.Fatal("nil C input was not rejected")
	}
	gnark_free_prepared_result(ffiResult)
}

func TestPreparedLifecycleAndCompatibility(t *testing.T) {
	prover := squareSystem(t)
	paths := writeSystem(t, prover)
	handle, err := loadPrepared(paths[0], paths[1], paths[2])
	if err != nil {
		t.Fatal(err)
	}
	defer releasePrepared(handle)
	if _, err := loadPrepared(paths[0], paths[1], paths[2]); err != errCapacity {
		t.Fatal("handle capacity is not bounded")
	}
	legacy, err := proveOnce(paths[0], paths[1], validSquare)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := verifyOnce(paths[0], paths[2], legacy.proof, legacy.publicInputs); err != nil || !valid {
		t.Fatal("legacy proof did not verify")
	}
	for _, path := range paths {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 3; index++ {
		result, err := provePrepared(handle, validSquare, false)
		if err != nil {
			t.Fatal("warm prove reopened an asset", err)
		}
		if result.shapeKnown {
			t.Fatal("generic circuit must report unknown shape")
		}
		if valid, err := verifyPrepared(handle, result.proof, result.publicInputs); err != nil || !valid {
			t.Fatal("warm verify reopened an asset")
		}
		var proof common.Proof
		if err := json.Unmarshal([]byte(result.proofJSON), &proof); err != nil {
			t.Fatal("noncanonical proof JSON")
		}
		var binary bytes.Buffer
		_, _ = proof.Proof.WriteTo(&binary)
		if hex.EncodeToString(binary.Bytes()) != result.proof {
			t.Fatal("JSON and binary proofs differ")
		}
		if _, err := verifyPrepared(handle, result.proof+"00", result.publicInputs); err != errProof {
			t.Fatal("trailing proof bytes accepted")
		}
		full, _ := buildWitnessFromJSON("{\"Secret\":\"3\",\"Public\":\"8\"}", prover.cs)
		public, _ := full.Public()
		binaryPublic, _ := public.MarshalBinary()
		if valid, err := verifyPrepared(handle, result.proof, hex.EncodeToString(binaryPublic)); err != nil || valid {
			t.Fatal("invalid public input was not rejected")
		}
	}
	releasePrepared(handle)
	releasePrepared(handle)
	if _, err := provePrepared(handle, validSquare, false); err != errHandle {
		t.Fatal("released handle accepted")
	}
	if len(prepared) != 0 {
		t.Fatal("prepared handles leaked")
	}
}

func TestConcurrentReleaseDoesNotRace(t *testing.T) {
	paths := writeSystem(t, squareSystem(t))
	handle, err := loadPrepared(paths[0], paths[1], paths[2])
	if err != nil {
		t.Fatal(err)
	}
	defer releasePrepared(handle)
	var group sync.WaitGroup
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := provePrepared(handle, validSquare, false)
			if err == errHandle {
				return
			}
			if err != nil {
				t.Error("concurrent prove failed")
				return
			}
			valid, err := verifyPrepared(handle, result.proof, result.publicInputs)
			if err != errHandle && (err != nil || !valid) {
				t.Error("concurrent verify failed")
			}
		}()
	}
	group.Add(1)
	go func() { defer group.Done(); releasePrepared(handle) }()
	group.Wait()
}

func TestInvalidKeysRejected(t *testing.T) {
	prover := squareSystem(t)
	paths := writeSystem(t, prover)
	validPK, err := os.ReadFile(paths[1])
	if err != nil {
		t.Fatal(err)
	}
	invalidDomain := append([]byte{}, validPK...)
	invalidDomain[0] = 255
	if err := os.WriteFile(paths[1], invalidDomain, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPrepared(paths[0], paths[1], paths[2]); err != errKey {
		t.Fatal("invalid FFT domain was not rejected before precomputation")
	}
	prover.pk.G1.Alpha.X.SetOne()
	prover.pk.G1.Alpha.Y.SetOne()
	var invalidCurve bytes.Buffer
	if _, err := prover.pk.WriteRawTo(&invalidCurve); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[1], invalidCurve.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	check := &preparedProver{cs: prover.cs, pk: new(native.ProvingKey)}
	if err := readProvingKey(paths[1], check); err != errKey {
		t.Fatal("proving key point validation was skipped")
	}
	other := squareSystem(t)
	prover.vk = other.vk
	if err := prover.validateKeys(); err != errKey {
		t.Fatal("unrelated verifying key accepted")
	}
	prover.vk = nil
	prover.pk.InfinityA = nil
	if err := prover.validateKeys(); err != errKey {
		t.Fatal("mismatched key shape accepted")
	}
	if err := os.WriteFile(paths[1], []byte(sentinel), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPrepared(paths[0], paths[1], paths[2]); err != errKey {
		t.Fatal("corrupt proving key accepted")
	}
	if len(prepared) != 0 {
		t.Fatal("failed load leaked a handle")
	}
}

func fixtureRequest(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/transfer-2x3.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestStructuredRequestRejectsAdversarialInput(t *testing.T) {
	request := fixtureRequest(t)
	cases := []string{
		"{", "null", "[]",
		strings.Replace(request, "\"nInputs\":2", "\"nInputs\":3.9", 1),
		strings.Replace(request, "\"nInputs\":2", "\"nInputs\":\"2\"", 1),
		strings.Replace(request, "\"nInputs\":2", "\"nInputs\":2,\"nInputs\":2", 1),
		strings.Replace(request, "\"nInputs\":2", "\"NInputs\":2", 1),
		strings.Replace(request, "\"nInputs\":2", "\""+sentinel+"\":2", 1),
		strings.Replace(request, "\"domain\":\"0x3\"", "\"domain\":\""+sentinel+"\"", 1),
		strings.Replace(request, "\"domain\":\"0x3\"", "\"domain\":3.9", 1),
		strings.Replace(request, "\"domain\":\"0x3\"", "\"domain\":\"-1\"", 1),
		strings.Replace(request, "\"domain\":\"0x3\"", "\"domain\":\"0x"+ecc.BN254.ScalarField().Text(16)+"\"", 1),
		strings.Replace(request, "\"domain\":\"0x3\"", "\"domain\":\"0x3\",\"domain\":\"0x3\"", 1),
	}
	for index, input := range cases {
		if input == request {
			t.Fatalf("case %d did not mutate fixture", index)
		}
		_, err := requestAssignment(input)
		if err != errRequest && err != errUnsupported {
			t.Fatalf("case %d: expected fixed request error", index)
		}
	}
	for _, kind := range []string{"transfer-p256-ring", "custom-ring", "address-append", sentinel} {
		input := strings.Replace(request, "transfer-confidential", kind, 1)
		if _, err := requestAssignment(input); err != errUnsupported {
			t.Fatal("unsupported rail did not fail closed")
		}
	}
	system := compileCircuit(t, &squareCircuit{})
	if _, err := buildRequestWitness(request, system); err != errShape {
		t.Fatal("mismatched circuit layout accepted")
	}
}

func compareWitnesses(t *testing.T, system *csbn254.R1CS, request string, assignment frontend.Circuit, flattened string) {
	t.Helper()
	structured, err := buildRequestWitness(request, system)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(structured.Vector(), reference.Vector()) {
		t.Fatal("structured assignment changed protocol semantics")
	}
	if flattened != "" {
		flat, err := buildWitnessFromJSON(flattened, system)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(flat.Vector(), structured.Vector()) {
			t.Fatal("structured and flattened witness vectors differ")
		}
		flatPublic, _ := flat.Public()
		structuredPublic, _ := structured.Public()
		if !reflect.DeepEqual(flatPublic.Vector().(fr.Vector), structuredPublic.Vector().(fr.Vector)) {
			t.Fatal("public input vectors differ")
		}
	}
}

func proveFixture(t *testing.T, system *csbn254.R1CS, request string, inputs, outputs uint32) {
	t.Helper()
	pk, vk, err := groth16.Setup(system)
	if err != nil {
		t.Fatal(err)
	}
	prover := &preparedProver{cs: system, pk: pk.(*native.ProvingKey), vk: vk.(*native.VerifyingKey)}
	if err := prover.validateKeys(); err != nil {
		t.Fatal(err)
	}
	full, err := buildRequestWitness(request, system)
	if err != nil {
		t.Fatal(err)
	}
	result, err := prover.prove(full)
	if err != nil {
		t.Fatal(err)
	}
	if !result.shapeKnown || result.inputs != inputs || result.outputs != outputs {
		for _, name := range system.Secret {
			if strings.Contains(name, "OutputHash") || strings.Contains(name, "Nullifiers_0") {
				t.Log("fixture shape signal", name)
			}
		}
		t.Log("fixture public signal names", system.Public)
		t.Fatalf("incorrect shape: %d %d %v", result.inputs, result.outputs, result.shapeKnown)
	}
	if valid, err := prover.verify(result.proof, result.publicInputs); err != nil || !valid {
		t.Fatal("native fixture proof failed verification")
	}
	var canonical common.Proof
	if err := json.Unmarshal([]byte(result.proofJSON), &canonical); err != nil {
		t.Fatal(err)
	}
	public, _ := full.Public()
	if err := groth16.Verify(canonical.Proof, vk, public); err != nil {
		t.Fatal("web proof JSON failed native verification")
	}
}

func TestTransferFixture(t *testing.T) {
	request := fixtureRequest(t)
	assignment, err := requestAssignment(request)
	if err != nil {
		t.Fatal(err)
	}
	system := compileCircuit(t, assignment)
	assignment, err = requestAssignment(request)
	if err != nil {
		t.Fatal(err)
	}
	compareWitnesses(t, system, request, assignment, flattenAssignment(t, assignment))
	if !testing.Short() {
		proveFixture(t, system, request, 2, 3)
	}
}

func TestStagedTransferKeys(t *testing.T) {
	dir := os.Getenv("ZOLANA_TEST_KEYS")
	if dir == "" {
		t.Skip("set ZOLANA_TEST_KEYS for pinned deployed key interoperability")
	}
	prefix := filepath.Join(dir, "transfer_confidential_2_3")
	handle, err := loadPrepared(prefix+".r1cs", prefix+".pk", prefix+".vk")
	if err != nil {
		t.Fatal(err)
	}
	defer releasePrepared(handle)
	request := fixtureRequest(t)
	assignment, err := requestAssignment(request)
	if err != nil {
		t.Fatal("request decoding", err)
	}
	publicNames, secretNames, err := assignmentNames(assignment)
	if err != nil {
		t.Fatal("request schema", err)
	}
	if _, err := buildRequestWitness(request, prepared[handle].cs); err != nil {
		t.Logf("assignment public=%d secret=%d; circuit public=%d secret=%d",
			len(publicNames), len(secretNames), len(prepared[handle].cs.Public)-1, len(prepared[handle].cs.Secret))
		for index, name := range secretNames {
			if index < len(prepared[handle].cs.Secret) && name != prepared[handle].cs.Secret[index] {
				t.Logf("first fixture schema mismatch at index %d: assignment=%s circuit=%s", index, name, prepared[handle].cs.Secret[index])
			}
		}
		t.Fatal("request witness", err)
	}
	flattened, err := os.ReadFile("testdata/witness-2x3.json")
	if err != nil {
		t.Fatal(err)
	}
	compareWitnesses(t, prepared[handle].cs, request, assignment, string(flattened))
	legacy, err := proveOnce(prefix+".r1cs", prefix+".pk", string(flattened))
	if err != nil {
		t.Fatal("canonical staged legacy prove", err)
	}
	if valid, err := verifyOnce(prefix+".r1cs", prefix+".vk", legacy.proof, legacy.publicInputs); err != nil || !valid {
		t.Fatal("canonical staged legacy verify", err)
	}
	stagedFlat, err := os.ReadFile(filepath.Join(dir, "witness-2x3.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proveOnce(prefix+".r1cs", prefix+".pk", string(stagedFlat)); err != nil {
		t.Fatal("staged legacy fixture rejected", err)
	}
	if !bytes.Equal(stagedFlat, flattened) {
		t.Fatal("staged flattened fixture differs from canonical testdata")
	}
	for index := 0; index < 2; index++ {
		result, err := provePrepared(handle, request, true)
		if err != nil || !result.shapeKnown || result.inputs != 2 || result.outputs != 3 {
			t.Fatal("staged structured proof failed", err)
		}
		if valid, err := verifyPrepared(handle, result.proof, result.publicInputs); err != nil || !valid {
			t.Fatal("staged verification failed")
		}
		t.Logf("witness_ms=%d prove_ms=%d", result.witnessMS, result.proveMS)
	}
}

func flattenAssignment(t *testing.T, assignment frontend.Circuit) string {
	t.Helper()
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	publicNames, secretNames, err := assignmentNames(assignment)
	if err != nil {
		t.Fatal(err)
	}
	names := append(publicNames, secretNames...)
	values := full.Vector().(fr.Vector)
	flattened := make(map[string]string, len(names))
	for index, name := range names {
		var number big.Int
		values[index].BigInt(&number)
		flattened[name] = number.String()
	}
	encoded, err := json.Marshal(flattened)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestRequiredRequestFields(t *testing.T) {
	request := fixtureRequest(t)
	var object map[string]any
	if err := json.Unmarshal([]byte(request), &object); err != nil {
		t.Fatal(err)
	}
	if _, err := requestAssignment(request); err != nil {
		t.Fatal(err)
	}
	var tested int
	var inspect func(map[string]any, reflect.Type)
	inspect = func(current map[string]any, expected reflect.Type) {
		for index := 0; index < expected.NumField(); index++ {
			field := expected.Field(index)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			value, exists := current[name]
			if !exists {
				continue
			}
			delete(current, name)
			encoded, _ := json.Marshal(object)
			if _, err := requestAssignment(string(encoded)); err != errRequest && err != errUnsupported {
				t.Fatal("missing required field was accepted")
			}
			tested++
			current[name] = value
			switch field.Type.Kind() {
			case reflect.Struct:
				inspect(value.(map[string]any), field.Type)
			case reflect.Slice:
				if field.Type.Elem().Kind() == reflect.Struct {
					for _, item := range value.([]any) {
						inspect(item.(map[string]any), field.Type.Elem())
					}
				}
			}
		}
	}
	inspect(object, reflect.TypeOf(transfer.TransferParametersJSON{}))
	if tested < 80 {
		t.Fatal("insufficient missing-field coverage")
	}
}

func TestMergeFixture(t *testing.T) {
	assignment := buildWitness(t, true)
	asInteger := func(value frontend.Variable) *big.Int { return value.(*big.Int) }
	asIntegers := func(values []frontend.Variable) []*big.Int {
		result := make([]*big.Int, len(values))
		for index, value := range values {
			result[index] = asInteger(value)
		}
		return result
	}
	params := mergeprover.MergeParameters{
		CircuitType:         common.MergeCircuitType,
		Asset:               asInteger(assignment.Asset),
		OwnerPkHash:         asInteger(assignment.OwnerPkHash),
		UserNullifierPk:     asInteger(assignment.UserNullifierPk),
		UserNullifierSecret: asInteger(assignment.UserNullifierSecret),
		ExternalDataHash:    asInteger(assignment.ExternalDataHash),
		PrivateTxHash:       asInteger(assignment.PrivateTxHash),
		PublicInputHash:     asInteger(assignment.PublicInputHash),
		AllowDummyInputs:    asInteger(assignment.AllowDummyInputs),
		OutputTreeID:        asInteger(assignment.OutputTreeID),
		Output:              mergeprover.OutputParams{RingDataHash: asInteger(assignment.Output.RingDataHash), Hash: asInteger(assignment.OutputHash)},
	}
	for _, slot := range assignment.TreeSlots {
		params.TreeSlots = append(params.TreeSlots, common.TreeSlotParams{
			ID: asInteger(slot.ID), UtxoRoot: asInteger(slot.UtxoRoot), NullifierRoot: asInteger(slot.NullifierRoot),
		})
	}
	for index, input := range assignment.Inputs {
		params.Inputs = append(params.Inputs, mergeprover.InputParams{
			Domain: asInteger(input.Domain), Amount: asInteger(input.Amount), Blinding: asInteger(input.Blinding),
			RingDataHash: asInteger(input.RingDataHash), StatePathElements: asIntegers(input.StatePathElements),
			StatePathIndex: asInteger(input.StatePathIndex), NullifierLowValue: asInteger(input.NullifierLowValue),
			NullifierNextValue: asInteger(input.NullifierNextValue), NullifierLowPathElements: asIntegers(input.NullifierLowPathElements),
			NullifierLowPathIndex: asInteger(input.NullifierLowPathIndex), TreeSlot: asInteger(input.TreeSlot),
			Nullifier: asInteger(assignment.Nullifiers[index]),
		})
	}
	encoded, err := json.Marshal(&params)
	if err != nil {
		t.Fatal(err)
	}
	system := compileCircuit(t, assignment)
	assignment = buildWitness(t, true)
	compareWitnesses(t, system, string(encoded), assignment, "")
	if !testing.Short() {
		proveFixture(t, system, string(encoded), 8, 1)
	}
}

func writeKeyFile(t *testing.T, path string, header [3]uint32, prover *preparedProver, trailer []byte) {
	t.Helper()
	var container bytes.Buffer
	for _, field := range header {
		_ = binary.Write(&container, binary.BigEndian, field)
	}
	for _, section := range []io.WriterTo{prover.pk, prover.vk, prover.cs} {
		if _, err := section.WriteTo(&container); err != nil {
			t.Fatal(err)
		}
	}
	container.Write(trailer)
	if err := os.WriteFile(path, container.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestKeyFileContainer(t *testing.T) {
	if testing.Short() {
		t.Skip("groth16 setup of the transfer fixture circuit")
	}
	request := fixtureRequest(t)
	assignment, err := requestAssignment(request)
	if err != nil {
		t.Fatal(err)
	}
	system := compileCircuit(t, assignment)
	pk, vk, err := groth16.Setup(system)
	if err != nil {
		t.Fatal(err)
	}
	prover := &preparedProver{cs: system, pk: pk.(*native.ProvingKey), vk: vk.(*native.VerifyingKey)}
	path := filepath.Join(t.TempDir(), "transfer_confidential_2_3.key")

	writeKeyFile(t, path, [3]uint32{2, 3, 0}, prover, nil)
	handle, err := loadPreparedKey(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := provePrepared(handle, request, true)
	if err != nil || !result.shapeKnown || result.inputs != 2 || result.outputs != 3 {
		t.Fatal("container proof failed", err)
	}
	if valid, err := verifyPrepared(handle, result.proof, result.publicInputs); err != nil || !valid {
		t.Fatal("container proof did not verify")
	}
	releasePrepared(handle)

	for name, tamper := range map[string]struct {
		header  [3]uint32
		trailer []byte
	}{
		"p256 rail":     {[3]uint32{2, 3, 1}, nil},
		"header shape":  {[3]uint32{1, 3, 0}, nil},
		"trailing byte": {[3]uint32{2, 3, 0}, []byte{0}},
	} {
		writeKeyFile(t, path, tamper.header, prover, tamper.trailer)
		if _, err := loadPreparedKey(path); err != errKey {
			t.Fatalf("%s: container accepted", name)
		}
	}
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, valid[:len(valid)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPreparedKey(path); err != errKey {
		t.Fatal("truncated container accepted")
	}
	if len(prepared) != 0 {
		t.Fatal("rejected containers leaked a handle")
	}
}

func TestStagedKeyFile(t *testing.T) {
	path := os.Getenv("ZOLANA_TEST_KEY_FILE")
	if path == "" {
		t.Skip("set ZOLANA_TEST_KEY_FILE to a pinned transfer_confidential_2_3.key")
	}
	handle, err := loadPreparedKey(path)
	if err != nil {
		t.Fatal(err)
	}
	defer releasePrepared(handle)
	result, err := provePrepared(handle, fixtureRequest(t), true)
	if err != nil || result.inputs != 2 || result.outputs != 3 {
		t.Fatal("staged key file proof failed", err)
	}
	if valid, err := verifyPrepared(handle, result.proof, result.publicInputs); err != nil || !valid {
		t.Fatal("staged key file proof did not verify")
	}
}
