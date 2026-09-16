package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    char *proof;
    char *public_inputs;
    char *proof_json;
    uint32_t inputs;
    uint32_t outputs;
    uint32_t shape_known;
    uint64_t witness_ms;
    uint64_t prove_ms;
    uint64_t verify_ms;
    char *error;
} C_Groth16ProofResult;

typedef struct {
    uint64_t handle;
    char *error;
} C_PreparedResult;
*/
import "C"

import (
	"os"
	"runtime"
	"unsafe"
)

func cError(err error) *C.char {
	if err == nil {
		return nil
	}
	switch err {
	case errKey, errWitness, errRequest, errUnsupported, errShape, errProof, errInvalidProof, errHandle, errCapacity:
		return C.CString(err.Error())
	default:
		return C.CString(errBackend.Error())
	}
}

func exportProof(result proofResult, err error) *C.C_Groth16ProofResult {
	output := (*C.C_Groth16ProofResult)(C.calloc(1, C.size_t(unsafe.Sizeof(C.C_Groth16ProofResult{}))))
	if output == nil {
		return nil
	}
	if err != nil {
		output.error = cError(err)
		return output
	}
	output.proof = C.CString(result.proof)
	output.public_inputs = C.CString(result.publicInputs)
	output.proof_json = C.CString(result.proofJSON)
	output.inputs = C.uint32_t(result.inputs)
	output.outputs = C.uint32_t(result.outputs)
	if result.shapeKnown {
		output.shape_known = 1
	}
	output.witness_ms = C.uint64_t(result.witnessMS)
	output.prove_ms = C.uint64_t(result.proveMS)
	output.verify_ms = C.uint64_t(result.verifyMS)
	return output
}

func recoverProof(output **C.C_Groth16ProofResult) {
	if recover() != nil {
		*output = exportProof(proofResult{}, errBackend)
	}
}

func recoverError(output **C.char) {
	if recover() != nil {
		*output = cError(errBackend)
	}
}

//export gnark_init
func gnark_init() (status C.int) {
	defer func() {
		if recover() != nil {
			status = -1
		}
	}()
	if runtime.GOOS == "ios" || runtime.GOOS == "darwin" {
		_ = os.Setenv("GODEBUG", "asyncpreemptoff=1")
	}
	return 0
}

//export gnark_prepared_load
func gnark_prepared_load(r1csPath, pkPath, vkPath *C.char) (output *C.C_PreparedResult) {
	output = (*C.C_PreparedResult)(C.calloc(1, C.size_t(unsafe.Sizeof(C.C_PreparedResult{}))))
	if output == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			output.error = cError(errBackend)
		}
	}()
	handle, err := loadPrepared(C.GoString(r1csPath), C.GoString(pkPath), C.GoString(vkPath))
	output.handle = C.uint64_t(handle)
	output.error = cError(err)
	return output
}

//export gnark_prepared_prove
func gnark_prepared_prove(handle C.uint64_t, input *C.char) (output *C.C_Groth16ProofResult) {
	defer recoverProof(&output)
	result, err := provePrepared(uint64(handle), C.GoString(input), false)
	return exportProof(result, err)
}

//export gnark_prepared_prove_request
func gnark_prepared_prove_request(handle C.uint64_t, input *C.char) (output *C.C_Groth16ProofResult) {
	defer recoverProof(&output)
	result, err := provePrepared(uint64(handle), C.GoString(input), true)
	return exportProof(result, err)
}

//export gnark_prepared_verify
func gnark_prepared_verify(handle C.uint64_t, proof, publicInputs *C.char) (output *C.char) {
	defer recoverError(&output)
	valid, err := verifyPrepared(uint64(handle), C.GoString(proof), C.GoString(publicInputs))
	if err == nil && !valid {
		err = errInvalidProof
	}
	return cError(err)
}

//export gnark_prepared_release
func gnark_prepared_release(handle C.uint64_t) {
	defer func() { _ = recover() }()
	releasePrepared(uint64(handle))
}

//export gnark_free_prepared_result
func gnark_free_prepared_result(result *C.C_PreparedResult) {
	if result != nil {
		C.free(unsafe.Pointer(result.error))
		C.free(unsafe.Pointer(result))
	}
}

//export gnark_groth16_prove
func gnark_groth16_prove(r1csPath, pkPath, input *C.char) (output *C.C_Groth16ProofResult) {
	defer recoverProof(&output)
	result, err := proveOnce(C.GoString(r1csPath), C.GoString(pkPath), C.GoString(input))
	return exportProof(result, err)
}

//export gnark_groth16_verify
func gnark_groth16_verify(r1csPath, vkPath, proof, publicInputs *C.char) (output *C.char) {
	defer recoverError(&output)
	valid, err := verifyOnce(C.GoString(r1csPath), C.GoString(vkPath), C.GoString(proof), C.GoString(publicInputs))
	if err == nil && !valid {
		err = errInvalidProof
	}
	return cError(err)
}

//export gnark_free_proof_result
func gnark_free_proof_result(result *C.C_Groth16ProofResult) {
	if result != nil {
		C.free(unsafe.Pointer(result.proof))
		C.free(unsafe.Pointer(result.public_inputs))
		C.free(unsafe.Pointer(result.proof_json))
		C.free(unsafe.Pointer(result.error))
		C.free(unsafe.Pointer(result))
	}
}

//export gnark_free_string
func gnark_free_string(value *C.char) {
	C.free(unsafe.Pointer(value))
}

func main() {}
