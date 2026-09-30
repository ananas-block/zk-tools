package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16"
	native "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/logger"
	_ "github.com/consensys/gnark/std/rangecheck"
	"zolana/prover/prover/common"
)

var (
	errBackend      = errors.New("gnark operation failed")
	errKey          = errors.New("invalid proving system")
	errWitness      = errors.New("invalid witness")
	errRequest      = errors.New("invalid proof request")
	errUnsupported  = errors.New("unsupported proof request")
	errShape        = errors.New("request does not match proving system")
	errProof        = errors.New("invalid proof encoding")
	errInvalidProof = errors.New("invalid proof")
	errHandle       = errors.New("invalid prepared handle")
	errCapacity     = errors.New("prepared prover capacity reached")
	backendMu       sync.Mutex
	prepared        = make(map[uint64]*preparedProver)
	nextHandle      uint64
)

const maxPrepared = 1
const maxJSONBytes = 8 << 20

type proofResult struct {
	proof        string
	publicInputs string
	proofJSON    string
	inputs       uint32
	outputs      uint32
	shapeKnown   bool
	witnessMS    uint64
	proveMS      uint64
	verifyMS     uint64
}

type preparedProver struct {
	cs *csbn254.R1CS
	pk *native.ProvingKey
	vk *native.VerifyingKey
}

func init() {
	logger.Disable()
}

func backendCall[Result any](operation func() (Result, error)) (result Result, err error) {
	backendMu.Lock()
	defer backendMu.Unlock()
	defer func() {
		if recover() != nil {
			var empty Result
			result = empty
			err = errBackend
		}
	}()
	return operation()
}

func readValidated(path string, target io.ReaderFrom) error {
	file, err := os.Open(path)
	if err != nil {
		return errKey
	}
	defer file.Close()
	if _, err = target.ReadFrom(file); err != nil {
		return errKey
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); count != 0 || err != io.EOF {
		return errKey
	}
	return nil
}

func readSystem(r1csPath, pkPath, vkPath string) (*preparedProver, error) {
	prover := &preparedProver{cs: groth16.NewCS(ecc.BN254).(*csbn254.R1CS)}
	if err := readValidated(r1csPath, prover.cs); err != nil {
		return nil, err
	}
	if _, _, err := witnessNames(prover.cs); err != nil {
		return nil, errKey
	}
	if pkPath != "" {
		prover.pk = groth16.NewProvingKey(ecc.BN254).(*native.ProvingKey)
		if err := readProvingKey(pkPath, prover); err != nil {
			return nil, err
		}
	}
	if vkPath != "" {
		prover.vk = groth16.NewVerifyingKey(ecc.BN254).(*native.VerifyingKey)
		if err := readValidated(vkPath, prover.vk); err != nil {
			return nil, err
		}
	}
	if err := prover.validateKeys(); err != nil {
		return nil, err
	}
	return prover, nil
}

func readProvingKey(path string, prover *preparedProver) error {
	file, err := os.Open(path)
	if err != nil {
		return errKey
	}
	defer file.Close()
	var header [8 + 5*fr.Bytes + 1]byte
	if _, err := io.ReadFull(file, header[:]); err != nil || header[len(header)-1] > 1 {
		return errKey
	}
	domain := fft.NewDomain(uint64(prover.cs.GetNbConstraints()), fft.WithoutPrecompute())
	var expected bytes.Buffer
	if _, err := domain.WriteTo(&expected); err != nil ||
		!bytes.Equal(header[:len(header)-1], expected.Bytes()[:len(header)-1]) {
		return errKey
	}
	if _, err := prover.pk.ReadFrom(io.MultiReader(bytes.NewReader(header[:]), file)); err != nil {
		return errKey
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); count != 0 || err != io.EOF {
		return errKey
	}
	return nil
}

func (prover *preparedProver) validateKeys() error {
	commitments, ok := prover.cs.CommitmentInfo.(constraint.Groth16Commitments)
	if !ok || len(commitments) > 1 || prover.cs.GetNbConstraints() <= 0 {
		return errKey
	}
	nbPublic := prover.cs.GetNbPublicVariables()
	nbPrivate := prover.cs.GetNbSecretVariables() + prover.cs.NbInternalVariables
	nbWires := nbPublic + nbPrivate
	privateCommitted := 0
	for _, commitment := range commitments {
		privateCommitted += len(commitment.PrivateCommitted)
		if commitment.CommitmentIndex < nbPublic || commitment.CommitmentIndex >= nbWires {
			return errKey
		}
		for _, index := range append(append([]int{}, commitment.PrivateCommitted...), commitment.PublicAndCommitmentCommitted...) {
			if index < 0 || index >= nbWires {
				return errKey
			}
		}
	}
	if prover.pk != nil {
		key := prover.pk
		domain := ecc.NextPowerOfTwo(uint64(prover.cs.GetNbConstraints()))
		if key.Domain.Cardinality != domain || len(key.G1.Z) != int(domain)-1 ||
			len(key.G1.K) != nbPrivate-privateCommitted-len(commitments) ||
			len(key.CommitmentKeys) != len(commitments) ||
			len(key.InfinityA) != nbWires || len(key.InfinityB) != nbWires {
			return errKey
		}
		countInfinity := func(flags []bool) uint64 {
			var count uint64
			for _, flag := range flags {
				if flag {
					count++
				}
			}
			return count
		}
		if key.NbInfinityA != countInfinity(key.InfinityA) || key.NbInfinityB != countInfinity(key.InfinityB) ||
			len(key.G1.A) != nbWires-int(key.NbInfinityA) ||
			len(key.G1.B) != nbWires-int(key.NbInfinityB) || len(key.G2.B) != len(key.G1.B) {
			return errKey
		}
		for index, commitment := range commitments {
			if len(key.CommitmentKeys[index].Basis) != len(commitment.PrivateCommitted) ||
				len(key.CommitmentKeys[index].BasisExpSigma) != len(commitment.PrivateCommitted) {
				return errKey
			}
		}
	}
	if prover.vk != nil {
		key := prover.vk
		if len(key.G1.K) != nbPublic+len(commitments) || len(key.CommitmentKeys) != len(commitments) ||
			len(key.PublicAndCommitmentCommitted) != len(commitments) {
			return errKey
		}
		for index, commitment := range commitments {
			if !reflect.DeepEqual(key.PublicAndCommitmentCommitted[index], commitment.PublicAndCommitmentCommitted) {
				return errKey
			}
		}
		if prover.pk != nil && (!prover.pk.G1.Alpha.Equal(&key.G1.Alpha) ||
			!prover.pk.G2.Beta.Equal(&key.G2.Beta) || !prover.pk.G2.Delta.Equal(&key.G2.Delta)) {
			return errKey
		}
	}
	return nil
}

// readKeyFile loads a Zolana `.key` container: nInputs, nOutputs and
// requiresP256 as big-endian u32s, then the proving key, verifying key and
// constraint system. The constraint system comes last, so the proving key
// cannot be checked against its domain before it is read; the caller must
// verify the file against the pinned proving-key lockfile before loading it.
func readKeyFile(path string) (*preparedProver, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errKey
	}
	defer file.Close()
	var header [12]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		return nil, errKey
	}
	inputs := binary.BigEndian.Uint32(header[0:4])
	outputs := binary.BigEndian.Uint32(header[4:8])
	// Only the Solana-only (eddsa) rails are proved on device.
	if binary.BigEndian.Uint32(header[8:12]) != 0 {
		return nil, errKey
	}
	prover := &preparedProver{
		cs: groth16.NewCS(ecc.BN254).(*csbn254.R1CS),
		pk: groth16.NewProvingKey(ecc.BN254).(*native.ProvingKey),
		vk: groth16.NewVerifyingKey(ecc.BN254).(*native.VerifyingKey),
	}
	for _, section := range []io.ReaderFrom{prover.pk, prover.vk, prover.cs} {
		if _, err := section.ReadFrom(file); err != nil {
			return nil, errKey
		}
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); count != 0 || err != io.EOF {
		return nil, errKey
	}
	if _, _, err := witnessNames(prover.cs); err != nil {
		return nil, errKey
	}
	if err := prover.validateKeys(); err != nil {
		return nil, err
	}
	if shapeInputs, shapeOutputs, known := circuitShape(prover.cs); !known ||
		shapeInputs != inputs || shapeOutputs != outputs {
		return nil, errKey
	}
	return prover, nil
}

func register(read func() (*preparedProver, error)) (uint64, error) {
	return backendCall(func() (uint64, error) {
		if len(prepared) >= maxPrepared || nextHandle == ^uint64(0) {
			return 0, errCapacity
		}
		prover, err := read()
		if err != nil {
			return 0, err
		}
		nextHandle++
		prepared[nextHandle] = prover
		return nextHandle, nil
	})
}

func loadPrepared(r1csPath, pkPath, vkPath string) (uint64, error) {
	return register(func() (*preparedProver, error) {
		if r1csPath == "" || pkPath == "" || vkPath == "" {
			return nil, errKey
		}
		return readSystem(r1csPath, pkPath, vkPath)
	})
}

func loadPreparedKey(path string) (uint64, error) {
	return register(func() (*preparedProver, error) {
		if path == "" {
			return nil, errKey
		}
		return readKeyFile(path)
	})
}

func releasePrepared(handle uint64) {
	_, _ = backendCall(func() (bool, error) {
		delete(prepared, handle)
		return true, nil
	})
}

func provePrepared(handle uint64, input string, structured bool) (proofResult, error) {
	return backendCall(func() (proofResult, error) {
		prover, ok := prepared[handle]
		if !ok {
			return proofResult{}, errHandle
		}
		var full witness.Witness
		var err error
		started := time.Now()
		if structured {
			full, err = buildRequestWitness(input, prover.cs)
		} else {
			full, err = buildWitnessFromJSON(input, prover.cs)
		}
		if err != nil {
			return proofResult{}, err
		}
		witnessMS := uint64(time.Since(started).Milliseconds())
		result, err := prover.prove(full)
		result.witnessMS = witnessMS
		return result, err
	})
}

func (prover *preparedProver) prove(full witness.Witness) (proofResult, error) {
	started := time.Now()
	proof, err := groth16.Prove(prover.cs, prover.pk, full)
	proveMS := uint64(time.Since(started).Milliseconds())
	if err != nil {
		return proofResult{}, errBackend
	}
	public, err := full.Public()
	if err != nil {
		return proofResult{}, errBackend
	}
	var verifyMS uint64
	if prover.vk != nil {
		started := time.Now()
		if err := groth16.Verify(proof, prover.vk, public); err != nil {
			return proofResult{}, errBackend
		}
		verifyMS = uint64(time.Since(started).Milliseconds())
	}
	var proofBytes bytes.Buffer
	if _, err := proof.WriteTo(&proofBytes); err != nil {
		return proofResult{}, errBackend
	}
	publicBytes, err := public.MarshalBinary()
	if err != nil {
		return proofResult{}, errBackend
	}
	canonical, err := json.Marshal(&common.Proof{Proof: proof})
	if err != nil {
		return proofResult{}, errBackend
	}
	inputs, outputs, shapeKnown := circuitShape(prover.cs)
	return proofResult{
		proof:        hex.EncodeToString(proofBytes.Bytes()),
		publicInputs: hex.EncodeToString(publicBytes),
		proofJSON:    string(canonical),
		inputs:       inputs,
		outputs:      outputs,
		shapeKnown:   shapeKnown,
		proveMS:      proveMS,
		verifyMS:     verifyMS,
	}, nil
}

func (prover *preparedProver) verify(proofHex, publicHex string) (bool, error) {
	if len(proofHex) > 4096 || len(publicHex) > maxJSONBytes {
		return false, errProof
	}
	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		return false, errProof
	}
	proof := groth16.NewProof(ecc.BN254)
	reader := bytes.NewReader(proofBytes)
	if _, err := proof.ReadFrom(reader); err != nil || reader.Len() != 0 {
		return false, errProof
	}
	publicBytes, err := hex.DecodeString(publicHex)
	if err != nil {
		return false, errProof
	}
	nbPublic := prover.cs.GetNbPublicVariables() - 1
	if len(publicBytes) != 12+fr.Bytes*nbPublic {
		return false, errProof
	}
	public, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return false, errBackend
	}
	if err := public.UnmarshalBinary(publicBytes); err != nil {
		return false, errProof
	}
	canonical, err := public.MarshalBinary()
	if err != nil || !bytes.Equal(canonical, publicBytes) {
		return false, errProof
	}
	publicOnly, err := public.Public()
	if err != nil || len(publicOnly.Vector().(fr.Vector)) != nbPublic {
		return false, errProof
	}
	if err := groth16.Verify(proof, prover.vk, public); err != nil {
		return false, nil
	}
	return true, nil
}

func verifyPrepared(handle uint64, proofHex, publicHex string) (bool, error) {
	return backendCall(func() (bool, error) {
		prover, ok := prepared[handle]
		if !ok {
			return false, errHandle
		}
		return prover.verify(proofHex, publicHex)
	})
}

func proveOnce(r1csPath, pkPath, input string) (proofResult, error) {
	return backendCall(func() (proofResult, error) {
		if pkPath == "" {
			return proofResult{}, errKey
		}
		prover, err := readSystem(r1csPath, pkPath, "")
		if err != nil {
			return proofResult{}, err
		}
		started := time.Now()
		full, err := buildWitnessFromJSON(input, prover.cs)
		if err != nil {
			return proofResult{}, err
		}
		witnessMS := uint64(time.Since(started).Milliseconds())
		result, err := prover.prove(full)
		result.witnessMS = witnessMS
		return result, err
	})
}

func verifyOnce(r1csPath, vkPath, proofHex, publicHex string) (bool, error) {
	return backendCall(func() (bool, error) {
		if vkPath == "" {
			return false, errKey
		}
		prover, err := readSystem(r1csPath, "", vkPath)
		if err != nil {
			return false, err
		}
		return prover.verify(proofHex, publicHex)
	})
}
