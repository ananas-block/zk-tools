package shared_test

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"testing/cryptotest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	defaultring "zolana/prover/circuits/spp_transaction/default"
	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
	"zolana/prover/prover/common"
	transfer "zolana/prover/prover/transfer_eddsa_only"
)

// Not upstream: writes the web prover's 2x3 demo request, a deterministic
// satisfying transfer_confidential witness in `/prove` JSON.
//
//	WEB_FIXTURE=$PWD/prover-wasm/testdata/transfer-2x3.json go test ./circuits/spp_transaction/shared -run TestWriteWebFixture
func TestWriteWebFixture(t *testing.T) {
	path := os.Getenv("WEB_FIXTURE")
	if path == "" {
		t.Skip("WEB_FIXTURE is unset")
	}
	cryptotest.SetGlobalRandom(t, 0)
	assignment := buildDefaultRingEddsaOnlyAssignment(t, protocol.Shape{NInputs: 2, NOutputs: 3})
	assignment.BlindingSeed = big.NewInt(800)
	rebuildAfterOwnerChange(t, assignment)
	refreshDefaultRingPublicInputHash(t, assignment)
	circuit := asDefaultRingEddsaOnly(assignment).(*defaultring.DefaultRingEddsaOnlyCircuit)
	circuit.Shape = assignment.Shape

	data, err := json.Marshal(webParameters(circuit))
	if err != nil {
		t.Fatal(err)
	}
	var decoded transfer.TransferParameters
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.ValidateShape(); err != nil {
		t.Fatal(err)
	}
	witness, err := decoded.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(witness, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("request does not satisfy the circuit: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// webParameters inverts TransferParameters.CreateWitness for the default ring.
func webParameters(c *defaultring.DefaultRingEddsaOnlyCircuit) *transfer.TransferParameters {
	value := spptest.AsBigInt
	values := spptest.ToBigInts
	p := &transfer.TransferParameters{
		NInputs:                      uint32(len(c.Private.Inputs)),
		NOutputs:                     uint32(len(c.Private.Outputs)),
		OutputTreeID:                 value(c.Public.OutputTreeID),
		ExternalDataHash:             value(c.Public.ExternalDataHash),
		PrivateTxHash:                value(c.Public.PrivateTxHash),
		BlindingSeed:                 value(c.Private.BlindingSeed),
		PublicAssets:                 values(c.Public.PublicAssets[:]),
		PublicAmounts:                values(c.Public.PublicAmounts[:]),
		RingProgramID:                big.NewInt(0),
		SignerPkHashes:               values(c.Public.SignerPkHashes),
		InputFlags:                   value(c.Public.InputFlags),
		PublishedOutputOwnerPkHashes: values(c.Public.OutputOwnerPkHashes),
		Cache: transfer.CacheSelectionParams{
			TreeID:        value(c.CachedInputs.TreeID),
			ReadHashChain: value(c.CachedInputs.ReadHashChain),
			ReadHashes:    values(c.CachedInputs.ReadHashes),
			IsCached:      values(c.CachedInputs.IsCached),
			ReadIndex:     values(c.CachedInputs.ReadIndex),
		},
		Variant:         transfer.ConfidentialVariant,
		PublicInputHash: value(c.Public.PublicInputHash),
	}
	for _, slot := range c.Public.TreeSlots {
		p.TreeSlots = append(p.TreeSlots, common.TreeSlotParams{
			ID:            value(slot.ID),
			UtxoRoot:      value(slot.UtxoRoot),
			NullifierRoot: value(slot.NullifierRoot),
		})
	}
	for i, in := range c.Private.Inputs {
		p.Inputs = append(p.Inputs, transfer.InputParams{
			Utxo:                     utxoParams(in.Utxo),
			StatePathElements:        values(in.StatePathElements),
			StatePathIndex:           value(in.StatePathIndex),
			NullifierLowValue:        value(in.NullifierLowValue),
			NullifierNextValue:       value(in.NullifierNextValue),
			NullifierLowPathElements: values(in.NullifierLowPathElements),
			NullifierLowPathIndex:    value(in.NullifierLowPathIndex),
			TreeSlot:                 value(in.TreeSlot),
			Nullifier:                value(c.Public.Nullifiers[i]),
			OwnerPkHash:              value(c.Private.InputOwnerPkHashes[i]),
			NullifierSecret:          value(in.NullifierSecret),
		})
	}
	for i, out := range c.Private.Outputs {
		p.Outputs = append(p.Outputs, transfer.OutputParams{
			Utxo:        utxoParams(out),
			Hash:        value(c.Public.OutputHashes[i]),
			OwnerPkHash: value(c.Public.OutputOwnerPkHashes[i]),
			NullifierPk: value(c.Private.OutputNullifierPks[i]),
		})
	}
	return p
}

func utxoParams(u UtxoCircuitFields) transfer.UtxoParams {
	value := func(v frontend.Variable) *big.Int { return spptest.AsBigInt(v) }
	return transfer.UtxoParams{
		Domain:        value(u.Domain),
		Owner:         value(u.Owner),
		Asset:         value(u.Asset),
		Amount:        value(u.Amount),
		Blinding:      value(u.Blinding),
		DataHash:      value(u.DataHash),
		RingDataHash:  value(u.RingDataHash),
		RingProgramID: value(u.RingProgramID),
	}
}
