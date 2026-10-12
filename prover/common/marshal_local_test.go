package common

import (
	"math/big"
	"testing"
)

// Not upstream: FromHex is patched to keep a malformed witness value out of
// its error, which the worker would otherwise relay.
func TestFromHexDoesNotExposeInvalidWitness(t *testing.T) {
	var value big.Int
	err := FromHex(&value, "review-private-sentinel")
	if err == nil || err.Error() != "invalid number" {
		t.Fatal("invalid witness must return a fixed error without the input")
	}
}
