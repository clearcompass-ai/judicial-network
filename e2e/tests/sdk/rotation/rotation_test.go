// SDK-tier rotation tests — run with NO infrastructure:
//
//	go test ./rotation/
//
// A 15-era ("year 1 → year 15") witness-set rotation chain through the real
// baseproof rotation primitives. Captured in the e2e suite as S6.19/S6.20.
package rotation

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/tests/sdk/equivocation"
)

func eras(t *testing.T) []*equivocation.WitnessSet {
	t.Helper()
	e, err := Eras(15, 4, 3, "rotation-year1-to-year15") // 15 eras, 3-of-4 each
	if err != nil {
		t.Fatalf("Eras: %v", err)
	}
	return e
}

// UC-ROT: the year-1 → year-15 rotation chain is authorized end-to-end.
func TestUC_ROT_ChainAuthorized_Year1ToYear15(t *testing.T) {
	AssertRotationChainAuthorized(t, eras(t))
}

// UC-ROT (negative): forged / sub-quorum rotations are rejected.
func TestUC_ROT_ForgedRotationRejected(t *testing.T) {
	AssertForgedRotationRejected(t, eras(t))
}
