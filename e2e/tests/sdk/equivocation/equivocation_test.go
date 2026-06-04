// SDK-tier equivocation tests — run with NO infrastructure:
//
//	go test ./equivocation/
//
// These exercise the H4 fork fixture end-to-end through the real baseproof SDK
// (witness.DetectEquivocation, findings.NewEquivocationFinding, the
// position-aware anchors, and the verifier burn-gate). The identical assertions
// are captured in the e2e black-box suite (tests/phase6_equivocation_capture_test.go)
// so `make test` against a live stack exercises them too.
package equivocation

import "testing"

func newSet(t *testing.T) *WitnessSet {
	t.Helper()
	ws, err := NewWitnessSet(4, 3, NetworkIDFromLabel("equivocation-fixture"))
	if err != nil {
		t.Fatalf("NewWitnessSet: %v", err)
	}
	return ws
}

// UC-EQ-1: a fork is detected + provable, and wraps into a valid finding.
func TestUC_EQ_1_EquivocationDetected(t *testing.T) { AssertEquivocationDetected(t, newSet(t)) }

// UC-EQ-1 (negative): no false slash from honest / foreign / sub-quorum heads.
func TestUC_EQ_1_NoFalseSlash(t *testing.T) { AssertNoFalseSlash(t, newSet(t)) }

// UC-EQ-2: equivocation is era-bound (position-aware), not judged by the live set.
func TestUC_EQ_2_PositionAwareEraCorrect(t *testing.T) { AssertPositionAwareEraCorrect(t) }

// UC-EQ-3 / UC-XL-2: a burned source fails closed in the cross-log gate.
func TestUC_EQ_3_BurnGateFailsClosed(t *testing.T) { AssertBurnFailsClosed(t, newSet(t)) }
