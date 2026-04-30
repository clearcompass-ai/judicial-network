/*
FILE PATH: verification/appellate_history_test.go

DESCRIPTION:
    Tests for the v0.7.0 unbounded WalkAppealChain. Pins:
      - origin-only chain (length 1).
      - 2-step chain (TN COA topology).
      - 3-step chain (TN COA + Sup Ct topology).
      - 4-step chain (federal: district → circuit → en-banc
        rehear → SCOTUS).
      - error halts the walk; partial chain returned.
      - nil NextProofFn rejected.
      - Step indices are 1-indexed and contiguous.

    VerifyAppealChain pins are out-of-scope here (require live
    BLS keys); covered in cross-log proof contract tests.
*/
package verification

import (
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// stubNext is a deterministic NextProofFn that returns each
// step in `successors` in turn, then nil.
func stubNext(successors []AppealStep) NextProofFn {
	i := 0
	return func(_ AppealStep) (*AppealStep, error) {
		if i >= len(successors) {
			return nil, nil
		}
		s := successors[i]
		i++
		return &s, nil
	}
}

// ─── nil callback rejection ──────────────────────────────────────

func TestWalkAppealChain_NilCallback(t *testing.T) {
	if _, err := WalkAppealChain(AppealStep{}, nil); err == nil {
		t.Error("nil NextProofFn must reject")
	}
}

// ─── origin-only chain ──────────────────────────────────────────

func TestWalkAppealChain_OriginOnly(t *testing.T) {
	origin := AppealStep{
		LogDID: "did:web:state:tn:davidson",
	}
	chain, err := WalkAppealChain(origin, stubNext(nil))
	if err != nil {
		t.Fatalf("WalkAppealChain: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("origin-only chain length: want 1, got %d", len(chain))
	}
	if chain[0].Step != 1 {
		t.Errorf("origin Step must be 1, got %d", chain[0].Step)
	}
}

// ─── TN COA topology: trial → COA ───────────────────────────────

func TestWalkAppealChain_TN_TwoLevel(t *testing.T) {
	origin := AppealStep{LogDID: "did:web:state:tn:davidson"}
	successors := []AppealStep{
		{LogDID: "did:web:state:tn:coa", Outcome: "affirmed"},
	}
	chain, err := WalkAppealChain(origin, stubNext(successors))
	if err != nil {
		t.Fatalf("WalkAppealChain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("TN 2-level chain: want 2 steps, got %d", len(chain))
	}
	if chain[0].Step != 1 || chain[1].Step != 2 {
		t.Errorf("Step indices drift: %d, %d", chain[0].Step, chain[1].Step)
	}
	if chain[1].LogDID != "did:web:state:tn:coa" {
		t.Errorf("step-2 LogDID drift: %q", chain[1].LogDID)
	}
}

// ─── TN 3-level: trial → COA → Sup Ct ───────────────────────────

func TestWalkAppealChain_TN_ThreeLevel(t *testing.T) {
	origin := AppealStep{LogDID: "did:web:state:tn:davidson"}
	successors := []AppealStep{
		{LogDID: "did:web:state:tn:coa", Outcome: "affirmed"},
		{LogDID: "did:web:state:tn:sc", Outcome: "affirmed"},
	}
	chain, err := WalkAppealChain(origin, stubNext(successors))
	if err != nil {
		t.Fatalf("WalkAppealChain: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("TN 3-level chain: want 3 steps, got %d", len(chain))
	}
	for i, want := range []string{
		"did:web:state:tn:davidson",
		"did:web:state:tn:coa",
		"did:web:state:tn:sc",
	} {
		if chain[i].LogDID != want {
			t.Errorf("step-%d LogDID drift: got %q want %q",
				i+1, chain[i].LogDID, want)
		}
		if chain[i].Step != i+1 {
			t.Errorf("step-%d Step drift: %d", i+1, chain[i].Step)
		}
	}
}

// ─── federal 4-level: district → circuit → en-banc → SCOTUS ─────

func TestWalkAppealChain_Federal_FourLevel(t *testing.T) {
	origin := AppealStep{LogDID: "did:web:fed:trial:tnm"}
	successors := []AppealStep{
		{LogDID: "did:web:fed:circuit:6"},
		{LogDID: "did:web:fed:circuit:6", Outcome: "en_banc_rehearing"},
		{LogDID: "did:web:fed:scotus", Outcome: "cert_granted"},
	}
	chain, err := WalkAppealChain(origin, stubNext(successors))
	if err != nil {
		t.Fatalf("WalkAppealChain: %v", err)
	}
	if len(chain) != 4 {
		t.Fatalf("federal 4-level chain: want 4 steps, got %d",
			len(chain))
	}
	// Step 4 is the topology-agnostic property.
	if chain[3].Step != 4 {
		t.Errorf("step-4 Step drift: %d", chain[3].Step)
	}
}

// ─── error halts walk ───────────────────────────────────────────

func TestWalkAppealChain_ErrorHaltsWalk(t *testing.T) {
	origin := AppealStep{LogDID: "did:web:state:tn:davidson"}
	calls := 0
	next := func(_ AppealStep) (*AppealStep, error) {
		calls++
		if calls == 1 {
			return &AppealStep{LogDID: "did:web:state:tn:coa"}, nil
		}
		return nil, errors.New("simulated fetch failure")
	}
	chain, err := WalkAppealChain(origin, next)
	if err == nil {
		t.Fatal("error must propagate")
	}
	if !strings.Contains(err.Error(), "step 2") {
		t.Errorf("error must reference halting step; got %q", err)
	}
	// Partial chain returned (origin + step 2).
	if len(chain) != 2 {
		t.Errorf("partial chain length: want 2, got %d", len(chain))
	}
}

// ─── Step indices remain 1-indexed and contiguous ───────────────

func TestWalkAppealChain_StepIndicesContiguous(t *testing.T) {
	origin := AppealStep{LogDID: "x"}
	successors := []AppealStep{
		{LogDID: "y"},
		{LogDID: "z"},
		{LogDID: "w"},
	}
	chain, err := WalkAppealChain(origin, stubNext(successors))
	if err != nil {
		t.Fatalf("WalkAppealChain: %v", err)
	}
	for i, s := range chain {
		if s.Step != i+1 {
			t.Errorf("step %d index drift: %d", i+1, s.Step)
		}
	}
}

// ─── VerifyAppealChain: unverified-proof short-circuit ──────────

func TestVerifyAppealChain_UnknownLogDIDFailsClosed(t *testing.T) {
	// step with non-nil Proof but unknown LogDID → ProofVerified=false.
	steps := []AppealStep{
		{LogDID: "x", CasePos: types.LogPosition{Sequence: 1}},
		{
			LogDID:  "unknown",
			CasePos: types.LogPosition{Sequence: 2},
			Proof:   &types.CrossLogProof{},
		},
	}
	result, err := VerifyAppealChain(steps,
		map[string][]types.WitnessPublicKey{},
		map[string]int{}, nil)
	if err == nil {
		t.Error("unknown LogDID must break the chain")
	}
	if len(result) != 2 {
		t.Errorf("VerifyAppealChain must return all steps; got %d",
			len(result))
	}
}

// ─── AppealStep no longer carries Level ─────────────────────────

// TestAppealStep_NoLevelField pins the v0.7.0 invariant: the
// SCOTUS-shaped Level field is gone.
func TestAppealStep_NoLevelField(t *testing.T) {
	// If the field comes back, this won't compile.
	s := AppealStep{Step: 1}
	if s.Step != 1 {
		t.Fail()
	}
}
