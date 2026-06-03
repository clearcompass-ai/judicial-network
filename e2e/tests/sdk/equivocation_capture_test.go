//go:build e2e

// Phase 6 — equivocation CAPTURE (S6.16–S6.18, S5.17), SCENARIOS.md.
//
// These CAPTURE the SDK-tier equivocation use cases inside the e2e black-box
// suite, so one `make test` run against the live federation exercises them too.
// The crypto is pure-SDK (the H4 fork fixture in ../equivocation), so they need
// NO live infrastructure and pass regardless of which stack is up — they are the
// e2e suite's record that the equivocation→finding→position-aware→burn-gate
// chain is covered.
//
// The one piece that genuinely needs a spun-up stack is injecting a fork into a
// RUNNING auditor and asserting the deployed slasher/JN fail closed — that is
// TestS6_7_Equivocation (phase6_flows_test.go), still gated on E2E_FORK_ENABLE.
package sdk

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/tests/sdk/equivocation"
)

func equivFixture(t *testing.T) *equivocation.WitnessSet {
	t.Helper()
	ws, err := equivocation.NewWitnessSet(4, 3, equivocation.NetworkIDFromLabel("e2e-equivocation"))
	if err != nil {
		t.Fatalf("fork fixture (H4): %v", err)
	}
	return ws
}

// S6.16 — a fork is detected + provable + wraps into a valid finding (UC-EQ-1).
func TestS6_16_EquivocationDetected(t *testing.T) {
	equivocation.AssertEquivocationDetected(t, equivFixture(t))
}

// S6.17 — no false slash: honest / foreign-key / sub-quorum heads never yield a
// proof (UC-EQ-1 negative).
func TestS6_17_EquivocationNoFalseSlash(t *testing.T) {
	equivocation.AssertNoFalseSlash(t, equivFixture(t))
}

// S6.18 — equivocation is era-bound (position-aware): a year-1 fork confirms
// against its own set, not the year-15 set (UC-EQ-2 / ZT-SCN-02).
func TestS6_18_EquivocationPositionAware(t *testing.T) {
	equivocation.AssertPositionAwareEraCorrect(t)
}

// S5.17 — a pin into a burned (equivocated) source fails closed in the cross-log
// gate (UC-EQ-3 / UC-XL-2).
func TestS5_17_CrossLogBurnGate(t *testing.T) {
	equivocation.AssertBurnFailsClosed(t, equivFixture(t))
}
