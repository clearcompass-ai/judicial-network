//go:build e2e

// Phase 6 — witness/key-rotation CAPTURE (S6.19–S6.21), SCENARIOS.md.
//
// CAPTURE the SDK-tier rotation use cases inside the e2e suite (the crypto is
// pure-SDK — ../rotation — so they need NO live infra and run under any stack).
// The DEPLOYED rotation (ledger→auditor→JN verify-before-swap, quorum inherited)
// is S6.9, which needs a running stack + a rotation driver.
package sdk

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/tests/sdk/equivocation"
	"github.com/clearcompass-ai/judicial-network/e2e/tests/sdk/rotation"
)

func rotationEras(t *testing.T) []*equivocation.WitnessSet {
	t.Helper()
	e, err := rotation.Eras(15, 4, 3, "e2e-rotation-year1-15") // year-1 → year-15
	if err != nil {
		t.Fatalf("rotation eras: %v", err)
	}
	return e
}

// S6.19 — the year-1 → year-15 rotation chain is authorized end-to-end (UC-ROT).
func TestS6_19_RotationChainAuthorized(t *testing.T) {
	rotation.AssertRotationChainAuthorized(t, rotationEras(t))
}

// S6.20 — forged / sub-quorum rotations are rejected (UC-ROT negative).
func TestS6_20_RotationForgedRejected(t *testing.T) {
	rotation.AssertForgedRotationRejected(t, rotationEras(t))
}

// S6.21 — a provable multi-era history reconstructs the era-correct set at any
// historical position; null as-of rejected (UC-ROT-4 / ZT-IMM-01).
func TestS6_21_RotationHistoryEraCorrect(t *testing.T) {
	rotation.AssertVerifiedHistoryEraCorrect(t, rotationEras(t), "did:web:e2e-rotation-history.test")
}
