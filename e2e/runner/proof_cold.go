package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "federation.proof.cold", Tags: []string{"proof", "cold", "verify"}, Run: federationProofCold})
}

// federation.proof.cold: prove a COLD entry — one committed early, then left far
// behind as the horizon advances — exercising the cold-seq read path end to end:
// FetchCosignedHead resolves the LATEST horizon for an old seq (Phase 1, 1.1b);
// inclusion of that old leaf is reconstructed under the advanced tree; and the
// receipt proof binds to the entry's FIRST covering checkpoint (a per-checkpoint
// delta), not the latest horizon (1.2a). The proof still verifies FULLY OFFLINE
// against the genesis trust root and fails closed under the tamper matrix.
func federationProofCold(s *Session) error {
	t, ok := s.Target("")
	if !ok {
		return fmt.Errorf("no network in the persisted manifest")
	}
	ctx := context.Background()
	drain := time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 15)) * time.Minute

	// 1. A small first batch: entry 0 is committed at an EARLY checkpoint.
	n1 := intEnv("E2E_COLD_EARLY", 4)
	early, err := stack.Backfill(t, s.Images.Ledger, n1, 8, 0.0, 1)
	if err != nil {
		return fmt.Errorf("early backfill: %w", err)
	}
	if len(early.Leaves) == 0 {
		return fmt.Errorf("early backfill produced no leaves")
	}
	coldKey := early.Leaves[0].Key
	if !stack.WaitDrained(t.CertsDir, t.LedgerPort, early.Roots+1, drain) { // +1 genesis seed
		return fmt.Errorf("early batch did not drain (raise E2E_DRAIN_TIMEOUT_MIN)")
	}
	earlySize, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)

	// 2. A large second batch pushes the horizon FAR past entry 0 — it goes cold.
	n2 := intEnv("E2E_COLD_ADVANCE", 40)
	late, err := stack.Backfill(t, s.Images.Ledger, n2, 8, 0.0, 1)
	if err != nil {
		return fmt.Errorf("advance backfill: %w", err)
	}
	if !stack.WaitDrained(t.CertsDir, t.LedgerPort, early.Roots+late.Roots+1, drain) {
		return fmt.Errorf("advance batch did not drain (raise E2E_DRAIN_TIMEOUT_MIN)")
	}
	lateSize, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)

	if lateSize <= earlySize {
		return fmt.Errorf("horizon did not advance (early=%d late=%d) — cold arm would be a no-op", earlySize, lateSize)
	}
	fmt.Printf("== federation.proof.cold: entry committed at size~%d, horizon advanced to %d (cold gap %d) — proving the cold entry ==\n",
		earlySize, lateSize, lateSize-earlySize)

	// 3. Prove the COLD entry against the advanced horizon; verify offline + tamper.
	if err := proveEntry(ctx, t.Network, t, coldKey); err != nil {
		return fmt.Errorf("cold proof: %w", err)
	}
	fmt.Printf("  [PASS] cold entry proven + verified OFFLINE against advanced horizon %d\n", lateSize)
	return nil
}
