package runner

import (
	"context"
	"fmt"

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

	// 1. A small first batch: entry 0 is committed at an EARLY checkpoint.
	early, err := backfillDrained(t, s.Images.Ledger, intEnv("E2E_COLD_EARLY", 4))
	if err != nil {
		return fmt.Errorf("early backfill: %w", err)
	}
	if len(early.Leaves) == 0 {
		return fmt.Errorf("early backfill produced no leaves")
	}
	coldKey := early.Leaves[0].Key
	earlySize, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)

	// 2. A large second batch pushes the horizon FAR past entry 0 — it goes cold.
	if _, err := backfillDrained(t, s.Images.Ledger, intEnv("E2E_COLD_ADVANCE", 40)); err != nil {
		return fmt.Errorf("advance backfill: %w", err)
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
