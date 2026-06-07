package runner

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "federation.proof.cold", Tags: []string{"proof", "cold", "verify"}, Run: federationProofCold})
}

// federation.proof.cold: on EVERY network (single → 1, federation → N), prove a COLD
// entry — one committed early, then left far behind as the horizon advances —
// exercising the cold-seq read path end to end: FetchCosignedHead resolves the LATEST
// horizon for an old seq (1.1b); inclusion of that old leaf is reconstructed under the
// advanced tree; the receipt proof binds to the entry's FIRST covering checkpoint, not
// the latest horizon (1.2a). The proof verifies FULLY OFFLINE + tamper-fails-closed.
func federationProofCold(s *Session) error {
	ctx := context.Background()
	return forEachNetwork(s, func(name string, t stack.Target) error {
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
		fmt.Printf("== %s cold: entry committed at size~%d, horizon advanced to %d (cold gap %d) — proving it ==\n",
			name, earlySize, lateSize, lateSize-earlySize)

		// 3. Prove the COLD entry against the advanced horizon; verify offline + tamper.
		if err := proveEntry(ctx, name, t, coldKey); err != nil {
			return fmt.Errorf("cold proof: %w", err)
		}
		fmt.Printf("  [PASS] %s cold entry proven + verified OFFLINE against advanced horizon %d\n", name, lateSize)
		return nil
	})
}
