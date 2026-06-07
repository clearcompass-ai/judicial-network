package runner

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "federation.proof.scale", Tags: []string{"proof", "scale", "verify"}, Run: federationProofScale})
}

// federation.proof.scale: on EVERY network (single → 1, federation → N), load
// E2E_SCALE_ENTRIES (default 30000) and validate the v2 proof path EXTENSIVELY across
// the WHOLE range — prove E2E_SCALE_SAMPLES members evenly spaced OLDEST..NEWEST, each
// FULLY OFFLINE with only the genesis root + the tamper matrix. Every proof exercises
// all eight touchpoints (genesis_bootstrap, witness_rotation_chain, entry_inclusion,
// entry_smt_membership, checkpoint_quorum, receipt_proof, burn_attestation,
// entry_author_signature); the oldest sample is the deepest cold read — its receipt
// binds to a checkpoint tens of thousands of sizes below the horizon (1.2a) and its
// inclusion is rebuilt under the 30k-leaf tree (1.1b).
//
// Tuning: E2E_SCALE_ENTRIES (30000), E2E_SCALE_SAMPLES (9), and E2E_DRAIN_TIMEOUT_MIN
// (raise it — 30k entries per network take longer to drain + cosign).
func federationProofScale(s *Session) error {
	ctx := context.Background()
	n := intEnv("E2E_SCALE_ENTRIES", 30000)
	samples := intEnv("E2E_SCALE_SAMPLES", 9)
	return forEachNetwork(s, func(name string, t stack.Target) error {
		fmt.Printf("== %s scale: loading %d entries (raise E2E_DRAIN_TIMEOUT_MIN for the drain) ==\n", name, n)
		st, err := backfillDrained(t, s.Images.Ledger, n)
		if err != nil {
			return fmt.Errorf("scale backfill: %w", err)
		}
		total := len(st.Leaves)
		if total == 0 {
			return fmt.Errorf("scale backfill produced no leaves")
		}
		sz, sigs := stack.HeadStatus(t.CertsDir, t.LedgerPort)
		idxs := sampleIndices(total, samples)
		fmt.Printf("== %s: %d entries committed; head at tree_size %d (%d cosigs) — proving %d members across the range ==\n",
			name, total, sz, sigs, len(idxs))
		for _, i := range idxs {
			label := fmt.Sprintf("%s/scale[%d..%d]", name, i, total-1)
			if err := proveEntry(ctx, label, t, st.Leaves[i].Key); err != nil {
				return fmt.Errorf("scale proof at leaf %d of %d: %w", i, total-1, err)
			}
		}
		fmt.Printf("  [PASS] %s %d-entry scale: %d members (oldest..newest) proven + verified OFFLINE, all touchpoints\n",
			name, total, len(idxs))
		return nil
	})
}

// sampleIndices returns up to `samples` evenly-spaced leaf indices over [0, total-1],
// always including the oldest (0) and newest (total-1) — cold-to-warm coverage with a
// bounded number of full proofs. Deduped + ascending.
func sampleIndices(total, samples int) []int {
	if total <= 0 || samples <= 0 {
		return nil
	}
	if samples == 1 {
		return []int{0}
	}
	if samples > total {
		samples = total
	}
	seen := make(map[int]bool, samples)
	out := make([]int, 0, samples)
	for k := 0; k < samples; k++ {
		i := k * (total - 1) / (samples - 1) // evenly spaced, includes 0 and total-1
		if !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	return out
}
