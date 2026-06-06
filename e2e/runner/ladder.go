package runner

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "federation.ladder", Tags: []string{"federation", "ladder", "soak"}, Run: federationLadder})
}

// federation.ladder — the scaling-ladder soak: load each rung's entry count per
// network in sequence (default 3K then 30K), and at EVERY rung validate BOTH
// phases at once:
//
//	Phase 1 (deep trace + proof): the load flows through the fully-instrumented
//	  ledger (admission→ship→checkpoint traces are emitted when an OTLP endpoint
//	  is set), and a v2 self-anchored proof of a real committed member is
//	  generated and verified OFFLINE per network.
//	Phase 2 (sustained/durability): after the load, the witness-cosigned HORIZON
//	  must catch up to the committed head at K-of-N, and — on a v0.0.19+ ledger
//	  image — the WAL backlog and horizon lag must drain to 0 (shipping and
//	  checkpointing kept up with ingest). The per-rung throughput + durability
//	  gauges are printed.
//
// Rungs are CUMULATIVE (each adds its count on top of the prior), so the 30K
// rung exercises a sustained 30K burst on a non-empty log. Override the rungs
// with E2E_LADDER_SCALES="3000,30000,300000"; tuning knobs (E2E_FED_WORKERS,
// E2E_FED_BATCH_SIZE, E2E_DRAIN_TIMEOUT_MIN) match federation.soak.
func federationLadder(s *Session) error {
	nets := s.Manifest.Networks
	if len(nets) == 0 {
		return fmt.Errorf("federation.ladder needs at least one network in the manifest")
	}
	ctx := context.Background()
	scales := ladderScales()
	workers := intEnv("E2E_FED_WORKERS", 16)
	batch := intEnv("E2E_FED_BATCH_SIZE", 1)
	drain := time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 60)) * time.Minute

	fmt.Printf("== federation.ladder: rungs %v across %d network(s) ==\n", scales, len(nets))
	for ri, scale := range scales {
		fmt.Printf("== rung %d/%d: +%d entries/network — Phase-1 trace+proof + Phase-2 durability ==\n",
			ri+1, len(scales), scale)
		for _, nm := range nets {
			t, ok := s.Target(nm.Name)
			if !ok {
				return fmt.Errorf("no target for network %q", nm.Name)
			}
			before, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)

			t0 := time.Now()
			st, err := stack.Backfill(t, s.Images.Ledger, scale, workers, 0.5, batch)
			if err != nil {
				return fmt.Errorf("rung %d network %s backfill: %w", scale, nm.Name, err)
			}
			elapsed := time.Since(t0)

			if !stack.WaitDrained(t.CertsDir, t.LedgerPort, before+scale, drain) {
				sz, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
				return fmt.Errorf("rung %d network %s: head did not reach %d (stuck at %d) — raise E2E_DRAIN_TIMEOUT_MIN",
					scale, nm.Name, before+scale, sz)
			}

			// Phase 2: durability — horizon caught up at K-of-N + backlog/lag drained.
			snap, err := assertDrained(t, before+scale, drain)
			if err != nil {
				return fmt.Errorf("rung %d network %s durability: %w", scale, nm.Name, err)
			}

			// Phase 1: v2 self-anchored proof of a real committed member, verified offline.
			if len(st.Leaves) == 0 {
				return fmt.Errorf("rung %d network %s: no SMT leaves to prove", scale, nm.Name)
			}
			if err := proveEntry(ctx, nm.Name, t, st.Leaves[0].Key); err != nil {
				return fmt.Errorf("rung %d network %s v2 proof: %w", scale, nm.Name, err)
			}

			rate := float64(scale) / elapsed.Seconds()
			fmt.Printf("  [PASS] %-8s +%d in %s (%.0f entries/s) | head=%d horizon=%d sigs=%d/%d | %s\n",
				nm.Name, scale, elapsed.Round(time.Second), rate,
				snap.HeadSize, snap.HorizonSize, snap.HorizonSigs, t.QuorumK, durabilityLine(snap))
		}
		fmt.Printf("== rung %d (+%d) PASS — drained, horizon at K-of-N, v2 proof verified per network ==\n",
			ri+1, scale)
	}
	fmt.Println("== federation.ladder COMPLETE — every rung green (Phase-1 traces+proof + Phase-2 durability) ==")
	return nil
}

// ladderScales returns the rung sizes: E2E_LADDER_SCALES="3000,30000" (CSV) or
// the default [3000, 30000].
func ladderScales() []int {
	if v := strings.TrimSpace(os.Getenv("E2E_LADDER_SCALES")); v != "" {
		var out []int
		for _, p := range strings.Split(v, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 {
				out = append(out, n)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []int{3000, 30000}
}
