package runner

import (
	"fmt"
	"strings"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "federation.dr", Tags: []string{"federation", "dr", "slow"}, Run: federationDR})
}

// federation.dr (SLOW): the disaster-recovery cutover — Gate 5 ⨝ C2. On each
// network: load a workload (committed + shipped to the object store), capture the
// cosigned head, then simulate a NODE + PROJECTION loss — remove the writer ledger
// (its tessera dir is container-internal) and empty the Postgres projection — and
// rebuild it from the OBJECT STORE ALONE via /rebuild-projection
// --tiles-from-bytestore (tooling v0.0.29+). Asserts the rebuilt projection
// reconstructs the EXACT committed state — entry_index row count == tree_size and
// smt_root_state == the cosigned smt_root — proving a wiped node recovers Postgres
// from S3 with no local filesystem and no live writer.
func federationDR(s *Session) error {
	n := intEnv("E2E_DR_ENTRIES", 200)
	return forEachNetwork(s, func(name string, t stack.Target) error {
		if t.DB == "" || t.Bucket == "" {
			return fmt.Errorf("%s: manifest has no db/bucket — bring the stack up with this build", name)
		}

		// 1. Workload → committed + shipped to the object store.
		before, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
		st, err := stack.Backfill(t, s.Images.Ledger, n, intEnv("E2E_BACKFILL_WORKERS", 8), 0.0, intEnv("E2E_BACKFILL_BATCH", 1))
		if err != nil {
			return fmt.Errorf("%s: backfill: %w", name, err)
		}
		if !stack.WaitDrained(t.CertsDir, t.LedgerPort, before+st.Roots,
			time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 15))*time.Minute) {
			return fmt.Errorf("%s: backfill did not drain", name)
		}

		// 2. Capture the cosigned head — its tiles ship to S3 before it publishes.
		hz, err := stack.FetchHorizon(t.CertsDir, t.LedgerPort)
		if err != nil {
			return fmt.Errorf("%s: fetch horizon: %w", name, err)
		}
		if hz.TreeSize == 0 || hz.SMTRoot == "" {
			return fmt.Errorf("%s: cosigned horizon empty (size=%d smt_root=%q) — nothing to recover", name, hz.TreeSize, hz.SMTRoot)
		}

		// 3. Lose the node + the projection.
		if err := stack.WipeLedgerProjection(t); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		// 4. Rebuild Postgres from the object store alone.
		if _, err := stack.UpRebuildJob(t, s.Images.Ledger); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		// 5. The rebuilt projection must reconstruct the exact committed state.
		count, smtRoot, err := stack.RebuiltProjectionState(t)
		if err != nil {
			return fmt.Errorf("%s: read rebuilt state: %w", name, err)
		}
		if count != hz.TreeSize {
			return fmt.Errorf("%s: rebuilt entry_index has %d rows, want tree_size %d", name, count, hz.TreeSize)
		}
		if !strings.EqualFold(smtRoot, hz.SMTRoot) {
			return fmt.Errorf("%s: rebuilt smt_root %s != cosigned smt_root %s", name, smtRoot, hz.SMTRoot)
		}
		fmt.Printf("  [PASS] %-8s DR: wiped node rebuilt Postgres from the object store alone — %d entries, smt_root %s… reconstructed\n",
			name, count, smtRoot[:16])
		return nil
	})
}
