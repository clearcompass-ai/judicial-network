package runner

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "smoke", Tags: []string{"smoke"}, Run: smoke})
	Register(Recipe{Name: "audit.tiles", Tags: []string{"audit", "tiles"}, Run: auditTiles})
}

func intEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// smoke: the persisted stack is healthy and its head is witness-cosigned.
func smoke(s *Session) error {
	t, ok := s.Target("")
	if !ok {
		return fmt.Errorf("no network in the persisted manifest")
	}
	if !stack.LedgerHealthyPort(t.LedgerPort) {
		return fmt.Errorf("ledger /healthz not ok on :%d", t.LedgerPort)
	}
	sz, sigs := stack.HeadStatus(t.LedgerPort)
	if sz < 1 || sigs < t.QuorumK {
		return fmt.Errorf("head not cosigned (size=%d, sigs=%d, want size>=1 sigs>=%d)", sz, sigs, t.QuorumK)
	}
	fmt.Printf("  head: tree_size=%d, signatures=%d (K=%d)\n", sz, sigs, t.QuorumK)
	return nil
}

// audit.tiles: load an authority workload, wait for the builder to commit it, then
// verify sampled SMT proofs over the tile substrate against the witness-cosigned
// root (the light-client auditor). The headline ledger integrity check.
func auditTiles(s *Session) error {
	t, ok := s.Target("")
	if !ok {
		return fmt.Errorf("no network in the persisted manifest")
	}
	n := intEnv("E2E_AUTH_ENTRIES", 64)
	workers := intEnv("E2E_AUTH_WORKERS", 8)
	batch := intEnv("E2E_AUTH_BATCH_SIZE", 1)

	st, err := stack.Backfill(t, s.Images.Ledger, n, workers, 0.5, batch)
	if err != nil {
		return err
	}
	fmt.Printf("  backfill: %d roots + %d amendments → %d SMT leaves\n", st.Roots, st.Amendments, len(st.Leaves))

	if !stack.WaitDrained(t.LedgerPort, n+1, 10*time.Minute) { // +1 for the genesis seed
		sz, _ := stack.HeadStatus(t.LedgerPort)
		return fmt.Errorf("builder did not drain to tree_size>=%d (stuck at %d)", n+1, sz)
	}
	samples := intEnv("E2E_AUDIT_SAMPLES", 32)
	random := intEnv("E2E_AUDIT_RANDOM", 16)
	return stack.RunAudit(t, s.Images.Ledger, samples, random, true)
}
