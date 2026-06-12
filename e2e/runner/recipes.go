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
	if !stack.LedgerHealthyPort(t.CertsDir, t.LedgerPort) {
		return fmt.Errorf("ledger /healthz not ok on :%d", t.LedgerPort)
	}
	sz, sigs := stack.HeadStatus(t.CertsDir, t.LedgerPort)
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

	drainTimeout := time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 30)) * time.Minute // raise for large -n (e.g. 300K)
	if !stack.WaitDrained(t.CertsDir, t.LedgerPort, n+1, drainTimeout) {             // +1 for the genesis seed
		sz, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
		return fmt.Errorf("builder did not drain to tree_size>=%d in %s (stuck at %d) — raise E2E_DRAIN_TIMEOUT_MIN", n+1, drainTimeout, sz)
	}
	// E2E_AUDIT_FULL=1 audits EVERY committed member key (samples >= leaf count) —
	// indisputable coverage; otherwise sample E2E_AUDIT_SAMPLES (default 32).
	samples := intEnv("E2E_AUDIT_SAMPLES", 32)
	if intEnv("E2E_AUDIT_FULL", 0) == 1 && len(st.Leaves) > samples {
		samples = len(st.Leaves)
	}
	random := intEnv("E2E_AUDIT_RANDOM", 16)
	out, err := stack.RunAudit(t, s.Images.Ledger, samples, random, true)
	if err != nil {
		return err
	}
	// Indisputable evidence: dump the witnessed checkpoint + manifest + audit + full
	// ledger log, and assert the log carries none of the integrity-regression
	// signatures we fixed this cycle (SQLSTATE 21000, horizon-root-unknown, …).
	return stack.CaptureEvidence(s.Layout, t, out)
}
