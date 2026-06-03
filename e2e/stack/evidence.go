package stack

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/clearcompass-ai/judicial-network/e2e/dockerx"
	"github.com/clearcompass-ai/judicial-network/e2e/runstore"
)

// regressionSig is a known integrity-failure signature from a bug fixed this cycle.
// The evidence scan asserts the ledger log contains ZERO of the HARD ones — a
// healthy 30K run with amendments must never emit them.
type regressionSig struct {
	name string
	sig  string
	hard bool // hard ⇒ any occurrence fails the recipe
}

// The ledger-log signatures of the integrity bugs fixed this cycle. HARD ones are
// unambiguous faults that must not appear; the others are designed-mechanism noise
// surfaced for visibility (a transient hold/backpressure tick is legitimate; a
// sustained run is not, and shows up as a large count next to a passing audit).
var ledgerRegressions = []regressionSig{
	{"amendment-batch ON CONFLICT (SQLSTATE 21000)", "cannot affect row a second time", true},
	{"builder batch failure", "batch processing failed", true},
	{"horizon root unknown (the 30K /v1/smt/proof 500)", "horizon root unknown", true},
	{"unknown SMT root in proof", "ErrUnknownRoot", true},
	{"publish/tile-durability gate violated", "publish-tile-durability gate violated", true},
	{"sequencer wedge (builder lag at limit)", "backpressure stall — builder lag at limit", false},
	{"checkpoint hold (horizon frozen)", "checkpoint hold (horizon frozen", false},
}

// CaptureEvidence writes an evidence bundle under .run/{id}/evidence and asserts the
// ledger log contains none of the HARD integrity-regression signatures. It returns
// an error iff a hard signature is present (so a regression fails the recipe with
// the artifacts already on disk). The bundle is:
//
//	checkpoint.json          the witness-cosigned horizon (root_hash, smt_root,
//	                         tree_size, K signatures) — the only trusted anchor
//	head.json                /v1/tree/head
//	backfill-manifest.json   the audit oracle (its keys are the real committed keys)
//	audit.txt                the full light-client audit output
//	ledger.log               the complete ledger container log
//	regressions.txt          per-signature scan result (PASS / FOUND ×N)
func CaptureEvidence(layout *runstore.Layout, t Target, auditOutput string) error {
	dir := filepath.Join(layout.Home, "evidence")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	write := func(name, content string) { _ = os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644) }

	log := dockerx.Logs(t.LedgerName)
	write("ledger.log", log)
	write("checkpoint.json", httpBody(fmt.Sprintf("http://localhost:%d/v1/tree/horizon", t.LedgerPort)))
	write("head.json", httpBody(fmt.Sprintf("http://localhost:%d/v1/tree/head", t.LedgerPort)))
	write("audit.txt", auditOutput)
	if b, err := os.ReadFile(filepath.Join(t.FixturesDir, "backfill-manifest.json")); err == nil {
		write("backfill-manifest.json", string(b))
	}

	var report strings.Builder
	fmt.Fprintf(&report, "regression scan of the ledger log (run %s):\n\n", layout.ID)
	hardHits := 0
	for _, r := range ledgerRegressions {
		n := strings.Count(log, r.sig)
		kind := "warn"
		if r.hard {
			kind = "HARD"
		}
		status := "PASS"
		if n > 0 {
			status = fmt.Sprintf("FOUND ×%d", n)
			if r.hard {
				hardHits++
			}
		}
		fmt.Fprintf(&report, "  [%s] %-48s %s\n", kind, r.name, status)
	}
	write("regressions.txt", report.String())
	fmt.Print("\n" + report.String())
	fmt.Printf("\n  evidence bundle → %s\n", dir)
	if hardHits > 0 {
		return fmt.Errorf("%d HARD integrity-regression signature(s) in the ledger log — see %s/regressions.txt", hardHits, dir)
	}
	return nil
}
