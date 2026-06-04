package runner

import (
	"fmt"
	"sort"
	"strings"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "federation.diag", Tags: []string{"federation", "diag"}, Run: federationDiag})
}

// federationDiag is a READ-ONLY forensic dump that PROVES (or refutes) object-store
// clobbering across networks from RUNTIME EVIDENCE — never code inference.
//
// The load-bearing invariant: two independent logs (distinct LogDIDs, distinct
// committed entries) can NEVER legitimately serve the same smt_root/root_hash. So
// if network A's :PORT_A and network B's :PORT_B both serve one smt_root, that is
// hard proof they are reading ONE overwritten object — the per-network ledgers are
// sharing an object-store namespace.
//
// It pairs, for each network:
//   - the SERVED horizon (what GET /v1/tree/horizon returns right now), and
//   - that ledger's OWN log lines ("checkpoint published" / "cosigned tree head" /
//     "checkpoint hold", carrying the ledger's smt_root + signatures + quorum_k/_n),
//
// so a divergence between "what THIS ledger says it published" and "what THIS
// ledger's port serves" is visible from the ledger's own logs — the absolute-
// certainty signal the served-bytes comparison is then cross-checked against.
//
// Read-only: it fetches and reads logs; it never writes. Safe to run against a
// live, already-failed stack to capture the post-mortem state.
func federationDiag(s *Session) error {
	nets := s.Manifest.Networks
	if len(nets) == 0 {
		return fmt.Errorf("no networks in the persisted manifest")
	}

	type row struct {
		name, ledger, logDID string
		port, quorumK        int
		hz                   stack.Checkpoint
		head                 stack.Checkpoint
		hzErr, headErr       error
	}
	rows := make([]row, 0, len(nets))

	fmt.Println("== federation.diag: per-network published horizon vs ledger's own log (read-only) ==")
	for _, nm := range nets {
		t, ok := s.Target(nm.Name)
		if !ok {
			return fmt.Errorf("no target for network %q", nm.Name)
		}
		r := row{name: nm.Name, ledger: t.LedgerName, logDID: t.LogDID, port: t.LedgerPort, quorumK: t.QuorumK}
		r.hz, r.hzErr = stack.FetchHorizon(t.CertsDir, t.LedgerPort)
		r.head, r.headErr = stack.FetchHead(t.CertsDir, t.LedgerPort)
		rows = append(rows, r)

		fmt.Printf("\n  network %-8s  ledger=%s  :%d  K=%d\n", r.name, r.ledger, r.port, r.quorumK)
		fmt.Printf("    LEDGER_LOG_DID           %s\n", r.logDID)
		if r.headErr != nil {
			fmt.Printf("    head    (served)         ERROR %v\n", r.headErr)
		} else {
			fmt.Printf("    head    (served)         size=%d sigs=%d\n", r.head.TreeSize, len(r.head.Signatures))
		}
		if r.hzErr != nil {
			fmt.Printf("    horizon (served)         ERROR %v\n", r.hzErr)
		} else {
			fmt.Printf("    horizon (served)         size=%d sigs=%d distinct=%d\n",
				r.hz.TreeSize, len(r.hz.Signatures), r.hz.DistinctSigners())
			fmt.Printf("      smt_root               %s\n", r.hz.SMTRoot)
			fmt.Printf("      root_hash              %s\n", r.hz.RootHash)
			for _, sig := range r.hz.Signatures {
				fmt.Printf("      cosigner pub_key_id    %s (scheme %d)\n", sig.PubKeyID, sig.SchemeTag)
			}
		}
		// The ledger's OWN account of what it published — the debug/info log lines that
		// carry smt_root + signatures + quorum_k/quorum_n. If THIS ledger logged it
		// published smt_root=X with K sigs, but THIS ledger's port now serves a
		// different smt_root, the object under it was overwritten by another writer.
		fmt.Printf("    ledger log (its own published checkpoints / cosigns / holds):\n")
		hits := tailMatching(stack.LedgerLog(r.ledger),
			[]string{"checkpoint published", "cosigned tree head", "checkpoint hold"}, 8)
		if len(hits) == 0 {
			fmt.Printf("      (none found — raise LEDGER_LOG_LEVEL=debug for full step trace)\n")
		}
		for _, ln := range hits {
			fmt.Printf("      | %s\n", ln)
		}
	}

	// ── Collision verdict from served bytes ──────────────────────────────────
	// Group every served horizon by its smt_root. Distinct logs MUST land in
	// distinct groups; any group with >1 network is proof of a shared-namespace
	// overwrite.
	fmt.Println("\n== cross-network collision verdict (served smt_root) ==")
	bySMT := map[string][]string{}
	for _, r := range rows {
		if r.hzErr != nil {
			continue
		}
		bySMT[r.hz.SMTRoot] = append(bySMT[r.hz.SMTRoot], r.name)
	}
	collision := false
	roots := make([]string, 0, len(bySMT))
	for root := range bySMT {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	for _, root := range roots {
		owners := bySMT[root]
		sort.Strings(owners)
		if len(owners) > 1 {
			collision = true
			fmt.Printf("  [COLLISION] networks {%s} ALL serve smt_root=%s\n", strings.Join(owners, ", "), short(root))
			fmt.Printf("              distinct logs cannot share a root — they are overwriting ONE shared\n")
			fmt.Printf("              object-store object (no per-network/per-log S3 namespace).\n")
		} else {
			fmt.Printf("  [distinct] %-8s smt_root=%s\n", owners[0], short(root))
		}
	}
	if collision {
		return fmt.Errorf("PROVEN: object-store clobbering — multiple networks serve an identical smt_root (shared S3 namespace)")
	}
	fmt.Println("  [OK] every network serves a DISTINCT smt_root — no shared-namespace clobbering observed")
	return nil
}

// tailMatching returns up to n of the LAST lines in log that contain any needle.
func tailMatching(log string, needles []string, n int) []string {
	var hits []string
	for _, ln := range strings.Split(log, "\n") {
		for _, nd := range needles {
			if strings.Contains(ln, nd) {
				hits = append(hits, strings.TrimSpace(ln))
				break
			}
		}
	}
	if len(hits) > n {
		hits = hits[len(hits)-n:]
	}
	return hits
}
