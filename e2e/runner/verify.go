package runner

import (
	"errors"
	"fmt"
	"strings"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "verify", Tags: []string{"verify"}, Run: verifyAll})
	Register(Recipe{Name: "verify.checkpoint", Tags: []string{"verify"}, Run: mk(vCheckpoint)})
	Register(Recipe{Name: "verify.head", Tags: []string{"verify"}, Run: mk(vHeadHorizon)})
	Register(Recipe{Name: "verify.witness", Tags: []string{"verify"}, Run: mk(vWitness)})
	Register(Recipe{Name: "verify.proofs", Tags: []string{"verify"}, Run: mk(vProofs)})
	Register(Recipe{Name: "verify.oracle", Tags: []string{"verify"}, Run: mk(vOracle)})
	Register(Recipe{Name: "verify.logs", Tags: []string{"verify"}, Run: mk(vLogs)})
	Register(Recipe{Name: "verify.auditor", Tags: []string{"verify"}, Run: vAuditor})
	Register(Recipe{Name: "verify.aggregator", Tags: []string{"verify"}, Run: vAggregator})
}

// check is one verification result.
type check struct {
	name   string
	ok     bool
	detail string
}

type checkFn func(*Session, stack.Target) check

// mk adapts a single check into a Recipe.Run.
func mk(c checkFn) func(*Session) error {
	return func(s *Session) error { return runChecks(s, c) }
}

// verifyAll is the exhaustive verifier: it re-derives every integrity property of
// the persisted stack from scratch — the witness-cosigned anchor, full-coverage SMT
// proofs over that anchor, the oracle's distinctness, the head/horizon coherence,
// and a regression scan of the ledger log. It trusts only SHA-256 and the K witness
// signatures; everything else is recomputed live.
func verifyAll(s *Session) error {
	// Ledger + witness cryptographic integrity, every byte re-derived and read
	// over OPEN HTTPS (server-verify, no client cert): the cosigned anchor, the
	// full-coverage SMT proofs, the oracle's distinctness, head/horizon coherence,
	// and the log regression scan.
	cfErr := runChecks(s, vCheckpoint, vHeadHorizon, vProofs, vOracle, vLogs)
	// The independent auditor's agreement, reached over the same open-HTTPS pull
	// path. Aggregated (not short-circuited) so one failure doesn't mask the other.
	audErr := vAuditor(s)
	return errors.Join(cfErr, audErr)
}

func runChecks(s *Session, checks ...checkFn) error {
	t, ok := s.Target("")
	if !ok {
		return fmt.Errorf("no network in the persisted manifest")
	}
	fmt.Printf("verifying stack %q (network %s, ledger :%d)\n", s.Manifest.ID, t.LedgerName, t.LedgerPort)
	allOK := true
	for _, c := range checks {
		r := c(s, t)
		status := "PASS"
		if !r.ok {
			status, allOK = "FAIL", false
		}
		fmt.Printf("  [%s] %-12s %s\n", status, r.name, r.detail)
	}
	if !allOK {
		return fmt.Errorf("verification FAILED")
	}
	return nil
}

func short(hex string) string {
	if len(hex) > 12 {
		return hex[:12] + "…"
	}
	return hex
}

// vCheckpoint: the horizon is witness-cosigned by >= K DISTINCT genesis witnesses.
func vCheckpoint(_ *Session, t stack.Target) check {
	c, err := stack.FetchHorizon(t.CertsDir, t.LedgerPort)
	if err != nil {
		return check{"checkpoint", false, err.Error()}
	}
	if c.TreeSize < 1 {
		return check{"checkpoint", false, "empty horizon (tree_size 0)"}
	}
	if len(c.Signatures) < t.QuorumK {
		return check{"checkpoint", false, fmt.Sprintf("%d signatures, want >= K=%d", len(c.Signatures), t.QuorumK)}
	}
	if c.DistinctSigners() != len(c.Signatures) {
		return check{"checkpoint", false, "a witness signed more than once (distinct < total)"}
	}
	if !c.SchemesAllECDSA() {
		return check{"checkpoint", false, "non-ECDSA cosignature scheme present"}
	}
	return check{"checkpoint", true, fmt.Sprintf("K-of-N %d/%d, %d distinct signers, tree_size %d, smt_root %s",
		len(c.Signatures), t.QuorumK, c.DistinctSigners(), c.TreeSize, short(c.SMTRoot))}
}

// vHeadHorizon: the cosigned horizon tracks the committed head (it lags by design,
// never leads, and on a static stack it has caught up).
func vHeadHorizon(_ *Session, t stack.Target) check {
	hz, err := stack.FetchHorizon(t.CertsDir, t.LedgerPort)
	if err != nil {
		return check{"head⇄horizon", false, err.Error()}
	}
	head, err := stack.FetchHead(t.CertsDir, t.LedgerPort)
	if err != nil {
		return check{"head⇄horizon", false, err.Error()}
	}
	if hz.TreeSize > head.TreeSize {
		return check{"head⇄horizon", false, fmt.Sprintf("horizon %d LEADS head %d (impossible)", hz.TreeSize, head.TreeSize)}
	}
	state := fmt.Sprintf("caught up at %d", head.TreeSize)
	if hz.TreeSize < head.TreeSize {
		state = fmt.Sprintf("horizon %d lags head %d by %d (committed-but-not-yet-cosigned)", hz.TreeSize, head.TreeSize, head.TreeSize-hz.TreeSize)
	}
	return check{"head⇄horizon", true, state}
}

// vProofs: re-run the light-client auditor at FULL coverage — every committed
// member key + random non-members — verifying each proof over the tile substrate
// against the witness-cosigned smt_root.
func vProofs(s *Session, t stack.Target) check {
	leaves, _, err := stack.InspectOracle(t.ManifestPath())
	if err != nil {
		return check{"proofs", false, "no oracle manifest — run audit.tiles (a workload) first: " + err.Error()}
	}
	out, err := stack.RunAudit(t, s.Images.Ledger, leaves, 16, true)
	if err != nil {
		return check{"proofs", false, "audit did not pass (see output above)"}
	}
	return check{"proofs", true, auditSummary(out)}
}

// vOracle: the backfill oracle has one DISTINCT key per leaf (no seq-0 collapse).
func vOracle(_ *Session, t stack.Target) check {
	leaves, distinct, err := stack.InspectOracle(t.ManifestPath())
	if err != nil {
		return check{"oracle", false, "no manifest: " + err.Error()}
	}
	if leaves == 0 {
		return check{"oracle", false, "manifest has 0 leaves"}
	}
	if distinct != leaves {
		return check{"oracle", false, fmt.Sprintf("%d/%d keys distinct — manifest collapsed (the DeriveKey(seq 0) bug)", distinct, leaves)}
	}
	return check{"oracle", true, fmt.Sprintf("%d leaves, all %d keys distinct (no seq-0 collapse)", leaves, distinct)}
}

// vLogs: the ledger log carries none of the HARD integrity-regression signatures.
func vLogs(_ *Session, t stack.Target) check {
	hard, report := stack.ScanRegressions(stack.LedgerLog(t.LedgerName))
	if hard > 0 {
		return check{"logs", false, fmt.Sprintf("%d HARD signature(s):\n%s", hard, report)}
	}
	return check{"logs", true, "0 HARD regression signatures"}
}

// vWitness: the witness fleet's K-of-N cosignatures on the ledger head verify
// CRYPTOGRAPHICALLY against the genesis bootstrap — read over OPEN HTTPS, no
// client cert. It first pins the cosignature shape (>= K distinct ECDSA signers
// on a non-empty horizon), then runs the stateless light-client audit WITHOUT the
// backfill oracle: the auditor pins the bootstrap witness keys, fetches the
// cosigned checkpoint, verifies the cosignatures, and samples inclusion/exclusion
// proofs over the cosigned root. Needs no workload — this is the witness-trust
// check on a fresh stack, and a no-client-cert caller completing it IS the
// open-read proof.
func vWitness(s *Session, t stack.Target) check {
	hz, err := stack.FetchHorizon(t.CertsDir, t.LedgerPort)
	if err != nil {
		return check{"witness", false, err.Error()}
	}
	if hz.TreeSize < 1 {
		return check{"witness", false, "empty horizon (tree_size 0) — nothing cosigned"}
	}
	if len(hz.Signatures) < t.QuorumK {
		return check{"witness", false, fmt.Sprintf("%d cosignatures, want >= K=%d", len(hz.Signatures), t.QuorumK)}
	}
	if hz.DistinctSigners() != len(hz.Signatures) {
		return check{"witness", false, "a witness signed more than once (distinct < total)"}
	}
	if !hz.SchemesAllECDSA() {
		return check{"witness", false, "non-ECDSA cosignature scheme present"}
	}
	// Cryptographic verification against the genesis witness set (bootstrap-only,
	// no oracle): proves the cosignatures are real, not just present.
	samples := hz.TreeSize
	if samples > 16 {
		samples = 16
	}
	out, err := stack.RunAudit(t, s.Images.Ledger, samples, 4, false)
	if err != nil {
		return check{"witness", false, "light-client cosignature audit did not pass (see output above)"}
	}
	return check{"witness", true, fmt.Sprintf("K-of-N %d/%d cosignatures verify vs genesis bootstrap over open HTTPS; %s",
		len(hz.Signatures), t.QuorumK, auditSummary(out))}
}

// vAuditor: every network's independent auditor service agrees with the ledger
// over the OPEN-HTTPS pull path. The auditor reaches /readyz only after its
// boot-time originator discovery GET /v1/log-info to the ledger SUCCEEDS over open
// HTTPS (server-verify, no client cert) — a failed handshake fails the pipeline
// build before the listener serves — so a green auditor is the auditor↔ledger
// open-HTTPS proof end-to-end. We re-confirm liveness and that its gossip custody
// feed (the JN's ingest source) is serving what it pulled. Lenient on ABSENCE
// (a topology with no auditors is skipped, not failed) so it can join verifyAll.
func vAuditor(s *Session) error {
	any := false
	for _, n := range s.Manifest.Networks {
		for idx, port := range n.AuditorPorts {
			any = true
			if !stack.AuditorReady(port) {
				return fmt.Errorf("auditor %s-%d not ready on :%d (/healthz+/readyz != 200 — open-HTTPS pull to the ledger failed?)", n.Name, idx+1, port)
			}
			if !stack.AuditorFeedServing(port) {
				return fmt.Errorf("auditor %s-%d gossip feed not serving on :%d (/v1/gossip 5xx — custody store not wired)", n.Name, idx+1, port)
			}
			fmt.Printf("  [PASS] auditor %-10s :%d  /readyz 200 (open-HTTPS ledger discovery succeeded) + gossip feed serving\n", fmt.Sprintf("%s-%d", n.Name, idx+1), port)
		}
	}
	if !any {
		fmt.Println("  [skip] no auditors in the persisted manifest")
	}
	return nil
}

// vAggregator: every JN-bearing network's read-projection aggregator is up and
// READY. /readyz is 200 only when the aggregator reached BOTH its projection DB
// and the mTLS ledger edge (the aggregator's probes.go), so green proves the
// scan-pipeline wiring end-to-end. (The full scan→classify→index→query path is
// exercised by the phase4_aggregator suite over a judicial workload.)
func vAggregator(s *Session) error {
	any := false
	for _, n := range s.Manifest.Networks {
		if n.AggregatorPort == 0 {
			continue
		}
		any = true
		if !stack.AggregatorReady(n.AggregatorPort) {
			return fmt.Errorf("aggregator %q not ready on :%d (/readyz != 200 — projection DB or mTLS ledger unreachable)", n.Name, n.AggregatorPort)
		}
		fmt.Printf("  [PASS] aggregator %-10s :%d  /healthz + /readyz 200 (mTLS ledger + projection DB reachable)\n", n.Name, n.AggregatorPort)
	}
	if !any {
		return fmt.Errorf("no aggregator in the persisted stack (every JN network should carry one — was it brought up?)")
	}
	return nil
}

// auditSummary pulls the membership / non-membership tallies out of the audit log.
func auditSummary(out string) string {
	var parts []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "membership —") {
			parts = append(parts, strings.TrimSpace(strings.TrimPrefix(line, "audit:")))
		}
	}
	if len(parts) == 0 {
		return "audit PASS"
	}
	return strings.Join(parts, "; ")
}
