//go:build e2e

// Phase 8 — Determinism / idempotency / atomicity, SCENARIOS.md.
package jn

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
)

// S8.1 — Replay idempotent: resubmitting an already-sequenced entry returns a
// stable canonical_hash and does not grow the tree.
func TestS8_1_ReplayIdempotent(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	size, ok := s.HeadSize()
	if !ok || size == 0 {
		t.Skip("no sequenced entries to replay")
	}
	rc, wire, err := s.Ledger.EntryRaw(0)
	if err != nil || rc != 200 || len(wire) == 0 {
		t.Skip("entry 0 raw bytes unavailable (rc=" + harness.Itoa(rc) + ")")
	}
	sct1, c1, _ := s.Ledger.SubmitEntry(wire)
	if c1 == 400 || c1 == 415 {
		t.Skip("raw entry bytes not directly re-submittable (framing differs from canonical submit)")
	}
	harness.StatusIn(t, c1, "replay submit status", 200, 202, 409)
	sct2, c2, _ := s.Ledger.SubmitEntry(wire)
	harness.StatusIn(t, c2, "replay submit (2) status", 200, 202, 409)
	if sct1.CanonicalHash != "" && sct2.CanonicalHash != "" {
		harness.Eq(t, sct2.CanonicalHash, sct1.CanonicalHash, "replay canonical_hash stable")
	}
	size2, _ := s.HeadSize()
	harness.Truthy(t, size2 == size, "tree grew on idempotent replay (was "+harness.Itoa(int(size))+", now "+harness.Itoa(int(size2))+")")
}

// S8.2 — SCT/canonical-hash stable across two fresh ledgers for the same
// payload. Needs a second court (H2).
func TestS8_2_SCTStableAcrossLedgers(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	s.RequireSecondCourt(t)
	s.Pending(t, "S8.2: submit the same payload to both courts; assert identical canonical_hash (needs H2)")
}

// S8.3 — Batch all-or-nothing: a batch containing an invalid entry commits
// none (tree size unchanged).
func TestS8_3_BatchAllOrNothing(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	size, ok := s.HeadSize()
	if !ok {
		t.Skip("no head to compare against")
	}
	body := []byte(`{"entries":[{"wire_bytes_hex":"00"},{"wire_bytes_hex":"zz"}]}`)
	code, _, err := s.Ledger.SubmitBatch(body)
	harness.Truthy(t, err == nil, "batch error: "+harness.ErrStr(err))
	harness.Truthy(t, code >= 400 && code < 500, "batch with an invalid entry was not rejected (status "+harness.Itoa(code)+")")
	size2, _ := s.HeadSize()
	harness.Truthy(t, size2 == size, "tree grew despite a rejected batch (atomicity broken)")
}

// S8.4 — STH finality: a published head with tree_size≥1 carries ≥K
// cosignatures (no state advance before cosign).
func TestS8_4_STHFinality(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)
	head, code, _ := s.Ledger.TreeHead()
	if code == 404 {
		t.Skip("no cosigned head yet")
	}
	if head.TreeSize >= 1 {
		harness.Truthy(t, len(head.Signatures) >= s.QuorumK(), "published head has < K cosignatures (finality before cosign)")
	}
}
