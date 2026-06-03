//go:build e2e

// Phase I (integration) — the first cross-component API→DB→Ledger seam.
package integration

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/db"
	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
)

// TestI1_SeedPath_HeadCustodiedAndProvable verifies the live seed/submit path
// across three components at once:
//
//   - API:    the ledger serves a witness-cosigned head over the seeded entries;
//   - DB:     the auditor ingested + PERSISTED that head — peer_gossip is
//     non-empty in the network's Postgres (queried via internal/db);
//   - Ledger: a sampled entry's inclusion proof still serves against the tree.
//
// This is the integration tier's contract — assert the OUTCOME across the stack,
// not just one component's wire shape. Skips cleanly with no stack / no DB.
func TestI1_SeedPath_HeadCustodiedAndProvable(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)

	// API — a cosigned head exists over the seeded entries.
	size, ok := s.HeadSize()
	if !ok || size == 0 {
		t.Skip("no sequenced entries yet — seed the ledger (E2E_SEED_ENTRIES)")
	}

	// DB — Federal's auditor #1 gossip DB persisted the head it ingested.
	pg, gossipDB := s.Cfg.Federal.PGContainer, "auditor_gossip_1"
	if !db.Reachable(pg, gossipDB) {
		if s.Cfg.Strict {
			t.Fatalf("auditor Postgres %s/%s unreachable", pg, gossipDB)
		}
		t.Skipf("auditor Postgres %s/%s unreachable — DB cross-check skipped", pg, gossipDB)
	}
	rows, err := db.Count(pg, gossipDB, "peer_gossip")
	if err != nil {
		t.Fatalf("count peer_gossip: %v", err)
	}
	if rows == 0 {
		t.Fatalf("API serves a head (size=%d) but the auditor DB has 0 peer_gossip rows — custody not persisted", size)
	}

	// Ledger — a sampled entry's inclusion proof serves against the tree.
	seq := size / 2
	code, _, err := s.Ledger.Inclusion(seq)
	if err != nil {
		t.Fatalf("inclusion(%d): %v", seq, err)
	}
	if code != 200 {
		t.Fatalf("inclusion(%d) status %d, want 200", seq, code)
	}

	t.Logf("seed path verified — head size=%d (API), %d peer_gossip rows (DB), inclusion(%d) served (Ledger)",
		size, rows, seq)
}
