//go:build e2e

// Phase 4 — Aggregator wire contract (L10), SCENARIOS.md.
package jn

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
)

// S4.1 — Health + ledger-gated readiness.
func TestS4_1_HealthReady(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireAggregator(t)
	code, _, _ := s.Aggregator.Health()
	harness.Eq(t, code, 200, "aggregator /healthz status")
	rc, _, _ := s.Aggregator.Ready()
	harness.StatusIn(t, rc, "aggregator /readyz status", 200, 503)
}

// S4.2 — classifyType taxonomy: each of the 10 header shapes routes to the
// right table. Needs distinct per-type logs (H1) carrying those shapes.
func TestS4_2_ClassifyTypeTaxonomy(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireAggregator(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S4.2: seed each of the 10 header shapes and assert table routing (needs H1 seeded entries)")
}

// S4.3 — Per-type indexing + uniqueness (cases UNIQUE(docket), …). H1.
func TestS4_3_PerTypeIndexing(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireAggregator(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S4.3: assert cases UNIQUE(docket) + per-type rows (needs H1 seeded case)")
}

// S4.4 — Read projection surface.
func TestS4_4_ReadProjection(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireAggregator(t)
	code, body, err := s.Aggregator.Cases()
	harness.Truthy(t, err == nil, "aggregator cases error: "+harness.ErrStr(err))
	harness.StatusIn(t, code, "aggregator /v1/judicial/cases status", 200, 404)
	if code == 200 {
		harness.ValidJSON(t, body, "aggregator cases")
	}
	if !s.Cfg.H1Seeded {
		t.Log("note: no H1 seeding yet — the projection isn't meaningfully populated")
	}
}

// S4.5 — Watermark + rebuildability (T4): reset scan_watermarks→0 + re-scan ⇒
// identical rows. Needs H1 + projection DB access.
func TestS4_5_Rebuildability(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S4.5: reset scan_watermarks→0 and diff rows (needs H1 seeded entries + aggregator DB access)")
}

// S4.6 — Decode resilience: a corrupt entry is skipped + the watermark still
// advances. Needs an inject fixture upstream.
func TestS4_6_DecodeResilience(t *testing.T) {
	s := harness.NewStack(t)
	s.Pending(t, "S4.6: inject a corrupt entry and assert it's skipped + watermark advances (needs an inject fixture)")
}
