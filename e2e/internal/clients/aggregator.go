package clients

import "github.com/clearcompass-ai/judicial-network/e2e/internal/httpx"

// Aggregator is a typed client for the read-projection aggregator (L10).
type Aggregator struct{ *httpx.Client }

// NewAggregator returns an aggregator client rooted at base.
func NewAggregator(base string) *Aggregator { return &Aggregator{httpx.New(base)} }

// Cases is GET /v1/judicial/cases — the rebuildable case projection (S4.4,
// T4); returned raw until the projection shape is pinned.
func (a *Aggregator) Cases() (int, []byte, error) { return a.GetRaw("/v1/judicial/cases") }
