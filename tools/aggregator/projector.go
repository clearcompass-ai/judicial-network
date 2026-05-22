package aggregator

import (
	"context"

	libagg "github.com/clearcompass-ai/attesta-tools/libs/aggregator"
)

// JudicialProjector adapts the agnostic libs/aggregator engine to the judicial
// domain. It implements libagg.Projector: the engine polls/decodes/advances the
// watermark; this classifies each decoded entry by judicial header shape and
// indexes it into the judicial Postgres projection (Ledger Principle 12 —
// schema-aware extractor inversion).
type JudicialProjector struct {
	indexer *Indexer
}

// NewJudicialProjector builds the projector over the judicial indexer.
func NewJudicialProjector(idx *Indexer) *JudicialProjector {
	return &JudicialProjector{indexer: idx}
}

// Project classifies the decoded entry and indexes it into the judicial tables.
func (p *JudicialProjector) Project(ctx context.Context, d *libagg.DecodedEntry) error {
	return p.indexer.Index(ctx, classify(d))
}
