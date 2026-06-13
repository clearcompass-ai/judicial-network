package aggregator

import (
	"context"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/exchange"
	"github.com/baseproof/baseproof/kinds"
	libagg "github.com/baseproof/tooling/libs/aggregator"
)

// JudicialProjector adapts the agnostic libs/aggregator engine to the judicial
// domain. It implements libagg.Projector: the engine polls/decodes/advances the
// watermark; this classifies each decoded entry by judicial header shape and
// indexes it into the judicial Postgres projection (Ledger Principle 12 —
// schema-aware extractor inversion).
type JudicialProjector struct {
	// Gate is the W2 replay judge: THE SAME SubmitGater the write door
	// runs (handlers.BundleSubmitGate over the jurisdiction Registry),
	// re-run on every destination entry BEFORE projection. nil = no
	// judge = fail-closed: destination entries refuse (counted), the
	// directory never moves on unjudged input.
	Gate SubmitGater

	// Destinations is the directory mutation seam (the *Indexer in
	// production; a recording fake in the lock tests).
	Destinations DestinationStore

	// Refusals is the named-refusal counter surface. Never nil after
	// NewJudicialProjector.
	Refusals *RefusalCounter

	indexer *Indexer
}

// NewJudicialProjector builds the projector over the judicial indexer.
// SubmitGater mirrors handlers.SubmitGater (api/exchange/handlers) without
// importing the API package from the aggregator — one method, same
// contract: nil = admit, non-nil = the closed-set rejection.
type SubmitGater interface {
	Admit(e *envelope.Entry) *GateRejection
}

// GateRejection mirrors handlers.Rejection.
type GateRejection struct {
	Code   string
	Reason string
}

func NewJudicialProjector(idx *Indexer) *JudicialProjector {
	p := &JudicialProjector{indexer: idx}
	p.Refusals = NewRefusalCounter()
	p.Destinations = idx
	return p
}

// Project classifies the decoded entry and indexes it into the judicial tables.
func (p *JudicialProjector) Project(ctx context.Context, d *libagg.DecodedEntry) error {
	c := classify(d)
	if c.EntryType == "platform_kind" {
		return p.projectPlatformKind(ctx, c)
	}
	return p.indexer.Index(ctx, c)
}

// projectPlatformKind is the rc10 dispatch. Destination lifecycle kinds
// re-judge their cosignature mix (W2) then apply; every other registry
// kind is INERT here by doctrine — no consumer, no mutation, no counter
// noise. The rogue-grant lock test pins the inertness.
func (p *JudicialProjector) projectPlatformKind(ctx context.Context, c *ClassifiedEntry) error {
	kind := platformKind(c)
	switch kind {
	case kinds.EntryDestinationProvisionV1, kinds.EntryDestinationAmendV1, kinds.EntryDestinationRetireV1:
		// fall through to the judged path below
	default:
		return nil // inert-by-absence: genesis/delegation/credential/burn
	}

	// W2: re-judge the embedded mix with THE SAME gate the door runs.
	// No judge wired ⇒ fail closed: count, never mutate.
	if p.Gate == nil {
		p.Refusals.Inc(RefusalGateUnwired)
		return nil
	}
	if rej := p.Gate.Admit(c.Entry); rej != nil {
		p.Refusals.Inc(RefusalGateRejected)
		return nil
	}
	if p.Destinations == nil {
		p.Refusals.Inc(RefusalGateUnwired)
		return nil
	}

	raw := c.Entry.DomainPayload
	var refusal string
	var err error
	switch kind {
	case kinds.EntryDestinationProvisionV1:
		pr, derr := exchange.DecodeDestinationProvisionPayload(raw)
		if derr != nil {
			p.Refusals.Inc(RefusalMalformed)
			return nil
		}
		refusal, err = p.Destinations.ApplyProvision(ctx, pr, c.LogDID, c.Sequence)
	case kinds.EntryDestinationAmendV1:
		am, derr := exchange.DecodeDestinationAmendPayload(raw)
		if derr != nil {
			p.Refusals.Inc(RefusalMalformed)
			return nil
		}
		refusal, err = p.Destinations.ApplyAmend(ctx, am, c.LogDID, c.Sequence)
	case kinds.EntryDestinationRetireV1:
		rt, derr := exchange.DecodeDestinationRetirePayload(raw)
		if derr != nil {
			p.Refusals.Inc(RefusalMalformed)
			return nil
		}
		refusal, err = p.Destinations.ApplyRetire(ctx, rt, c.LogDID, c.Sequence)
	}
	if err != nil {
		return err // infrastructure failure: surface, the scanner retries
	}
	if refusal != "" {
		p.Refusals.Inc(refusal) // lifecycle pollution: counted, unapplied
	}
	return nil
}
