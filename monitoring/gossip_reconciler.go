// FILE PATH: monitoring/gossip_reconciler.go
//
// DESCRIPTION:
//
//	Reconciler is the sink end of the inbound gossip pipeline: it receives raw
//	SignedEvents from the topology PeerPuller, runs the zero-trust two-tier
//	verifier, and routes each VERIFIED, strongly-typed finding to its enforcer.
//	It is the "Smart Edge brain" — the active agent that turns cryptographically
//	proven peer events into Judicial Network state changes.
//
//	  CosignedTreeHead         → TrustedHeadStore (advance JN's verified view of
//	                             the peer log's head; flag forks/regressions)
//	  Equivocation             → EquivocationResponder (slash the offending log)
//	  EntryCommitmentEquiv.    → alert (entry-level double-spend evidence)
//	  others (escrow / rotation / ghost / cross-log inclusion) → verified +
//	                             logged; their enforcers attach here as they land
//
//	The verifier and slasher are referenced through minimal local interfaces, so
//	monitoring stays free of verification/ and equivocation/ imports — the
//	concrete types are wired at the composition root. Reconciler satisfies
//	topology.SignedEventSink structurally (HandleSignedEvent).
//
//	FAIL-CLOSED: an event that fails verification returns an error (the puller
//	logs + skips it) and NEVER reaches an enforcer.
package monitoring

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
)

// FindingVerifier runs the two-tier (envelope + finding proof) check on a
// pulled event and returns the verified, typed finding.
// *verification.GossipVerifier satisfies it.
type FindingVerifier interface {
	Verify(ctx context.Context, ev gossip.SignedEvent) (gossip.Event, error)
}

// Reconciler verifies pulled events and dispatches them to enforcers.
type Reconciler struct {
	verifier FindingVerifier
	heads    *TrustedHeadStore
	equiv    *EquivocationResponder
	logger   *slog.Logger
}

// ReconcilerConfig configures a Reconciler.
type ReconcilerConfig struct {
	// Verifier runs the zero-trust check. Required.
	Verifier FindingVerifier
	// Heads records verified cosigned tree heads. Required (also the merkle
	// trust anchor).
	Heads *TrustedHeadStore
	// Equivocation responds to verified equivocation findings. Optional; nil ⇒
	// equivocation findings are verified + logged but not slashed.
	Equivocation *EquivocationResponder
	// Logger; nil ⇒ slog.Default().
	Logger *slog.Logger
}

// NewReconciler validates config and returns a Reconciler.
func NewReconciler(cfg ReconcilerConfig) (*Reconciler, error) {
	if cfg.Verifier == nil {
		return nil, errors.New("monitoring/gossip_reconciler: nil Verifier")
	}
	if cfg.Heads == nil {
		return nil, errors.New("monitoring/gossip_reconciler: nil Heads")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Reconciler{verifier: cfg.Verifier, heads: cfg.Heads, equiv: cfg.Equivocation, logger: logger}, nil
}

// HandleSignedEvent verifies one pulled event and acts on it. Satisfies
// topology.SignedEventSink. A verification failure returns an error so the
// puller records the rejection; a successful verify is dispatched by Kind.
func (r *Reconciler) HandleSignedEvent(ctx context.Context, ev gossip.SignedEvent) error {
	event, err := r.verifier.Verify(ctx, ev)
	if err != nil {
		return fmt.Errorf("monitoring/gossip_reconciler: verify: %w", err)
	}
	switch f := event.(type) {
	case *findings.CosignedTreeHeadFinding:
		verdict := r.heads.RecordCosignedHead(ev.Originator, f.Head.TreeHead)
		if verdict == VerdictForkSuspected {
			r.logger.Error("monitoring/gossip_reconciler: peer log fork — same size, different root",
				slog.String("source_log", ev.Originator),
				slog.Uint64("tree_size", f.Head.TreeSize))
		}
		return nil

	case *findings.EquivocationFinding:
		if r.equiv == nil {
			r.logger.Error("monitoring/gossip_reconciler: verified equivocation but no responder wired",
				slog.String("ledger_endpoint", f.LedgerEndpoint))
			return nil
		}
		return r.equiv.Respond(ctx, f)

	case *findings.EntryCommitmentEquivocationFinding:
		r.logger.Error("monitoring/gossip_reconciler: verified entry-commitment equivocation",
			slog.String("equivocator", f.EquivocatorDID),
			slog.String("schema_id", f.SchemaID))
		return nil

	default:
		// Verified but no enforcer attached yet (escrow override, witness/
		// originator rotation, ghost leaf, cross-log inclusion). Logged so the
		// event is observable; future enforcers slot into the switch above.
		r.logger.Info("monitoring/gossip_reconciler: verified finding (no enforcer)",
			slog.String("kind", string(event.Kind())),
			slog.String("originator", ev.Originator))
		return nil
	}
}
