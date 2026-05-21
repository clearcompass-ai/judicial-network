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
	"github.com/clearcompass-ai/attesta/types"
)

// FindingVerifier runs the two-tier (envelope + finding proof) check on a
// pulled event and returns the verified, typed finding.
// *verification.GossipVerifier satisfies it.
type FindingVerifier interface {
	Verify(ctx context.Context, ev gossip.SignedEvent) (gossip.Event, error)
}

// WitnessSetRotator installs a verified witness-set rotation into the live
// trust root, using the rotating log's standing (inherited) quorum.
// *verification.WitnessSetRegistry satisfies it. Optional in ReconcilerConfig;
// nil ⇒ verified rotations are logged but the trust root does not advance.
type WitnessSetRotator interface {
	ApplyVerifiedRotation(logDID string, rotation types.WitnessRotation) error
}

// Reconciler verifies pulled events and dispatches them to enforcers.
type Reconciler struct {
	verifier FindingVerifier
	heads    *TrustedHeadStore
	equiv    *EquivocationResponder
	rotator  WitnessSetRotator
	store    gossip.Store
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
	// Rotator installs verified witness-set rotations into the live trust root.
	// Optional; nil ⇒ verified rotations are logged but not applied (the
	// witness set cannot advance at runtime).
	Rotator WitnessSetRotator
	// Store durably persists every VERIFIED inbound event (D7) so the JN's
	// worldview survives a restart. Optional; nil ⇒ events are enforced but
	// not persisted (ephemeral, pre-durability behaviour).
	Store gossip.Store
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
	return &Reconciler{verifier: cfg.Verifier, heads: cfg.Heads, equiv: cfg.Equivocation, rotator: cfg.Rotator, store: cfg.Store, logger: logger}, nil
}

// HandleSignedEvent verifies one pulled event and acts on it. Satisfies
// topology.SignedEventSink. A verification failure returns an error so the
// puller records the rejection; a successful verify is dispatched by Kind.
func (r *Reconciler) HandleSignedEvent(ctx context.Context, ev gossip.SignedEvent) error {
	event, err := r.verifier.Verify(ctx, ev)
	if err != nil {
		return fmt.Errorf("monitoring/gossip_reconciler: verify: %w", err)
	}
	// D7: persist every verified event so the JN's worldview survives a
	// restart. Durability is the async clock — a store hiccup is logged
	// but never blocks enforcement (the action clock). Idempotent
	// re-receipt returns nil; chain/lamport rejects are observable.
	if r.store != nil {
		if err := r.store.Append(ctx, ev); err != nil {
			r.logger.Warn("monitoring/gossip_reconciler: persist verified event failed",
				slog.String("originator", ev.Originator),
				slog.String("kind", string(event.Kind())),
				slog.String("error", err.Error()))
		}
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

	case *findings.WitnessRotationFinding:
		// The finding is already Tier-2 verified (K-of-N of the CURRENT set
		// signed this rotation). Advance the live trust root: the registry
		// re-runs verify-before-swap and installs the new set under the
		// rotating log's standing quorum. logDID is the originator — the same
		// key the verifier resolved the witness set under.
		if r.rotator == nil {
			r.logger.Error("monitoring/gossip_reconciler: verified witness-set rotation but no rotator wired",
				slog.String("source_log", ev.Originator))
			return nil
		}
		if err := r.rotator.ApplyVerifiedRotation(ev.Originator, f.Rotation); err != nil {
			// Non-fatal: typically "no current set for this log" (we do not
			// track that peer's witness set) or a monotonic reject (a newer
			// set already won the race). Observable, not a pull failure.
			r.logger.Error("monitoring/gossip_reconciler: witness-set rotation not applied",
				slog.String("source_log", ev.Originator),
				slog.String("error", err.Error()))
			return nil
		}
		r.logger.Info("monitoring/gossip_reconciler: witness set rotated",
			slog.String("source_log", ev.Originator))
		return nil

	default:
		// Verified but no enforcer attached yet (escrow override, originator
		// rotation, ghost leaf, cross-log inclusion). Logged so the event is
		// observable; future enforcers slot into the switch above.
		r.logger.Info("monitoring/gossip_reconciler: verified finding (no enforcer)",
			slog.String("kind", string(event.Kind())),
			slog.String("originator", ev.Originator))
		return nil
	}
}
