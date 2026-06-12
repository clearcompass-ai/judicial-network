/*
FILE PATH: verification/eras/eras.go

Era-correct witness-set resolution for cross-log verification (FED-1 #107) —
the JN consumer wrapper around libs/witnessrotation's journal-first resolver,
adding exactly what the enforcer's verify path needs and nothing the resolver
already owns:

  - THE TAXONOMY (never folded, counters never page):
    no-such-peer        — the source log has no configured trust root;
    decided LOCALLY from the boot-built root set,
    never by parsing resolver errors.
    warming             — the per-peer rotation journal is an in-memory
    cache rebuilt at boot by the gossip puller's
    re-ingest; until a peer is WARM, a head we
    cannot explain is a retryable startup state,
    not evidence of staleness.
    cannot-resolve-era  — the peer is warm and no journaled chain set
    explains the head: a genuine refusal.
    (quorum-fail stays the cross-log verifier's own verdict — resolution
    hands it an era-correct set and gets out of the way.)

  - WARMTH, defined where it is knowable: a peer is warm once ANY of
    (a) a resolution for it has succeeded (a head explained by the chain
    proves the chain we hold is usable — including the genesis-only
    chain of a never-rotated peer);
    (b) its journal holds at least one rotation record (the backfill
    reached it);
    (c) the boot grace window has elapsed (bounded: the window exists
    only to cover re-ingest of a chain whose rotations number in
    the dozens — seconds, not minutes).
    Fail-closed both ways: warming NEVER admits anything; it only names
    the rejection so a 3 a.m. operator reads "starting up", not "fork".

The underlying trust machinery — genesis-rooted chain walk with
witness.VerifyRotation re-run every step, head-anchored era selection —
is libs/witnessrotation.JournalWitnessSetResolver's, untouched.
*/
package eras

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
)

// Rejection classes — one sentinel per class, errors.Is-able through wraps.
var (
	ErrNoSuchPeer       = errors.New("eras: no trust root configured for source log")
	ErrWarming          = errors.New("eras: rotation journal warming up for source log")
	ErrCannotResolveEra = errors.New("eras: no journaled chain set explains the head")
)

// SetResolver is the narrow seam handlers consume (and tests fake).
type SetResolver interface {
	// SetForHead returns the witness set authoritative for the SPECIFIC
	// cosigned head — era-anchored by which chain set's K-of-N the head's
	// cosignatures satisfy. Failures carry exactly one of the class
	// sentinels above.
	SetForHead(ctx context.Context, logDID string, head types.CosignedTreeHead) (*cosign.WitnessKeySet, error)

	// CurrentSet returns the NEWEST chain set this process can prove for
	// the log (genesis + every journaled verified rotation) — the
	// current-set consumer's seam (live-horizon fetches). It never
	// guesses past the journal: if the live log rotated beyond the chain
	// we hold, the downstream live-horizon verification fails closed and
	// the chain catches up via gossip. Failures: ErrNoSuchPeer, or
	// ErrCannotResolveEra wrapping a broken/poisoned chain.
	CurrentSet(ctx context.Context, logDID string) (*cosign.WitnessKeySet, error)
}

// headResolver is the libs resolver surface we delegate to.
type headResolver interface {
	SetForHead(ctx context.Context, logDID string, head types.CosignedTreeHead) (*cosign.WitnessKeySet, error)
	CurrentSet(ctx context.Context, logDID string) (*cosign.WitnessKeySet, error)
}

// chainSource reports whether a peer's journal holds any rotation records
// (warmth criterion (b)). Satisfied by witnessrotation journals' RecordsFor.
type chainSource interface {
	RecordsFor(ctx context.Context, logDID string) ([]types.WitnessRotationRecord, error)
}

// Counters are the dimensional Domain-Violation counters (never page).
type Counters struct {
	Resolved         atomic.Uint64
	NoSuchPeer       atomic.Uint64
	Warming          atomic.Uint64
	CannotResolveEra atomic.Uint64
}

// Resolver classifies era-resolution outcomes for the verify path.
// Construct via New; safe for concurrent use.
type Resolver struct {
	inner   headResolver
	chains  chainSource
	known   map[string]struct{} // canonical log DIDs + aliases with trust roots
	bootAt  time.Time
	grace   time.Duration
	logger  *slog.Logger
	warm    sync.Map // logDID → struct{}{}
	C       Counters
	nowFunc func() time.Time
}

// DefaultWarmupGrace bounds the warming window when neither a journal record
// nor a successful resolution has yet marked a peer warm. Re-ingest of a
// rotation chain (dozens of records) completes within one or two gossip poll
// intervals; 30s covers slow peers without hiding a real outage for long.
const DefaultWarmupGrace = 30 * time.Second

// New builds the resolver. knownLogs carries every name (canonical DID and
// alias) that has a configured trust root — the no-such-peer class is decided
// from this set, never by inspecting resolver errors. grace<=0 applies
// DefaultWarmupGrace.
func New(inner headResolver, chains chainSource, knownLogs []string, grace time.Duration, logger *slog.Logger) (*Resolver, error) {
	if inner == nil {
		return nil, fmt.Errorf("eras: nil inner resolver")
	}
	if chains == nil {
		return nil, fmt.Errorf("eras: nil chain source")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if grace <= 0 {
		grace = DefaultWarmupGrace
	}
	known := make(map[string]struct{}, len(knownLogs))
	for _, l := range knownLogs {
		if l != "" {
			known[l] = struct{}{}
		}
	}
	return &Resolver{
		inner: inner, chains: chains, known: known,
		bootAt: time.Now(), grace: grace, logger: logger,
		nowFunc: time.Now,
	}, nil
}

// SetForHead implements SetResolver with the class taxonomy.
func (r *Resolver) SetForHead(ctx context.Context, logDID string, head types.CosignedTreeHead) (*cosign.WitnessKeySet, error) {
	if _, ok := r.known[logDID]; !ok {
		r.C.NoSuchPeer.Add(1)
		return nil, fmt.Errorf("%w: %q", ErrNoSuchPeer, logDID)
	}
	set, err := r.inner.SetForHead(ctx, logDID, head)
	if err == nil {
		r.warm.Store(logDID, struct{}{})
		r.C.Resolved.Add(1)
		return set, nil
	}
	if r.isWarm(ctx, logDID) {
		r.C.CannotResolveEra.Add(1)
		return nil, fmt.Errorf("%w (log %q, head TreeSize=%d): %v", ErrCannotResolveEra, logDID, head.TreeSize, err)
	}
	r.C.Warming.Add(1)
	r.logger.InfoContext(ctx, "eras: resolution deferred during journal warmup",
		"log_did", logDID, "tree_size", head.TreeSize)
	return nil, fmt.Errorf("%w (log %q): %v", ErrWarming, logDID, err)
}

// CurrentSet implements SetResolver. A genesis-only chain is a SUCCESS
// (the newest provable set IS the genesis for a never-rotated log), so the
// warming class does not apply — only unknown logs and broken chains refuse.
func (r *Resolver) CurrentSet(ctx context.Context, logDID string) (*cosign.WitnessKeySet, error) {
	if _, ok := r.known[logDID]; !ok {
		r.C.NoSuchPeer.Add(1)
		return nil, fmt.Errorf("%w: %q", ErrNoSuchPeer, logDID)
	}
	set, err := r.inner.CurrentSet(ctx, logDID)
	if err != nil {
		r.C.CannotResolveEra.Add(1)
		return nil, fmt.Errorf("%w (log %q): %v", ErrCannotResolveEra, logDID, err)
	}
	r.C.Resolved.Add(1)
	return set, nil
}

// isWarm applies the three warmth criteria; (a) successes are recorded in
// SetForHead, so here only (b) journal-non-empty and (c) grace-elapsed run.
func (r *Resolver) isWarm(ctx context.Context, logDID string) bool {
	if _, ok := r.warm.Load(logDID); ok {
		return true
	}
	if recs, err := r.chains.RecordsFor(ctx, logDID); err == nil && len(recs) > 0 {
		r.warm.Store(logDID, struct{}{})
		return true
	}
	if r.nowFunc().Sub(r.bootAt) >= r.grace {
		return true // grace elapsed: from here on, failures are genuine
	}
	return false
}
