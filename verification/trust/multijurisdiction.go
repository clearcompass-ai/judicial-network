/*
FILE PATH:

	verification/trust/multijurisdiction.go

DESCRIPTION:

	MultiJurisdictionTrust is the cross-network LogTrustProvider. It
	is the C-3 successor to LocalTrust: where LocalTrust serves ONE
	(fetcher, leafReader) pair for every LogDID, MultiJurisdictionTrust
	dispatches by LogDID:

	  - HOME log → delegate to the embedded LocalTrust (the existing
	    single-network path; byte-for-byte parity preserved).

	  - FOREIGN log (one of the cfg.GossipIngest.PeerLogs entries) →
	    resolve the trust root via the in-process HeadsJournal — the
	    same journal the multi-network gossip ingest writes through
	    (cmd/network-api/gossip_reconciler.go). The journal returns
	    the foreign log's cosigned head at the requested asOf,
	    fail-closed: ErrEquivocatedLog if the log has been observed
	    to fork, ErrNoHead if no head is recorded yet. Either is
	    surfaced verbatim through TrustRoot (STRICT FAIL-CLOSED
	    Decision 5 of the 15-year zero-trust spec).

	  - UNKNOWN log → ErrUnknownLog (the SDK sentinel; the walker
	    fail-closes).

	The witness set for a foreign log is supplied at construction time
	from cfg.GossipIngest.PeerLogs[*].WitnessDIDs + .QuorumK +
	.NetworkID (the same triple the foreign gossip pipeline binds its
	GossipVerifier to). Threading them here is JN-LOCAL: the journal
	stores wire bytes + signatures but not the trust topology that
	gates them, by design (the journal is wire archive; the trust
	topology is local config).

ENTRY + LEAF SEMANTICS

	C-3 ships a TrustRoot-only foreign path: Entry and Leaf for a
	foreign LogDID return ErrUnknownLog. The call sites the C-4
	migration targets pass inclusion / membership proofs in their
	request payloads — the walker verifies those proofs against the
	TrustRoot.Head this provider returns, and never calls Entry /
	Leaf for the foreign log. A future expansion (post-C) could fold
	the libs/auditing/gossipverify tile-mirror path into Entry to
	serve foreign-log inclusion proofs directly; today that is
	speculative infrastructure.

	HOME log Entry / Leaf delegate to LocalTrust unchanged.

AS-OF SEMANTICS

	verifier.AsOf{} (zero value) → "latest known head" — the journal's
	LatestHead(logDID). A non-zero AsOf with Sequence > 0 →
	HeadAt(logDID, asOf.Sequence) (the head whose sequence is the
	greatest <= asOf.Sequence). This is the same monotonic-asOf
	contract LocalTrust honors via SingleLog.

LAW 4 (BURN FAIL-CLOSED)

	If the journal reports the log as burned (monitoring.
	ErrEquivocatedLog), TrustRoot wraps + returns it. The walker
	treats the wrap as a hard verification failure; no asOf can
	resolve a burned log to a clean head until governance re-
	establishes a clean trust root (out-of-band, per Decision 5).

KEY ARCHITECTURAL DECISIONS

  - Constructor takes the journal + the foreign WitnessKeySet map +
    the home LocalTrust. Each input is JN-local; nothing crosses a
    network boundary at construction time (matching the
    Separation of Duties posture of the rest of the trust topology).

  - foreignSets is keyed by foreign LogDID; a lookup miss for a
    DID that is neither the home LogDID nor in the foreign map
    returns ErrUnknownLog (the fail-closed sentinel).

  - Compile-time interface check at package init makes accidental
    drift surface at build time, not test time.
*/
package trust

import (
	"context"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"

	"github.com/baseproof/tooling/libs/monitoring"
)

// ErrMultiTrustConfig is the sentinel wrapping any constructor-time
// misconfiguration (zero home LogDID, nil journal, nil witness set
// for a declared foreign log). errors.Is-friendly so call sites can
// distinguish wiring faults from runtime trust failures.
var ErrMultiTrustConfig = errors.New("verification/trust: MultiJurisdictionTrust misconfigured")

// ForeignEntryResolver resolves entries on a FOREIGN log along
// with their inclusion proofs to the foreign log's tree root.
// Implementations might wrap a Static-CT tile mirror, the source
// log's /raw endpoint paired with a tile fetcher, or a hand-curated
// test fixture. MultiJurisdictionTrust does not interpret or
// validate the returned proof — the SDK walker's
// EvaluateAuthorityWithTrust verifies the proof against
// TrustRoot.Head.RootHash, fail-closed via ErrInclusionInvalid on
// any tampering.
//
// The asOf parameter is forwarded verbatim from the LogTrustProvider.
// Entry call; implementations honor it the same way TrustRoot does
// (asOf={} = "latest"; non-zero pins to a historical head).
type ForeignEntryResolver interface {
	EntryAt(ctx context.Context, pos types.LogPosition, asOf verifier.AsOf) (verifier.EntryProof, error)
}

// ForeignLeafResolver resolves SMT leaves on a FOREIGN log along
// with their membership proofs. Same posture as
// ForeignEntryResolver — the walker verifies the proof against
// TrustRoot.Head.SMTRoot, fail-closed via ErrLeafProofInvalid on
// any tampering.
type ForeignLeafResolver interface {
	LeafAt(ctx context.Context, logDID string, key [32]byte, asOf verifier.AsOf) (verifier.LeafProof, error)
}

// MultiJurisdictionTrust is the LogTrustProvider for cross-network
// evaluation. It dispatches LogDID-keyed: the home log delegates to
// an embedded LocalTrust; each foreign log resolves its trust root
// from the shared HeadsJournal + its pre-declared WitnessKeySet.
// Unknown logs return ErrUnknownLog (fail-closed).
type MultiJurisdictionTrust struct {
	// home is the JN's own log. Entry / Leaf calls for homeLogDID
	// delegate to local.
	homeLogDID string
	local      LocalTrust

	// foreignEntries is logDID → ForeignEntryResolver for foreign
	// logs that have an Entry-resolution backend wired (a Static-CT
	// tile mirror, an HTTP /raw fetcher pair, or a test fixture).
	// nil for a logDID ⇒ Entry calls return ErrUnknownLog (the C-3
	// TrustRoot-first default; call sites then pass inclusion
	// proofs in their request payload). Populated via
	// WithForeignEntries.
	foreignEntries map[string]ForeignEntryResolver

	// foreignLeaves is logDID → ForeignLeafResolver. Same posture
	// as foreignEntries, for SMT leaf reads. Populated via
	// WithForeignLeaves.
	foreignLeaves map[string]ForeignLeafResolver

	// foreignSets is logDID → *cosign.WitnessKeySet for every
	// foreign log declared in cfg.GossipIngest.PeerLogs. The
	// keyset is the pre-bound (witness keys + K + foreign
	// NetworkID) shape gossipverify hands to the foreign
	// reconciler — re-used here so the trust-root surface and
	// the verification surface use the same crypto inputs.
	foreignSets map[string]*cosign.WitnessKeySet

	// journal is the shared HeadsJournal — populated by the
	// multi-network gossip ingest pipelines, written through on
	// every verified CosignedTreeHeadFinding (home + foreign).
	// TrustRoot reads journal.HeadAt / LatestHead to resolve a
	// foreign log's head at the requested asOf.
	journal monitoring.HeadsJournal
}

// NewMultiJurisdictionTrust constructs a MultiJurisdictionTrust from
// its three JN-local inputs:
//
//   - home: the LocalTrust the home log already uses (preserves
//     byte-for-byte parity at homeLogDID).
//   - homeLogDID: the JN's home log DID (the dispatch key).
//   - foreignSets: logDID → *cosign.WitnessKeySet for every
//     foreign log declared in cfg.GossipIngest.PeerLogs. Each
//     keyset MUST be bound to the FOREIGN NetworkID (the same
//     binding the foreign gossip pipeline's GossipVerifier uses).
//   - journal: the shared HeadsJournal the multi-network ingest
//     writes through. nil disables foreign-log TrustRoot
//     resolution (every foreign lookup returns ErrUnknownLog).
//
// Returns ErrMultiTrustConfig if homeLogDID is empty or if any
// declared foreign log has a nil keyset (mis-declared trust
// topology — a foreign log without a witness set could not be
// verified against, so building one would be a deferred
// fail-closed that the caller has no good way to detect).
func NewMultiJurisdictionTrust(
	home LocalTrust,
	homeLogDID string,
	foreignSets map[string]*cosign.WitnessKeySet,
	journal monitoring.HeadsJournal,
) (MultiJurisdictionTrust, error) {
	if homeLogDID == "" {
		return MultiJurisdictionTrust{}, fmt.Errorf("%w: homeLogDID is empty", ErrMultiTrustConfig)
	}
	// Defensive copy of the foreign map so callers can mutate
	// theirs without affecting the trust provider's view (and so
	// a nil input is not a panic).
	fs := make(map[string]*cosign.WitnessKeySet, len(foreignSets))
	for did, ws := range foreignSets {
		if ws == nil {
			return MultiJurisdictionTrust{}, fmt.Errorf(
				"%w: nil WitnessKeySet for foreign log %q", ErrMultiTrustConfig, did)
		}
		if did == homeLogDID {
			// A foreign entry that collides with the home LogDID would
			// shadow the home backend at runtime (the foreign witness
			// set would override LocalTrust's resolution). Fail boot.
			return MultiJurisdictionTrust{}, fmt.Errorf(
				"%w: foreign log DID %q collides with homeLogDID", ErrMultiTrustConfig, did)
		}
		fs[did] = ws
	}
	return MultiJurisdictionTrust{
		homeLogDID:  homeLogDID,
		local:       home,
		foreignSets: fs,
		journal:     journal,
	}, nil
}

// TrustRoot dispatches by logDID. For the home log it delegates to
// LocalTrust verbatim (byte-for-byte parity preserved). For a
// foreign log it resolves the cosigned head from the journal at the
// requested asOf and pairs it with the pre-declared WitnessKeySet.
// Unknown logs return ErrUnknownLog (the SDK sentinel; the walker
// fail-closes).
//
// asOf semantics:
//
//   - AsOf{} (zero) → "latest known head" via journal.LatestHead.
//   - AsOf with Sequence > 0 → journal.HeadAt(logDID, Sequence)
//     (the head whose sequence is the greatest <= the requested
//     asOf.Sequence — monotonic-asOf contract).
//
// LAW 4: if the journal reports the log as burned (ErrEquivocated
// Log), the error is wrapped and returned. No asOf can resolve a
// burned log; governance must re-establish a clean trust root
// (out-of-band, per Decision 5).
func (m MultiJurisdictionTrust) TrustRoot(
	ctx context.Context,
	logDID string,
	asOf verifier.AsOf,
) (verifier.TrustRoot, error) {
	if logDID == m.homeLogDID {
		// ZT-IMM-01 (baseproof v1.43.0): the home log resolves a journaled,
		// VERIFIED cosigned head too — not LocalTrust's head-agnostic zero
		// head — so ResolveLatest and the per-hop walks can pin an exact head
		// (RootHash mandatory). The home reconciler journals home heads, so
		// they are available here; Entry/Leaf still read the home backend via
		// m.local below. With no journal wired we fall back to LocalTrust
		// (head-agnostic; the v1.43.0 head-bearing paths then fail closed).
		if m.journal == nil {
			return m.local.TrustRoot(ctx, logDID, asOf)
		}
		head, err := m.resolveHead(ctx, logDID, asOf)
		if err != nil {
			return verifier.TrustRoot{}, err
		}
		return verifier.TrustRoot{
			Head: types.CosignedTreeHead{
				TreeHead:   head.TreeHead,
				Signatures: head.Signatures,
			},
		}, nil
	}
	ws, ok := m.foreignSets[logDID]
	if !ok {
		return verifier.TrustRoot{}, verifier.ErrUnknownLog
	}
	if m.journal == nil {
		// Foreign log declared but no journal → no way to resolve a
		// head. Fail closed.
		return verifier.TrustRoot{}, verifier.ErrUnknownLog
	}

	head, err := m.resolveHead(ctx, logDID, asOf)
	if err != nil {
		// monitoring.ErrEquivocatedLog and monitoring.ErrNoHead are
		// both routed through here — both are fail-closed signals.
		// The walker sees the wrapped error and reports the failure;
		// the wrap keeps the structured cause discoverable via
		// errors.Is.
		return verifier.TrustRoot{}, err
	}
	return verifier.TrustRoot{
		WitnessSet: ws,
		Head: types.CosignedTreeHead{
			TreeHead:   head.TreeHead,
			Signatures: head.Signatures,
		},
	}, nil
}

// resolveHead reads the journal at the requested asOf. AsOf{}
// (zero) means "latest"; non-zero means HeadAt(asOf.Sequence).
// Errors propagate verbatim (ErrEquivocatedLog, ErrNoHead).
func (m MultiJurisdictionTrust) resolveHead(
	ctx context.Context,
	logDID string,
	asOf verifier.AsOf,
) (monitoring.Head, error) {
	if asOf.Sequence == 0 {
		return m.journal.LatestHead(ctx, logDID)
	}
	return m.journal.HeadAt(ctx, logDID, asOf.Sequence)
}

// Entry dispatches by pos.LogDID. The home log delegates to
// LocalTrust verbatim. A foreign log dispatches to the wired
// ForeignEntryResolver (if any), which returns the entry + its
// inclusion proof against the foreign log's tree root; the SDK
// walker then verifies the proof against TrustRoot.Head.RootHash
// (fail-closed via ErrInclusionInvalid on any tampering — the C-5
// forged-proof scenario). A declared foreign log with NO resolver
// wired (or an UNKNOWN log) returns ErrUnknownLog.
func (m MultiJurisdictionTrust) Entry(
	ctx context.Context,
	pos types.LogPosition,
	asOf verifier.AsOf,
) (verifier.EntryProof, error) {
	if pos.LogDID == m.homeLogDID {
		return m.local.Entry(ctx, pos, asOf)
	}
	if resolver, ok := m.foreignEntries[pos.LogDID]; ok && resolver != nil {
		return resolver.EntryAt(ctx, pos, asOf)
	}
	return verifier.EntryProof{}, verifier.ErrUnknownLog
}

// Leaf dispatches by logDID. The home log delegates to LocalTrust
// verbatim. A foreign log dispatches to the wired
// ForeignLeafResolver (if any); the walker verifies the membership
// proof against TrustRoot.Head.SMTRoot (fail-closed via
// ErrLeafProofInvalid on tampering). No wired resolver ⇒
// ErrUnknownLog.
func (m MultiJurisdictionTrust) Leaf(
	ctx context.Context,
	logDID string,
	key [32]byte,
	asOf verifier.AsOf,
) (verifier.LeafProof, error) {
	if logDID == m.homeLogDID {
		return m.local.Leaf(ctx, logDID, key, asOf)
	}
	if resolver, ok := m.foreignLeaves[logDID]; ok && resolver != nil {
		return resolver.LeafAt(ctx, logDID, key, asOf)
	}
	return verifier.LeafProof{}, verifier.ErrUnknownLog
}

// WithForeignEntries returns a new MultiJurisdictionTrust with the
// supplied per-log Entry resolvers wired. The original is unchanged
// (the provider is immutable; this is the additive-extension
// pattern). A nil map clears any existing resolvers.
//
// Resolvers MUST be supplied only for LogDIDs declared in
// foreignSets at construction time; resolvers for unknown LogDIDs
// are accepted but never dispatched to (a logDID dispatch first
// matches against foreignSets via TrustRoot; an unknown LogDID
// short-circuits to ErrUnknownLog from TrustRoot before Entry is
// ever called by the walker).
func (m MultiJurisdictionTrust) WithForeignEntries(resolvers map[string]ForeignEntryResolver) MultiJurisdictionTrust {
	cp := make(map[string]ForeignEntryResolver, len(resolvers))
	for did, r := range resolvers {
		cp[did] = r
	}
	m.foreignEntries = cp
	return m
}

// WithForeignLeaves returns a new MultiJurisdictionTrust with the
// supplied per-log Leaf resolvers wired. Same semantics as
// WithForeignEntries.
func (m MultiJurisdictionTrust) WithForeignLeaves(resolvers map[string]ForeignLeafResolver) MultiJurisdictionTrust {
	cp := make(map[string]ForeignLeafResolver, len(resolvers))
	for did, r := range resolvers {
		cp[did] = r
	}
	m.foreignLeaves = cp
	return m
}

// Compile-time check that MultiJurisdictionTrust satisfies the SDK
// interface. If the SDK ever changes the interface shape, this
// fails at build.
var _ verifier.LogTrustProvider = MultiJurisdictionTrust{}
