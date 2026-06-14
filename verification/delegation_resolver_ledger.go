/*
FILE PATH: verification/delegation_resolver_ledger.go

DESCRIPTION:

	LedgerDelegationResolver is JN's read-time concrete impl of the
	SDK's attestation.DelegationResolver interface. Walks the
	delegation chain for a given signer DID by repeated calls to
	the ledger's /v1/query/delegate_did/{did} endpoint, packaging
	the result as an attestation.DelegationChain.

	# WALK ALGORITHM

	Given signerDID:

	  1. did := signerDID
	  2. entries := delegateQuerier.QueryByDelegateDID(did)
	     - empty → chain ends (did is a root authority or has no
	       incoming delegation); return what we have.
	  3. Take entries[0] — the newest delegation TO did (DESC by
	     sequence). Its sequence is THIS DID's per-DID watermark.
	  4. Per-hop cache: if cache.Get(did, watermark) hits, reuse the
	     hop and skip 4a–5; else hydrate the canonical bytes via the
	     fetcher (4a) and build the hop.
	  5. Build DelegationHop:
	       DelegateDID  = did                                (loop variable)
	       DelegatorDID = entry.Header.SignerDID             (who signed this hop)
	       Scopes       = scopeExtractor(entry) — optional   (domain payload)
	       Live         = NOT a revocation/succession tip    (newest-grant-wins)
	     then cache.Set(did, hop, watermark). A not-live hop ends the chain.
	  6. did := DelegatorDID
	  7. cycle check (did already in visited set) → break.
	  8. depth check (len(hops) >= maxDepth) → break.
	  9. goto 2.

	# SCOPE EXTRACTION

	Scopes come from the delegation entry's DomainPayload, which is
	schema-specific. The resolver takes a ScopeExtractor function;
	when nil, Scopes is left empty (the SDK's RequiredScopes
	evaluator interprets empty as "delegate inherits parent's
	scopes in full"). Production wiring can supply a JN-schema-
	aware extractor; tests can leave nil.

	# CACHING (per-hop, log-sequence-revalidated — no TTL)

	The cache is PER-HOP, keyed by delegate DID and revalidated by that
	DID's per-DID watermark (entries[0].Sequence — the newest delegation to
	it), via SeqRevalidatingCache (exact match). Every resolve still issues
	the cheap QueryByDelegateDID metadata seek per hop, so the walk is always
	current-to-commit; a hit only skips the expensive part — the canonical-
	bytes hydrate + decode — for a DID whose watermark is unchanged. A new
	grant or a revocation moves the watermark and forces a re-walk of that hop
	(never-stale; Verify-Live-State). There is no whole-chain shortcut and no
	timer. InvalidateDID forces a per-DID miss.

KEY DEPENDENCIES:
  - baseproof v1.5.1 attestation.DelegationResolver, DelegationChain,
    DelegationHop (target interface)
  - baseproof v1.5.1 core/envelope.Deserialize (to read SignerDID
    from canonical bytes)
  - SeqRevalidatingCache (this package's per-hop log-sequence cache)
  - tipWithdrawsAuthority (newest-grant-wins liveness; authority_resolver_origin.go)
  - DelegateDIDQuerier (this package's HTTP shim)
  - types.EntryFetcher (the SDK seam; production wires
    sdklog.HTTPEntryFetcher)
*/
package verification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/types"
)

// ErrLedgerDelegationResolver is the umbrella sentinel for every
// error this resolver surfaces. Callers errors.Is(err, ...) for
// routing.
var ErrLedgerDelegationResolver = errors.New("verification/delegation_resolver_ledger")

// defaultMaxDelegationDepth bounds the walk. Judicial delegation
// chains are typically 1-3 hops (e.g., Network Authority →
// Judicial Officer → Delegated Magistrate). 32 leaves substantial
// headroom while preventing pathological cycles or hostile
// chain-extension from exhausting our HTTP budget.
const defaultMaxDelegationDepth = 32

// ScopeExtractor pulls the declared scope set from a delegation
// entry's canonical bytes. Domain-specific; nil is acceptable (the
// resolver leaves Scopes empty, which the SDK constraint evaluator
// reads as "delegate inherits the parent's scopes in full").
type ScopeExtractor func(entry *envelope.Entry) []string

// LedgerDelegationResolverConfig configures the resolver.
type LedgerDelegationResolverConfig struct {
	// Delegate is the JN HTTP shim for /v1/query/delegate_did.
	// Required.
	Delegate DelegateDIDQuerier

	// Fetcher hydrates each delegation entry's canonical bytes
	// (required to read Header.SignerDID — the DelegatorDID of
	// the hop). Required.
	Fetcher types.EntryFetcher

	// LogDID is the log being walked. Used to build LogPosition
	// when calling Fetcher.Fetch. Required.
	LogDID string

	// Scope, optional. When nil, Hop.Scopes is left empty.
	Scope ScopeExtractor

	// Role, optional. Extracts the role a delegation grants, for the
	// AuthorityVerdict's role-at-tip. Nil → empty role (structural use).
	Role func(entry *envelope.Entry) string

	// Expiry, optional. Extracts a delegation's expiry (ok=false when none is
	// declared). Nil → no expiry check. The judicial gate wires
	// JudicialHopExpiry so the verdict rejects an expired hop — parity with
	// AuthorityResolver, which rejects any chain whose hops have expired.
	Expiry func(entry *envelope.Entry) (at time.Time, ok bool)

	// Now overrides the expiry clock (tests). Nil → time.Now.
	Now func() time.Time

	// MaxDepth bounds the walk. Default defaultMaxDelegationDepth.
	MaxDepth int
}

// richHop is the full per-hop result of the shared index-walk: the structural
// fields the SDK DelegationChain needs PLUS the role + expiry the
// AuthorityVerdict needs. One walk, two projections (ResolveChain → chain,
// Resolve → verdict) — the single index-walk seam (no duplicated walk loop).
type richHop struct {
	delegateDID  string
	delegatorDID string
	role         string
	scopes       []string
	expiresAt    time.Time
	hasExpiry    bool
	live         bool
}

// LedgerDelegationResolver implements attestation.DelegationResolver
// against a JN-side cached projection of the ledger's
// delegate_did query.
type LedgerDelegationResolver struct {
	delegate DelegateDIDQuerier
	fetcher  types.EntryFetcher
	logDID   string
	scope    ScopeExtractor
	role     func(*envelope.Entry) string
	expiry   func(*envelope.Entry) (time.Time, bool)
	now      func() time.Time
	maxDepth int
	// cache is a PER-HOP cache keyed by delegate DID, revalidated by that
	// DID's newest-delegation sequence (the per-DID watermark). It replaces
	// the old whole-chain TTL cache: no timer, never-stale — a new grant or a
	// revocation for a DID moves its watermark, so the exact-match Get misses
	// and that hop is re-walked.
	cache *SeqRevalidatingCache[richHop]
}

// NewLedgerDelegationResolver constructs the resolver. Returns
// ErrLedgerDelegationResolver wrapping a precise sub-cause if cfg
// is malformed.
func NewLedgerDelegationResolver(cfg LedgerDelegationResolverConfig) (*LedgerDelegationResolver, error) {
	if cfg.Delegate == nil {
		return nil, fmt.Errorf("%w: Delegate (DelegateDIDQuerier) required", ErrLedgerDelegationResolver)
	}
	if cfg.Fetcher == nil {
		return nil, fmt.Errorf("%w: Fetcher (types.EntryFetcher) required", ErrLedgerDelegationResolver)
	}
	if cfg.LogDID == "" {
		return nil, fmt.Errorf("%w: LogDID required", ErrLedgerDelegationResolver)
	}
	maxDepth := cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxDelegationDepth
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &LedgerDelegationResolver{
		delegate: cfg.Delegate,
		fetcher:  cfg.Fetcher,
		logDID:   cfg.LogDID,
		scope:    cfg.Scope,
		role:     cfg.Role,
		expiry:   cfg.Expiry,
		now:      now,
		maxDepth: maxDepth,
		cache:    NewSeqRevalidatingCache[richHop](),
	}, nil
}

// ResolveChain walks the delegation graph from signerDID toward a
// root authority and returns the chain. Implements
// attestation.DelegationResolver.
//
// An empty signerDID returns an empty chain (not an error) — the
// SDK constraint evaluator interprets that as "no chain to walk"
// and rejects via ErrConstraintChainRevoked / similar.
//
// The walk re-checks every DID's per-DID watermark each call (cheap
// metadata seeks), so it is always current-to-commit; the per-hop cache
// only skips the canonical-bytes hydrate + decode for DIDs whose
// watermark is unchanged. There is no whole-chain shortcut and no TTL.
func (r *LedgerDelegationResolver) ResolveChain(
	ctx context.Context, signerDID string,
) (attestation.DelegationChain, error) {
	if signerDID == "" {
		return attestation.DelegationChain{}, nil
	}
	hops, _, err := r.walk(ctx, signerDID)
	if err != nil {
		return attestation.DelegationChain{}, err
	}
	out := make([]attestation.DelegationHop, len(hops))
	for i, h := range hops {
		out[i] = attestation.DelegationHop{
			DelegateDID:  h.delegateDID,
			DelegatorDID: h.delegatorDID,
			Scopes:       h.scopes,
			Live:         h.live,
		}
	}
	return attestation.DelegationChain{Hops: out}, nil
}

// InvalidateDID drops the cached hop for did. The per-DID watermark makes
// this rarely necessary (a grant/revocation moves the watermark and forces a
// miss on its own), but a caller with out-of-band knowledge may force it.
func (r *LedgerDelegationResolver) InvalidateDID(did string) {
	r.cache.Invalidate(did)
}

// walk does the chain construction shared by ResolveChain and Resolve. It
// returns the rich hops plus `complete` — true iff the walk reached a root (an
// empty delegate query), false if it stopped early (a not-live hop, the depth
// cap, a cycle, or a signer-less entry). At each hop it re-checks the DID's
// per-DID watermark (entries[0].Sequence) against the per-hop cache: a
// watermark match reuses the cached hop and skips the hydrate + decode; any
// change re-walks. Liveness is newest-grant-wins: a revocation/succession
// surfaced as entries[0] (#120) marks the hop not-live and ends the chain.
func (r *LedgerDelegationResolver) walk(
	ctx context.Context, signerDID string,
) ([]richHop, bool, error) {
	visited := make(map[string]struct{}, r.maxDepth)
	hops := make([]richHop, 0, 4)
	did := signerDID

	for i := 0; i < r.maxDepth; i++ {
		if _, seen := visited[did]; seen {
			return hops, false, nil // cycle — not a clean root
		}
		visited[did] = struct{}{}

		entries, err := r.delegate.QueryByDelegateDID(ctx, did)
		if err != nil {
			return nil, false, fmt.Errorf(
				"%w: delegate query for %q: %w",
				ErrLedgerDelegationResolver, did, err,
			)
		}
		if len(entries) == 0 {
			return hops, true, nil // reached a root (no incoming delegation)
		}

		// entries[0] is newest (ledger returns DESC). Its sequence is THIS
		// DID's per-DID watermark — the revalidation fingerprint. A cache hit
		// at this watermark reuses the hop and skips the canonical-bytes fetch
		// + decode; any change (new grant raises it, a revocation that drops
		// the newest grant lowers it) is an exact-match miss → re-walk.
		newest := entries[0]
		fp := newest.Position.Sequence
		if hop, ok := r.cache.Get(did, fp); ok {
			hops = append(hops, hop)
			if !hop.live {
				return hops, false, nil // a revocation/succession withdrew authority
			}
			did = hop.delegatorDID
			continue
		}

		hydrated, err := r.fetcher.Fetch(ctx, newest.Position)
		if err != nil {
			return nil, false, fmt.Errorf(
				"%w: hydrate entry %s: %w",
				ErrLedgerDelegationResolver, newest.Position, err,
			)
		}
		if hydrated == nil || hydrated.CanonicalBytes == nil {
			return nil, false, fmt.Errorf(
				"%w: fetcher returned no bytes for %s",
				ErrLedgerDelegationResolver, newest.Position,
			)
		}
		entry, err := envelope.Deserialize(hydrated.CanonicalBytes)
		if err != nil {
			return nil, false, fmt.Errorf(
				"%w: deserialize entry %s: %w",
				ErrLedgerDelegationResolver, newest.Position, err,
			)
		}

		delegator := entry.Header.SignerDID
		if delegator == "" {
			return hops, false, nil // malformed: a signer-less entry can't be a hop
		}

		// Newest-grant-wins liveness: the index surfaces a revocation or
		// succession as entries[0] (delegate_did.go, #120). A withdrawing tip
		// → not-live → the chain ends here, no SMT read (the gate trusts the
		// projection; the EvaluateOrigin lane stays for the external auditor).
		hop := richHop{
			delegateDID:  did,
			delegatorDID: delegator,
			live:         !tipWithdrawsAuthority(entry.DomainPayload),
		}
		if r.scope != nil {
			hop.scopes = r.scope(entry)
		}
		if r.role != nil {
			hop.role = r.role(entry)
		}
		if r.expiry != nil {
			hop.expiresAt, hop.hasExpiry = r.expiry(entry)
		}
		r.cache.Set(did, hop, fp)
		hops = append(hops, hop)
		if !hop.live {
			return hops, false, nil
		}
		did = delegator
	}

	return hops, false, nil // depth cap reached — chain not completed to a root
}

// Compile-time pin: the resolver implements the SDK interface.
var _ attestation.DelegationResolver = (*LedgerDelegationResolver)(nil)
