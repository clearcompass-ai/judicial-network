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
	  3. Take entries[0] — the newest live delegation TO did.
	     The ledger returns DESC by sequence; the SDK's
	     constraint evaluator wants the most recent grant.
	  4. Hydrate entry's canonical bytes via the fetcher.
	  5. Build DelegationHop:
	       DelegateDID  = did                                (loop variable)
	       DelegatorDID = entry.Header.SignerDID             (who signed this hop)
	       Scopes       = scopeExtractor(entry) — optional   (domain payload)
	       Live         = true                               (ledger filters live)
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

	# CACHING

	The resolver caches each (signerDID → DelegationChain) result
	for a caller-chosen TTL. Cache misses incur N HTTP round-trips
	to the ledger (where N == chain depth, typically 1-3 for
	judicial structures). Cache hits are O(1).

	The cache lives at the resolver level (not per-call) so the SDK
	stage runner sees a fast resolver. Invalidation is via TTL only;
	callers with external knowledge of revocation can call
	InvalidateDID.

KEY DEPENDENCIES:
  - attesta v1.5.1 attestation.DelegationResolver, DelegationChain,
    DelegationHop (target interface)
  - attesta v1.5.1 core/envelope.Deserialize (to read SignerDID
    from canonical bytes)
  - verification/policycache (TTL cache)
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

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/verification/policycache"
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

// defaultDelegationCacheTTL is a conservative bound. JN's read-time
// gate workload reads each delegation a few times per case;
// 60s lets bursts batch while keeping the view fresh enough for
// real-time use cases. Callers with tighter freshness needs override
// via LedgerDelegationResolverConfig.CacheTTL.
const defaultDelegationCacheTTL = 60 * time.Second

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

	// MaxDepth bounds the walk. Default defaultMaxDelegationDepth.
	MaxDepth int

	// CacheTTL bounds per-DID cache freshness. Default 60s. Set
	// to <=0 to disable caching (every resolve hits the ledger).
	CacheTTL time.Duration
}

// LedgerDelegationResolver implements attestation.DelegationResolver
// against a JN-side cached projection of the ledger's
// delegate_did query.
type LedgerDelegationResolver struct {
	delegate DelegateDIDQuerier
	fetcher  types.EntryFetcher
	logDID   string
	scope    ScopeExtractor
	maxDepth int
	cacheTTL time.Duration
	cache    *policycache.Cache[attestation.DelegationChain]
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
	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = defaultDelegationCacheTTL
	}
	return &LedgerDelegationResolver{
		delegate: cfg.Delegate,
		fetcher:  cfg.Fetcher,
		logDID:   cfg.LogDID,
		scope:    cfg.Scope,
		maxDepth: maxDepth,
		cacheTTL: ttl,
		cache:    policycache.New[attestation.DelegationChain](),
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
// Cache hits skip the entire walk. Cache misses do up to MaxDepth
// HTTP round-trips; partial chains (cycle or depth break) are
// cached anyway so a hostile cycle doesn't repeatedly burn the
// ledger.
func (r *LedgerDelegationResolver) ResolveChain(
	ctx context.Context, signerDID string,
) (attestation.DelegationChain, error) {
	if signerDID == "" {
		return attestation.DelegationChain{}, nil
	}
	if chain, ok := r.cache.Get(signerDID); ok {
		return chain, nil
	}
	chain, err := r.walk(ctx, signerDID)
	if err != nil {
		return attestation.DelegationChain{}, err
	}
	// Cache the result — even partial chains caused by cycle or
	// depth limit. This prevents repeated re-walks of pathological
	// inputs from exhausting the resolver's HTTP budget.
	if r.cacheTTL > 0 {
		r.cache.Set(signerDID, chain, r.cacheTTL)
	}
	return chain, nil
}

// InvalidateDID clears the cached chain for did. Callers with
// out-of-band knowledge of a revocation (e.g., a gossip event)
// call this to bypass TTL.
func (r *LedgerDelegationResolver) InvalidateDID(did string) {
	r.cache.Delete(did)
}

// walk does the actual chain construction; see file docblock for
// the algorithm. Caller has already done the cache check; walk
// always issues HTTP requests.
func (r *LedgerDelegationResolver) walk(
	ctx context.Context, signerDID string,
) (attestation.DelegationChain, error) {
	visited := make(map[string]struct{}, r.maxDepth)
	hops := make([]attestation.DelegationHop, 0, 4)
	did := signerDID

	for i := 0; i < r.maxDepth; i++ {
		if _, seen := visited[did]; seen {
			// Cycle. Return what we have so the SDK can decide.
			break
		}
		visited[did] = struct{}{}

		entries, err := r.delegate.QueryByDelegateDID(ctx, did)
		if err != nil {
			return attestation.DelegationChain{}, fmt.Errorf(
				"%w: delegate query for %q: %w",
				ErrLedgerDelegationResolver, did, err,
			)
		}
		if len(entries) == 0 {
			// No incoming delegation — this DID is a root or has
			// no entry binding it. Chain ends here.
			break
		}

		// entries[0] is newest (ledger returns DESC). Hydrate its
		// canonical bytes so we can read Header.SignerDID and (if
		// a scope extractor is wired) the DomainPayload scopes.
		newest := entries[0]
		hydrated, err := r.fetcher.Fetch(ctx, newest.Position)
		if err != nil {
			return attestation.DelegationChain{}, fmt.Errorf(
				"%w: hydrate entry %s: %w",
				ErrLedgerDelegationResolver, newest.Position, err,
			)
		}
		if hydrated == nil || hydrated.CanonicalBytes == nil {
			return attestation.DelegationChain{}, fmt.Errorf(
				"%w: fetcher returned no bytes for %s",
				ErrLedgerDelegationResolver, newest.Position,
			)
		}
		entry, err := envelope.Deserialize(hydrated.CanonicalBytes)
		if err != nil {
			return attestation.DelegationChain{}, fmt.Errorf(
				"%w: deserialize entry %s: %w",
				ErrLedgerDelegationResolver, newest.Position, err,
			)
		}

		delegator := entry.Header.SignerDID
		if delegator == "" {
			// Defensive: entry without a signer can't be in a real
			// chain. Stop the walk at this hop rather than emit a
			// nonsense hop.
			break
		}

		var scopes []string
		if r.scope != nil {
			scopes = r.scope(entry)
		}

		hops = append(hops, attestation.DelegationHop{
			DelegateDID:  did,
			DelegatorDID: delegator,
			Scopes:       scopes,
			Live:         true, // ledger's delegate_did filters live entries
		})

		did = delegator
	}

	return attestation.DelegationChain{Hops: hops}, nil
}

// Compile-time pin: the resolver implements the SDK interface.
var _ attestation.DelegationResolver = (*LedgerDelegationResolver)(nil)
