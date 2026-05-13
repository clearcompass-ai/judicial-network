/*
FILE PATH: verification/delegation_chain.go

DESCRIPTION:

	Delegation chain verification for a specific filing. Supports
	TWO complementary walking models from the attesta SDK:

	  - BY-POINTER (legacy, v0.x): VerifyFilingDelegation walks an
	    explicit DelegationPointers slice carried on the filing's
	    Header. The chain is GIVEN; the verifier confirms each hop's
	    cryptographic liveness via verifier.VerifyDelegationProvenance.

	  - BY-DID (v1.2.0+): ResolveDelegationByDID walks UP from a
	    leaf signer's DID through repeated EntrySource lookups via
	    the SDK's delegation.Resolver. The chain is DISCOVERED;
	    cycle detection and bounded max-depth (default 32) live
	    inside the SDK resolver. Returns an
	    attestation.DelegationChain — the shape consumed by
	    attestation.EvaluateConstraint and
	    attestation.VerifyEntryAttestationPolicy for
	    DelegationOriginDID / RequiredScopes evaluation.

	Both walks have valid use cases. By-pointer is faster when the
	caller already holds the chain (typical for filings carrying
	DelegationPointers). By-DID is necessary when only the leaf
	DID is known (audit tools, recursive authority lookups,
	attestation policy enforcement).

	# TWO PHASES (BY-POINTER MODEL)

	  Phase 1 - cryptographic provenance: walks DelegationPointers
	            linearly via the SDK's VerifyDelegationProvenance.
	            Confirms each hop's delegation is live and the
	            chain connects.
	  Phase 2 - semantic scope authority: walks the same chain via
	            verification.ScopeEnforcer to confirm the target
	            entry's SchemaRef is permitted by every delegation's
	            scope_limit (the read-side defense against the
	            Compromised-Subordinate-Key attack documented in
	            attesta/docs/implementation-obligations.md).

KEY ARCHITECTURAL DECISIONS:
  - SDK correction #1: VerifyDelegationProvenance (linear walk) NOT
    WalkDelegationTree (BFS). VerifyDelegationProvenance is the
    correct primitive for single-chain by-pointer verification.
  - Two-phase pattern: cryptographic before semantic. A chain that
    fails cryptographically MUST short-circuit before any payload is
    deserialized — the SDK layer is the trust boundary that gates
    whether DomainPayload is worth inspecting at all.
  - VerifyFilingDelegation accepts an optional *ScopeEnforcer. nil
    preserves the pre-Wave-1 behavior (cryptographic only) for
    callers that don't yet have a SchemaResolver wired. Passing a
    non-nil enforcer activates the semantic phase. The intent is
    every production caller passes one; the optionality is a
    migration aid, not a permanent escape hatch.
  - ResolveDelegationByDID is the new (v1.2.0) by-DID entry point.
    Composes with attestation.EvaluateConstraint and
    attestation.VerifyEntryAttestationPolicy without re-implementing
    the walker. JN supplies the EntrySource via
    verification.NewFuncEntrySource (delegation_source.go).

OVERVIEW:

	VerifyFilingDelegation → *DelegationVerification with both
	  cryptographic liveness AND scope_limit verdicts surfaced
	  (by-pointer model).
	ResolveDelegationByDID → attestation.DelegationChain via the
	  SDK's by-DID resolver (v1.2.0+).

KEY DEPENDENCIES:
  - attesta/verifier (VerifyDelegationProvenance) — by-pointer path
  - attesta/attestation (DelegationChain, DelegationHop,
    DelegationResolver) — by-DID return shape (v1.2.0+)
  - attesta/delegation (Resolver, Option) — by-DID walker (v1.2.0+)
  - attesta/core/envelope, types, smt
  - judicial-network/verification (ScopeEnforcer, FuncEntrySource)
*/
package verification

import (
	"context"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	sdkdelegation "github.com/clearcompass-ai/attesta/delegation"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// DelegationVerification carries the result of both verification
// phases. Callers inspect AllLive (cryptographic) AND ScopeOK
// (semantic) — both must be true for the entry to be authoritative.
type DelegationVerification struct {
	// Cryptographic phase output.
	Hops      []verifier.DelegationHop
	AllLive   bool
	Depth     int
	FirstDead *types.LogPosition

	// Semantic phase output. ScopeChecked is true iff a
	// non-nil ScopeEnforcer was passed; ScopeOK is true iff the
	// target entry's SchemaRef passed every hop's scope_limit. When
	// ScopeChecked is false, ScopeOK and ScopeViolation are zero.
	ScopeChecked   bool
	ScopeOK        bool
	ScopeViolation *ScopeViolation
}

// VerifyFilingDelegation verifies the delegation chain for a specific
// filing in two phases.  is the SDK's cryptographic provenance
// walk.  (only if scopeEnforcer is non-nil and target is
// non-nil) is the domain's scope_limit check against the target's
// SchemaRef.
//
//	short-circuits : if any hop fails cryptographically,
//
// scope_limit checks do not run. The cryptographic phase is the trust
// boundary for whether DomainPayload is worth deserializing.
//
// A nil scopeEnforcer or nil target preserves -only behavior.
// Production callers SHOULD pass both.
func VerifyFilingDelegation(
	ctx context.Context,
	delegationPointers []types.LogPosition,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
	scopeEnforcer *ScopeEnforcer,
	target *envelope.Entry,
) (*DelegationVerification, error) {
	if len(delegationPointers) == 0 {
		// No chain — Path A or commentary. Both phases vacuously OK.
		return &DelegationVerification{
			AllLive:      true,
			ScopeChecked: scopeEnforcer != nil && target != nil,
			ScopeOK:      scopeEnforcer != nil && target != nil,
		}, nil
	}

	// : cryptographic provenance.
	//
	// At the pinned SDK commit (v7.75/d6b9792),
	// verifier.VerifyDelegationProvenance never surfaces fetcher or
	// deserialize errors as a returned error — they collapse to
	// IsLive=false on the affected hop. We reflect that contract
	// here. If a future SDK pin changes the contract to return an
	// error, this call site needs the wrap-and-return branch
	// reinstated.
	hops, _ := verifier.VerifyDelegationProvenance(ctx, delegationPointers, fetcher, leafReader)

	result := &DelegationVerification{
		Hops:    hops,
		Depth:   len(hops),
		AllLive: true,
	}
	for i := range hops {
		if !hops[i].IsLive {
			result.AllLive = false
			if result.FirstDead == nil {
				pos := hops[i].Position
				result.FirstDead = &pos
			}
		}
	}

	//  short-circuits .
	if !result.AllLive {
		return result, nil
	}
	if scopeEnforcer == nil || target == nil {
		return result, nil
	}

	// : semantic scope authority.
	result.ScopeChecked = true
	if err := scopeEnforcer.VerifyDelegationScope(ctx, target); err != nil {
		var v *ScopeViolation
		if errors.As(err, &v) {
			result.ScopeViolation = v
			result.ScopeOK = false
			return result, nil
		}
		return nil, fmt.Errorf("verification/delegation_chain: scope phase: %w", err)
	}
	result.ScopeOK = true
	return result, nil
}

// ─── BY-DID walker (attesta v1.2.0+) ──────────────────────────

// ErrDelegationResolve wraps every error path the by-DID resolver
// surfaces. Underlying SDK sentinels (attestation.ErrUnknownDelegate,
// attestation.ErrChainBroken, sdkdelegation.ErrCycleDetected,
// sdkdelegation.ErrMaxDepthExceeded) remain reachable via errors.Is.
var ErrDelegationResolve = errors.New("verification/delegation_chain: resolve by DID")

// ResolveDelegationByDID walks the delegation chain UP from a leaf
// signer's DID using the SDK's by-DID resolver (v1.2.0+). The
// resolver:
//
//   - Returns chains leaf-first (Hops[0] authorises signerDID).
//   - Detects cycles via visited-set (returns ErrCycleDetected).
//   - Bounds traversal to DefaultMaxChainDepth (32) unless the
//     caller passes sdkdelegation.WithMaxDepth.
//   - Validates each hop's structural invariant
//     (DelegateDID/DelegatorDID/Scopes/Live non-empty / consistent).
//
// The returned attestation.DelegationChain is the canonical shape
// consumed by attestation.EvaluateConstraint and
// attestation.VerifyEntryAttestationPolicy when a Policy's
// Constraint.DelegationOriginDID or Constraint.RequiredScopes
// requires a chain walk. JN handlers wiring up SDK-attestation
// policy evaluation pass this resolver directly:
//
//	resolver, err := verification.NewResolverFromLookup(myLookup)
//	if err != nil { return ... }
//	report, err := attestation.VerifyEntryAttestationPolicy(
//	    ctx, primary, policy, candidates, sigVerifier, resolver,
//	)
//
// Returns ErrDelegationResolve wrapping the SDK sentinel on any
// walk-level failure. Callers errors.Is the SDK sentinel to route
// granular rejection paths.
//
// IDEMPOTENT. Pure function of (lookup, signerDID). Calling N
// times with the same lookup produces N identical chains.
func ResolveDelegationByDID(
	ctx context.Context,
	lookup DelegationLookupFunc,
	signerDID string,
	opts ...sdkdelegation.Option,
) (attestation.DelegationChain, error) {
	if lookup == nil {
		return attestation.DelegationChain{}, fmt.Errorf("%w: nil DelegationLookupFunc", ErrDelegationResolve)
	}
	if signerDID == "" {
		return attestation.DelegationChain{}, fmt.Errorf("%w: empty signerDID", ErrDelegationResolve)
	}
	resolver, err := NewResolverFromLookup(lookup, opts...)
	if err != nil {
		return attestation.DelegationChain{}, fmt.Errorf("%w: %w", ErrDelegationResolve, err)
	}
	chain, err := resolver.ResolveChain(ctx, signerDID)
	if err != nil {
		return attestation.DelegationChain{}, fmt.Errorf("%w: %w", ErrDelegationResolve, err)
	}
	return chain, nil
}

// ChainOriginDID returns the root authority's DID for the chain
// (the DelegatorDID of the last hop). Empty when the chain is
// empty. Convenience wrapper for handlers that want to verify
// the chain rolls up to an expected institutional DID without
// reaching into the SDK's chain methods.
//
// Mirrors attestation.DelegationChain.OriginDID() — exposed here
// for symmetry with the rest of the JN verification helpers.
func ChainOriginDID(chain attestation.DelegationChain) string {
	return chain.OriginDID()
}

// ChainHasScope reports whether the LEAF hop (Hops[0]) carries
// the named scope. Mirrors the SDK's
// attestation.DelegationChain.HasScope semantics (source-verified
// at v1.2.0): the leaf is the authority the queried signer
// effectively carries, so the predicate inspects only Hops[0].
// Upper-hop scopes represent parent authority constraints that
// were already evaluated when the leaf's delegation entry was
// admitted; the resolver returns them for diagnostic purposes
// but not for the leaf-scope predicate.
//
// Returns false on an empty chain. A future SDK change to
// "all-hops intersection" semantics would surface in the
// pinned ChainHasScope_LeafScopeOnly test.
func ChainHasScope(chain attestation.DelegationChain, scope string) bool {
	return chain.HasScope(scope)
}

// Compile-time pin — a future SDK rename or signature break in
// delegation.Resolver / attestation.DelegationChain surfaces at
// the JN build.
var (
	_ = sdkdelegation.NewResolver
	_ = sdkdelegation.DefaultMaxChainDepth
	_ = sdkdelegation.WithMaxDepth
	_ = (*attestation.DelegationChain)(nil)
)
