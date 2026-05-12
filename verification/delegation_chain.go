/*
FILE PATH: verification/delegation_chain.go

DESCRIPTION:

	Delegation chain verification for a specific filing. Two phases:
	    cryptographic provenance: walks DelegationPointers
	              linearly via the SDK's VerifyDelegationProvenance.
	              Confirms each hop's delegation is live and the chain
	              connects.
	    semantic scope authority: walks the same chain via
	              verification.ScopeEnforcer to confirm the target
	              entry's SchemaRef is permitted by every delegation's
	              scope_limit (the read-side defense against the
	              Compromised-Subordinate-Key attack documented in
	              attesta/docs/implementation-obligations.md).

KEY ARCHITECTURAL DECISIONS:
  - SDK correction #1: VerifyDelegationProvenance (linear walk) NOT
    WalkDelegationTree (BFS). VerifyDelegationProvenance is the
    correct primitive for single-chain verification.
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

OVERVIEW:

	VerifyFilingDelegation → *DelegationVerification with both
	cryptographic liveness AND scope_limit verdicts surfaced.

KEY DEPENDENCIES:
  - attesta/verifier (VerifyDelegationProvenance)
  - attesta/core/envelope, types, smt
  - judicial-network/verification (ScopeEnforcer)
*/
package verification

import (
	"context"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
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
