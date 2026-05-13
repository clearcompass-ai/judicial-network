/*
FILE PATH: verification/delegation_source.go

DESCRIPTION:

	JN adapter for attesta v1.2.0+'s delegation.EntrySource
	interface. Lets a JN service plug any lookup-by-DelegateDID
	function into the SDK's leaf-first delegation walker
	(delegation.Resolver), which in turn satisfies
	attestation.DelegationResolver — the seam the SDK's
	VerifyEntryAttestationPolicy needs to evaluate
	Constraint.DelegationOriginDID and Constraint.RequiredScopes.

	# WHY A FUNCTION-BACKED ADAPTER (NOT A SCAN-BASED SOURCE)

	The SDK's delegation.EntrySource asks one question:

	    DelegationOf(ctx, delegateDID) -> (DelegationEntry, error)

	JN's production storage does NOT index by Delegate_DID today
	(see attesta/log.LedgerQueryAPI — the five query methods
	cover CosignatureOf / TargetRoot / SignerDID / SchemaRef /
	ScanFromPosition; none answer "which entry's
	Header.DelegateDID is X"). A scan-based default would silently
	scale poorly past ~10K delegation entries.

	Instead, this file ships a FUNCTION-BACKED adapter and a
	transformation helper. Consumers wire a lookup function
	appropriate to their store (an external index, a Postgres
	view, the in-memory test fixture, etc.), and JN's verification
	layer composes it with the SDK Resolver. The contract is
	enforced by the SDK's typed sentinels: an unknown DID surfaces
	as attestation.ErrUnknownDelegate; a broken chain as
	attestation.ErrChainBroken.

	# SCOPE — DISTINCT FROM verification/delegation_chain.go

	verification/delegation_chain.go walks delegations BY POINTER
	using verifier.VerifyDelegationProvenance — the entry carries
	a slice of Header.DelegationPointers, and the verifier confirms
	that explicit chain. That mechanic is unchanged.

	This file (delegation_source.go) walks delegations BY DID. The
	caller supplies a leaf signer's DID; the Resolver walks UP via
	the EntrySource until it reaches a self-rooted DID (DelegatorDID
	equal to DelegateDID, e.g. the institutional DID). The returned
	chain is leaf-first — Hops[0] authorises the queried signer.

	Both walking models are valid. By-pointer is faster (the
	caller already has the chain in the entry); by-DID is needed
	when only the signer DID is known (the SDK's attestation
	composite, audit tools, recursive authority lookups).

TRUST ALIGNMENT:

	SDK Principle 9 (Zero-Trust Identity Agnosticism): the
	EntrySource interface lets JN swap DID-resolution backends
	without changing the SDK Resolver or the attestation verifier.
	SDK Principle 12 (Schema-Aware Extractor Inversion): JN
	supplies the storage mapping; the SDK does not bake in any
	particular index.

KEY DEPENDENCIES:
  - attesta/delegation: EntrySource, DelegationEntry, Resolver
  - attesta/attestation: ErrUnknownDelegate, DelegationChain
  - attesta/core/envelope: Entry, ControlHeader.DelegateDID
  - judicial-network/schemas: JudicialDelegationPayload
*/
package verification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/delegation"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ErrDelegationSource wraps every error path the adapter
// produces. SDK sentinels remain reachable via errors.Is —
// callers detect attestation.ErrUnknownDelegate and
// attestation.ErrChainBroken without unwrapping ErrDelegationSource.
var ErrDelegationSource = errors.New("verification/delegation_source")

// DelegationLookupFunc resolves a delegateDID to the
// delegation.DelegationEntry that authorises it. Implementations
// return attestation.ErrUnknownDelegate when no entry matches —
// the SDK Resolver propagates this sentinel back to the caller
// as the chain's terminus.
//
// Any other error is treated as a transport failure by the
// Resolver and aborts the walk with attestation.ErrChainBroken.
type DelegationLookupFunc func(ctx context.Context, delegateDID string) (delegation.DelegationEntry, error)

// FuncEntrySource is a delegation.EntrySource backed by a single
// closure. Satisfies the SDK's EntrySource interface
// structurally; useful for wiring custom indexes (Postgres
// views, in-memory caches, external directory services) without
// allocating a struct type per backend.
type FuncEntrySource struct {
	// Lookup is called once per Resolver hop. Required.
	Lookup DelegationLookupFunc
}

// NewFuncEntrySource constructs a FuncEntrySource. Returns
// ErrDelegationSource if lookup is nil — the resolver would
// otherwise panic on first walk.
func NewFuncEntrySource(lookup DelegationLookupFunc) (*FuncEntrySource, error) {
	if lookup == nil {
		return nil, fmt.Errorf("%w: nil DelegationLookupFunc", ErrDelegationSource)
	}
	return &FuncEntrySource{Lookup: lookup}, nil
}

// DelegationOf implements delegation.EntrySource. Forwards to
// the configured Lookup function; preserves the SDK sentinel
// returned by the lookup so errors.Is(err,
// attestation.ErrUnknownDelegate) works at the resolver
// boundary.
func (s *FuncEntrySource) DelegationOf(ctx context.Context, delegateDID string) (delegation.DelegationEntry, error) {
	if s == nil || s.Lookup == nil {
		return delegation.DelegationEntry{}, fmt.Errorf("%w: nil source or lookup", ErrDelegationSource)
	}
	return s.Lookup(ctx, delegateDID)
}

// Compile-time pin — FuncEntrySource MUST satisfy the SDK's
// EntrySource interface. A future SDK rename or signature change
// breaks the JN build here, before any runtime call.
var _ delegation.EntrySource = (*FuncEntrySource)(nil)

// EntryFromJudicialDelegation extracts a delegation.DelegationEntry
// from a JN-domain judicial-delegation-v1 envelope.Entry. Maps:
//
//	envelope.Entry.Header.DelegateDID       -> DelegationEntry.DelegateDID
//	JudicialDelegationPayload.GranterDID    -> DelegationEntry.DelegatorDID
//	JudicialDelegationPayload.Scope         -> DelegationEntry.Scopes
//
// Live is set from the caller-supplied revocationLookup, which
// returns true iff the entry's LogPosition is NOT in JN's
// revocation set at the verifier's time-of-check. JN's
// delegation/revoke.go owns the revocation table; that lookup is
// outside the SDK because revocation is a domain concern.
//
// Returns ErrDelegationSource wrapping ErrNoDelegateDID when
// Header.DelegateDID is nil (programming error — only entries
// that actually establish a delegation carry this field),
// wrapping a JSON error when the payload is malformed, or
// wrapping ErrPayloadInconsistent when payload.GranteeDID does
// not match Header.DelegateDID (a publish-time invariant the
// SDK admission gate enforces, defended again here for read-side
// confidence).
func EntryFromJudicialDelegation(
	entry *envelope.Entry,
	live bool,
) (delegation.DelegationEntry, error) {
	if entry == nil {
		return delegation.DelegationEntry{}, fmt.Errorf("%w: nil entry", ErrDelegationSource)
	}
	if entry.Header.DelegateDID == nil || *entry.Header.DelegateDID == "" {
		return delegation.DelegationEntry{}, fmt.Errorf("%w: %w", ErrDelegationSource, ErrNoDelegateDID)
	}
	var payload schemas.JudicialDelegationPayload
	if err := json.Unmarshal(entry.DomainPayload, &payload); err != nil {
		return delegation.DelegationEntry{}, fmt.Errorf("%w: unmarshal JudicialDelegationPayload: %w", ErrDelegationSource, err)
	}
	if payload.GranteeDID != *entry.Header.DelegateDID {
		return delegation.DelegationEntry{}, fmt.Errorf("%w: %w (Header=%q payload.GranteeDID=%q)",
			ErrDelegationSource, ErrPayloadInconsistent, *entry.Header.DelegateDID, payload.GranteeDID)
	}
	if payload.GranterDID == "" {
		return delegation.DelegationEntry{}, fmt.Errorf("%w: payload.GranterDID empty", ErrDelegationSource)
	}
	return delegation.DelegationEntry{
		DelegateDID:  payload.GranteeDID,
		DelegatorDID: payload.GranterDID,
		Scopes:       append([]string(nil), payload.Scope...),
		Live:         live,
	}, nil
}

// ErrNoDelegateDID fires when EntryFromJudicialDelegation is
// handed an envelope.Entry whose Header.DelegateDID is nil — the
// caller passed a non-delegation entry by mistake.
var ErrNoDelegateDID = errors.New("entry missing Header.DelegateDID")

// ErrPayloadInconsistent fires when the payload's GranteeDID
// does not match the Header.DelegateDID. A well-formed delegation
// entry has both fields equal; mismatch is a wire-level fraud
// signal.
var ErrPayloadInconsistent = errors.New("payload.GranteeDID != Header.DelegateDID")

// NewResolverFromLookup is the convenience constructor JN
// services use to obtain a fully-wired delegation.Resolver from
// a single lookup function. Equivalent to:
//
//	src, err := NewFuncEntrySource(lookup)
//	if err != nil { return nil, err }
//	return delegation.NewResolver(src, opts...), nil
//
// Returns ErrDelegationSource when lookup is nil. The returned
// *delegation.Resolver satisfies attestation.DelegationResolver
// — pass it into attestation.VerifyEntryAttestationPolicy.
func NewResolverFromLookup(lookup DelegationLookupFunc, opts ...delegation.Option) (*delegation.Resolver, error) {
	src, err := NewFuncEntrySource(lookup)
	if err != nil {
		return nil, err
	}
	return delegation.NewResolver(src, opts...), nil
}

// Compile-time pin — *delegation.Resolver satisfies
// attestation.DelegationResolver. If the SDK ever renames or
// resignatures ResolveChain, this guard breaks the JN build.
var _ attestation.DelegationResolver = (*delegation.Resolver)(nil)
