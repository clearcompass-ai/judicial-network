/*
FILE PATH: verification/chain_role_resolver.go

DESCRIPTION:

	ChainRoleResolver — the VERIFYING RoleResolver. Where
	PayloadRoleResolver returns the (role, exchange) a cosigner
	CLAIMS in its own signed_by_capacities block (trust mode),
	ChainRoleResolver returns only the claims a delegation chain
	BACKS on-log (verify mode).

	This is the G19 gate. A self-asserted judge — a signer whose
	signed_by_capacities says role="judge" but whose delegation
	chain does NOT resolve to "judge" (or does not resolve at all)
	— is DROPPED from the verified set. LookupRole then returns
	ErrSignerUnknown for that DID, and the cosignature verifier
	(collectSignerCosigners) does not count it toward the role
	threshold. The lie costs the entry its quorum; it dies at the
	gate.

	COMPOSITION (claim ∘ verify):
	  1. CLAIM   — read signed_by_capacities (what the signer says).
	  2. VERIFY  — for each claim with a delegation_ref, walk the
	               chain via the per-jurisdiction
	               jurisdiction.AuthorityChainResolver and confirm the
	               chain-tip role EQUALS the claimed role.
	  3. ADMIT   — only chain-backed claims enter the verified map.

	The walk binds to the cosigner's own DID (AuthorityRequest.SignerDID
	is the chain tip's expected grantee), so a cosigner cannot borrow a
	real judge's delegation_ref — the grantee chain would not start at
	the cosigner.

	FAIL-CLOSED. Every way a claim can fail to verify — no
	delegation_ref, chain doesn't resolve, role mismatch, a revoked /
	expired / depth-exceeded hop — DROPS the claim (absent from the map
	⇒ ErrSignerUnknown ⇒ not counted). Only structural input faults
	(malformed capacities, a cap that fails Validate, a cosigner count
	over attestation.MaxCosigners) return a construction error so the
	gate rejects the whole entry up-front.

	BOUNDED. attestation.BoundCosigners caps the cosigner set before any
	chain is walked, so per-entry verification is O(MaxCosigners ×
	MaxDepth) bounded indexed reads — never proportional to an
	attacker-chosen capacity list (scale is a correctness property).

OVERVIEW:

	ChainRoleResolver        — type (verified map; immutable after
	                           construction; safe for concurrent reads).
	NewChainRoleResolver     — parse payload + verify each claim.
	NewChainRoleResolverFrom — pre-parsed caps (composition / tests).
	LookupRole               — RoleResolver method; backed claims only.

KEY DEPENDENCIES:
  - schemas (SignedByCapacity, ExtractSignedByCapacities).
  - jurisdiction (AuthorityChainResolver, AuthorityRequest).
  - baseproof/attestation (BoundCosigners — the per-entry cap).
*/
package verification

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/attestation"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ChainRoleResolver answers LookupRole from chain-BACKED
// signed_by_capacities only. Immutable after construction; safe for
// concurrent reads.
type ChainRoleResolver struct {
	verified map[string]ResolverEntry
}

// NewChainRoleResolver parses signed_by_capacities from payload and
// verifies each claim against authority (see NewChainRoleResolverFrom
// for the verification contract). Returns an empty
// (lookup-fails-everywhere) resolver when the payload carries no
// signed_by_capacities block — the same posture as PayloadRoleResolver,
// so a pure-signer entry simply has no Tier-1 cosigners to count.
func NewChainRoleResolver(
	ctx context.Context,
	payload []byte,
	authority jurisdiction.AuthorityChainResolver,
) (*ChainRoleResolver, error) {
	caps, present, err := schemas.ExtractSignedByCapacities(payload)
	if err != nil {
		return nil, fmt.Errorf("verification/chain_role_resolver: %w", err)
	}
	if !present {
		return &ChainRoleResolver{verified: nil}, nil
	}
	return NewChainRoleResolverFrom(ctx, caps, authority)
}

// NewChainRoleResolverFrom verifies a pre-parsed capacity slice.
//
// Construction FAILS (returns error → the gate rejects the entry) on:
//   - attestation.BoundCosigners(len(caps)) — too many cosigners.
//   - a nil authority resolver (programming error).
//   - any cap that fails structural Validate().
//
// A structurally-valid claim is ADMITTED to the verified map iff its
// delegation_ref walks to a chain whose tip role EQUALS the claimed
// role (verdict.OK && verdict.Role == cap.Role). Every other outcome —
// no delegation_ref, verdict not OK (unresolved / revoked / expired /
// depth), or role mismatch — drops the claim silently (fail-closed):
// LookupRole returns ErrSignerUnknown and the cosignature verifier does
// not count it toward the threshold.
func NewChainRoleResolverFrom(
	ctx context.Context,
	caps []schemas.SignedByCapacity,
	authority jurisdiction.AuthorityChainResolver,
) (*ChainRoleResolver, error) {
	if len(caps) == 0 {
		return &ChainRoleResolver{verified: nil}, nil
	}
	if err := attestation.BoundCosigners(len(caps)); err != nil {
		return nil, fmt.Errorf("verification/chain_role_resolver: %w", err)
	}
	if authority == nil {
		return nil, fmt.Errorf("verification/chain_role_resolver: nil AuthorityChainResolver")
	}
	verified := make(map[string]ResolverEntry, len(caps))
	for i := range caps {
		c := &caps[i]
		if err := c.Validate(); err != nil {
			return nil, fmt.Errorf("verification/chain_role_resolver: signed_by_capacities[%d]: %w", i, err)
		}
		// A claim with no chain pointer cannot be verified → drop.
		if c.DelegationRef == nil {
			continue
		}
		verdict := authority.Resolve(ctx, jurisdiction.AuthorityRequest{
			SignerDID: c.DID,
			DelegationRef: jurisdiction.DelegationRef{
				LogDID:   c.DelegationRef.LogDID,
				Sequence: c.DelegationRef.Sequence,
			},
			// Walk-only: verifying the cosigner's ROLE, not authorizing
			// an action. The verdict carries the chain-tip role; the
			// cosignature rule decides role membership downstream.
			RequestedAction: "",
		})
		// Chain-backed iff the walk validated AND the on-log tip role
		// equals the claimed role. A mismatch is a lie; drop it.
		if verdict.OK && verdict.Role == c.Role {
			verified[c.DID] = ResolverEntry{Role: c.Role, Exchange: c.Exchange}
		}
	}
	return &ChainRoleResolver{verified: verified}, nil
}

// LookupRole satisfies RoleResolver. Returns ErrSignerUnknown when did
// is not a chain-BACKED cosigner — whether because it was never claimed
// or because its claim failed chain verification.
func (r *ChainRoleResolver) LookupRole(did string) (ResolverEntry, error) {
	if r == nil || len(r.verified) == 0 {
		return ResolverEntry{}, fmt.Errorf("%w: did=%s", ErrSignerUnknown, did)
	}
	e, ok := r.verified[did]
	if !ok {
		return ResolverEntry{}, fmt.Errorf("%w: did=%s", ErrSignerUnknown, did)
	}
	return e, nil
}

// Static check.
var _ RoleResolver = (*ChainRoleResolver)(nil)
