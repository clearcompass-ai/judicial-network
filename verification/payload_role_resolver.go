/*
FILE PATH: verification/payload_role_resolver.go

DESCRIPTION:

	PayloadRoleResolver — production-grade RoleResolver that reads
	its truth from the entry's payload `signed_by_capacities` block.
	.signed-by deliverable: the verifier no longer needs an
	off-log registry; every cosigning Signer is self-described in
	the same payload they cosigned.

	Construction: hand the resolver the entry's domain-payload bytes.
	The resolver parses signed_by_capacities once, validates each
	entry, and answers LookupRole(did) from that cache.

	Failure modes:
	  - payload has no signed_by_capacities: the resolver is
	    constructed cleanly but every LookupRole call returns
	    ErrSignerUnknown. The verifier surfaces unknown DIDs as
	    InAllowedSet=false; the threshold check then fails. This
	    mirrors the writer's omission honestly — silent fallbacks
	    would be a foot-gun.
	  - payload's signed_by_capacities is malformed: the constructor
	    returns an error and the verifier rejects the entry up-front.
	  - individual entry fails Validate: surfaced at construction
	    time so the audit trail blames the writer, not a downstream
	    check.

	Composition: callers can layer this with a future
	AuthorityResolver chain walk (.preqs) by treating
	PayloadRoleResolver as the source-of-truth and the chain walk
	as a verifier of that truth. This file ships only the read path.

OVERVIEW:

	PayloadRoleResolver        — type.
	NewPayloadRoleResolver     — parses payload bytes.
	NewPayloadRoleResolverFrom — accepts a pre-parsed slice
	                             (test/composition seam).
	LookupRole                 — RoleResolver method.
	Capacities                 — read-only view (audit/tests).

KEY DEPENDENCIES:
  - schemas/signed_by_capacity.go (ExtractSignedByCapacities,
    SignedByCapacity, FindSignedByCapacity).
*/
package verification

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// PayloadRoleResolver answers LookupRole from the
// signed_by_capacities block of a single entry's payload. Immutable
// after construction; safe for concurrent reads.
type PayloadRoleResolver struct {
	caps []schemas.SignedByCapacity
}

// NewPayloadRoleResolver constructs a resolver from raw payload
// bytes. Returns an empty (lookup-fails-everywhere) resolver when
// the payload has no signed_by_capacities. Returns an error when
// the array is present but malformed, or when any entry fails
// structural validation.
func NewPayloadRoleResolver(payload []byte) (*PayloadRoleResolver, error) {
	caps, present, err := schemas.ExtractSignedByCapacities(payload)
	if err != nil {
		return nil, fmt.Errorf("verification/payload_role_resolver: %w", err)
	}
	if !present {
		return &PayloadRoleResolver{caps: nil}, nil
	}
	for i := range caps {
		if err := caps[i].Validate(); err != nil {
			return nil, fmt.Errorf("verification/payload_role_resolver: signed_by_capacities[%d]: %w",
				i, err)
		}
	}
	return &PayloadRoleResolver{caps: caps}, nil
}

// NewPayloadRoleResolverFrom accepts a pre-parsed slice. Each entry
// is validated; a bad entry surfaces an error. Useful for
// composition (e.g., the inline cosignature pipeline already holds
// the slice and avoids a re-parse) and for tests.
func NewPayloadRoleResolverFrom(caps []schemas.SignedByCapacity) (*PayloadRoleResolver, error) {
	for i := range caps {
		if err := caps[i].Validate(); err != nil {
			return nil, fmt.Errorf("verification/payload_role_resolver: signed_by_capacities[%d]: %w",
				i, err)
		}
	}
	cp := make([]schemas.SignedByCapacity, len(caps))
	copy(cp, caps)
	return &PayloadRoleResolver{caps: cp}, nil
}

// LookupRole satisfies RoleResolver. Returns ErrSignerUnknown when
// did is not in the payload's signed_by_capacities block.
func (r *PayloadRoleResolver) LookupRole(did string) (ResolverEntry, error) {
	if r == nil || len(r.caps) == 0 {
		return ResolverEntry{}, fmt.Errorf("%w: did=%s", ErrSignerUnknown, did)
	}
	c := schemas.FindSignedByCapacity(r.caps, did)
	if c == nil {
		return ResolverEntry{}, fmt.Errorf("%w: did=%s", ErrSignerUnknown, did)
	}
	return ResolverEntry{Role: c.Role, Exchange: c.Exchange}, nil
}

// Capacities returns a read-only view of the parsed
// signed_by_capacities slice. Callers must not mutate the returned
// slice; the resolver does not defensively copy on read.
func (r *PayloadRoleResolver) Capacities() []schemas.SignedByCapacity {
	if r == nil {
		return nil
	}
	return r.caps
}

// Static check.
var _ RoleResolver = (*PayloadRoleResolver)(nil)
