/*
FILE PATH: jurisdiction/authority_chain_resolver.go

DESCRIPTION:

	AuthorityChainResolver — per-jurisdiction delegation chain
	walker interface. Each Bundle returns its own resolver from
	Bundle.AuthorityChainResolver(); the resolver evaluates a
	Signer's delegation chain against THAT jurisdiction's
	RoleCatalog only.

	Per-jurisdiction scoping is the v0.5.0 invariant: a Davidson
	Adjudicator's chain is validated against Davidson's catalog;
	a Shelby Adjudicator's chain against Shelby's. Cross-
	jurisdiction events (case transfers, relay attestations)
	resolve both bundles explicitly via the registry.

	Why an interface here, not the concrete verification.
	AuthorityResolver: keeping the type in jurisdiction lets
	Bundle expose chain resolution without a circular import
	(verification depends on jurisdiction; the inverse cannot
	hold). The verification package provides the concrete
	implementation.

	The minimal interface — one Resolve method — covers what
	every caller needs: the cosignature verifier, the
	prerequisites walker, the submit-time admission gate.
	Audit-rich detail flows through AuthorityVerdict.

OVERVIEW:

	AuthorityChainResolver       — interface (1 method).
	AuthorityRequest             — input to Resolve.
	DelegationRef                — log pointer to a delegation entry.
	AuthorityVerdict             — output of Resolve.
	NoAuthorityChainResolver     — closed-by-default factory for
	                               TEMPLATE bundles and tests.

KEY DEPENDENCIES: context (for cancellation only).
*/
package jurisdiction

import "context"

// AuthorityChainResolver evaluates whether a Signer holds the
// authority claimed in the entry, by walking the Signer's
// delegation chain in this jurisdiction's RoleCatalog.
// Implementations MUST be safe for concurrent use.
type AuthorityChainResolver interface {
	// Resolve walks the chain referenced by req.DelegationRef
	// and returns a verdict. The verdict's Rejection field
	// carries a closed-set machine token; Reason carries human
	// detail. Resolve never returns an error — every failure
	// surfaces through the verdict.
	Resolve(ctx context.Context, req AuthorityRequest) AuthorityVerdict
}

// AuthorityRequest is the input to a chain walk.
type AuthorityRequest struct {
	// SignerDID is the entry's primary signer.
	SignerDID string

	// DelegationRef points at the signer's delegation entry on
	// the log (the chain tip). Required.
	DelegationRef DelegationRef

	// RequestedAction is the event_type or other action token
	// the signer is attempting. The catalog uses it for the
	// final role × action check. Empty string requests a chain
	// walk only — the verdict's Role and EffectiveScope are
	// produced but no action-permission decision is made.
	RequestedAction string
}

// DelegationRef points at a delegation entry on the log. Mirror
// of the SDK's domain-payload granter_delegation_ref shape,
// re-exported at the jurisdiction layer so this interface stays
// free of SDK types.
type DelegationRef struct {
	// LogDID is the institutional DID of the log holding the
	// delegation entry.
	LogDID string

	// Sequence is the entry's monotonic position in that log.
	Sequence uint64
}

// IsZero reports whether r is the zero value (no delegation
// reference set). Useful in callers that distinguish "top of
// chain" from "missing field."
func (r DelegationRef) IsZero() bool {
	return r.LogDID == "" && r.Sequence == 0
}

// AuthorityVerdict is the output of a chain walk.
type AuthorityVerdict struct {
	// OK is true iff every hop validated and the chain authorizes
	// req.RequestedAction (or req.RequestedAction was empty and
	// the chain walk itself succeeded).
	OK bool

	// SignerDID is echoed for audit-trail clarity.
	SignerDID string

	// Role is the role the signer holds at the chain tip.
	Role string

	// EffectiveScope is the running intersection of every hop's
	// scope tokens. Empty slice means the scope chain narrowed to
	// zero — a configuration bug; the resolver treats this as a
	// violation.
	EffectiveScope []string

	// Depth is the number of hops walked. Zero on rejection
	// before any walk happened.
	Depth int

	// Rejection is a closed-set machine token. Empty on OK=true.
	// Implementations SHOULD use the verification.AuthorityRejection
	// constants (RejectFetchFailed, RejectExpired, ...) for cross-
	// resolver audit consistency.
	Rejection string

	// Reason carries human-readable detail. Stable shape — auditors
	// parse "hop=N delegate=DID" patterns.
	Reason string
}

// nilResolver is the closed-by-default AuthorityChainResolver
// for TEMPLATE bundles and tests. Every Resolve call returns
// OK=false with rejection token "no_resolver_configured".
type nilResolver struct{}

// Resolve always returns a rejection. The req.SignerDID is
// echoed so audit logs identify the offending entry.
func (nilResolver) Resolve(_ context.Context, req AuthorityRequest) AuthorityVerdict {
	return AuthorityVerdict{
		OK:        false,
		SignerDID: req.SignerDID,
		Rejection: "no_resolver_configured",
		Reason:    "bundle has no AuthorityChainResolver wired",
	}
}

// NoAuthorityChainResolver returns a resolver that always
// rejects. TEMPLATE bundles wire this so the Bundle interface
// is satisfied (non-nil) while every authority check fails
// closed at boot time. Production bundles override.
func NoAuthorityChainResolver() AuthorityChainResolver {
	return nilResolver{}
}
