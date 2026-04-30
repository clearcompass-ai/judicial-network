/*
FILE PATH: verification/authority_resolver.go

DESCRIPTION:
    AuthorityResolver — the on-log truth gate for "may signer X
    perform action A?" in the unified judicial-delegation-v1 model.

    Walks the signer's delegation chain in DOMAIN PAYLOAD via the
    granter_delegation_ref pointer at each hop. The SDK's
    DelegationPointers in the Control Header carry the cryptographic
    chain; granter_delegation_ref is the domain-readable mirror —
    walking it lets us decide authority O(depth) without re-parsing
    the SDK header.

    At each hop:
      - Fetch the delegation entry from the operator.
      - Deserialize the DomainPayload as JudicialDelegationPayload.
      - Confirm not expired (mandatory expiration invariant).
      - Evaluate origin via the SDK's EvaluateOrigin to catch
        revocation, amendment, and succession that may have happened
        on the entry since it was first published.
      - If origin is succeeded — follow the successor DID (Authority
        flows transparently through the succession entry).
      - Intersect the hop's Scope tokens with the running effective
        scope (narrower-cannot-be-widened).

    Termination:
      - granter_delegation_ref == nil → top of chain (institutional
        DID at depth 0). Walk completes.
      - Depth > MaxDelegationDepth → reject (the architecture spec
        caps at 3).
      - Revocation observed at any hop → reject.

    The resolver is sub-millisecond on a warm cache; callers run it
    on every entry submission as the read-side authority gate.

KEY ARCHITECTURAL DECISIONS:
    - Domain-payload chain walk (granter_delegation_ref) — not the
      SDK header. The two are kept in sync at issuance; reading the
      domain side is faster and keeps the resolver schema-aware.
    - Origin evaluation per-hop. A delegation entry may have been
      revoked or succeeded since publication; EvaluateOrigin reads
      Origin_Tip to surface those state changes.
    - Catalog validation is final-pass. After the chain produces an
      effective (role, scope), the resolver consults RoleCatalog to
      confirm the requested action is permissible at that authority.
    - On rejection, the resolver returns *Authority with OK=false and
      Reason populated. The caller logs Reason verbatim — auditors
      get exact answers without re-running the walk.

OVERVIEW:
    Authority         — the verdict struct (OK, Role, EffectiveScope,
                        Depth, Reason).
    AuthorityResolver — the dependency-injected resolver.
    Resolve           — the main entry point.

KEY DEPENDENCIES:
    - schemas (JudicialDelegationPayload, RoleCatalog).
    - ortholog-sdk verifier (EvaluateOrigin).
*/
package verification

import (
	"errors"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// MaxDelegationDepth caps the chain length per the architecture spec.
// Beyond this depth the resolver rejects without further walking; a
// well-behaved deployment never produces a deeper chain.
const MaxDelegationDepth = 3

// AuthorityRejection enumerates the closed-set rejection reasons the
// resolver returns. Audit pipelines key on these — string-matching
// the Reason field is brittle.
type AuthorityRejection string

const (
	RejectNone               AuthorityRejection = ""
	RejectFetchFailed        AuthorityRejection = "fetch_failed"
	RejectMalformedPayload   AuthorityRejection = "malformed_payload"
	RejectExpired            AuthorityRejection = "expired"
	RejectRevoked            AuthorityRejection = "revoked"
	RejectDepthExceeded      AuthorityRejection = "depth_exceeded"
	RejectScopeViolation     AuthorityRejection = "scope_violation"
	RejectCatalogViolation   AuthorityRejection = "catalog_violation"
	RejectMissingChainTip    AuthorityRejection = "missing_chain_tip"
	RejectSignerMismatch     AuthorityRejection = "signer_mismatch"
)

// Authority is the verdict returned by AuthorityResolver.Resolve.
type Authority struct {
	// OK is true iff every hop validated and the requested scope is
	// authorized by both the chain and the catalog.
	OK bool

	// SignerDID is echoed for audit-trail clarity.
	SignerDID string

	// Role is the role the signer holds at the tip of the chain (the
	// signer's own delegation entry).
	Role string

	// EffectiveScope is the running intersection of every hop's
	// Scope, ordered as the resolver encountered them. Empty slice
	// means the scope chain narrowed to zero — a configuration bug
	// upstream; the resolver treats this as a violation.
	EffectiveScope []string

	// Depth is the number of delegation hops walked (signer's own
	// delegation = 1; institutional grant = 1 too if signer is
	// granted directly by depth-0 institution). Zero on rejection
	// before any walk happened.
	Depth int

	// Rejection is RejectNone on OK=true, otherwise one of the
	// AuthorityRejection enum values.
	Rejection AuthorityRejection

	// Reason carries human-readable detail for audit logs. Stable
	// shape — auditors parse "hop=N delegate=DID" patterns.
	Reason string
}

// AuthorityResolver is the dependency-injected gate. Construct once
// per process; safe for concurrent Resolve calls.
type AuthorityResolver struct {
	// Fetcher reads entries by LogPosition. Production: HTTP client
	// to the operator. Tests: in-memory fake.
	Fetcher types.EntryFetcher

	// LeafReader reads SMT leaves for origin evaluation. Required
	// when SuccessionAware is true; nil disables origin checks (only
	// the static delegation entry is examined — useful in tests
	// where the chain is known not to have been revoked/succeeded).
	LeafReader smt.LeafReader

	// Catalog enforces role-level permissions (which roles may
	// delegate which, MaxDuration, AllowedScope subset). Required.
	Catalog schemas.RoleCatalog

	// Now returns the current time; defaults to time.Now. Tests
	// inject a fixed clock for expiration assertions.
	Now func() time.Time
}

// resolvedHop carries one chain hop's parsed payload. Internal.
type resolvedHop struct {
	payload *schemas.JudicialDelegationPayload
	entry   *envelope.Entry
}

func (r *AuthorityResolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

// ─── helpers ────────────────────────────────────────────────────────

func intersectScope(a, b []string) []string {
	idx := make(map[string]struct{}, len(b))
	for _, t := range b {
		idx[t] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, t := range a {
		if _, ok := idx[t]; ok {
			out = append(out, t)
		}
	}
	return out
}

func contains(s []string, t string) bool {
	for _, x := range s {
		if x == t {
			return true
		}
	}
	return false
}

// errFetchNotFound wraps a fetcher's nil-result; the resolver folds
// it into RejectFetchFailed.
var errFetchNotFound = errors.New("authority_resolver: fetcher returned nil entry")
