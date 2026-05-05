/*
FILE PATH: schemas/judicial_delegation.go

DESCRIPTION:

	judicial-delegation-v1 — the single canonical entry shape for
	every authority grant in the judicial network. Replaces the
	previous role-specific delegation builders (judge.go, clerk.go,
	deputy.go) with one unified payload.

	A delegation is: "X granted Y the role R with scope S, expiring
	at E, on date D." That sentence captures the entire authority
	graph. Walked recursively, it's the audit trail. Intersected
	across the chain, it's the access-control list.

KEY ARCHITECTURAL DECISIONS:
  - One entry type. Roles are programmatic (RoleCatalog), not
    hard-coded constants. New roles are added by editing
    court-controlled YAML — no JN code change, no schema
    migration.
  - Mandatory expiration. Every delegation MUST carry an
    expires_at timestamp. The institutional DID at depth 0 is
    treated as unrestricted (no expiration) because it has its
    own multi-party Authority_Set governance.
  - granter_delegation_ref documents the chain explicitly in
    Domain Payload. The SDK's Delegation_Pointers in the Control
    Header carries the cryptographic chain; granter_delegation_ref
    is the domain-readable mirror so AuthorityResolver can walk
    O(depth) without re-decoding the header.
  - scope is a list of domain-defined string tokens. The
    ScopeEnforcer (verification/scope_enforcement.go) intersects
    across the chain — narrower-cannot-be-widened — and
    AuthorityResolver enforces this at every admission gate.
  - rationale is human-readable text published on-log for
    transparency. Limited to 2 KiB; larger evidence (CV,
    selection-panel scoring) goes via rationale_artifact CID.

OVERVIEW:

	JudicialDelegationPayload — the Domain Payload shape.
	Amendments (revocation, succession) are in judicial_amendments.go.
	Marshal helpers + registry registrations are in
	judicial_delegation_registry.go.

KEY DEPENDENCIES:
  - schemas/registry.go (registers the schema URI)
*/
package schemas

import (
	"fmt"
	"time"
)

// SchemaJudicialDelegationV1 is the URI for the canonical delegation
// schema. The on-log SchemaRef of every delegation entry must
// reference an entry whose Domain Payload identifies this URI.
const SchemaJudicialDelegationV1 = "judicial-delegation-v1"

// SchemaJudicialRevocationV1 is the URI for revocation amendments.
// Path A entry (same_signer): the granter who issued the original
// delegation revokes it via amendment. Origin_Tip of the original
// delegation advances to the revocation entry.
const SchemaJudicialRevocationV1 = "judicial-revocation-v1"

// SchemaJudicialSuccessionV1 is the URI for succession entries used
// when an irreplaceable signer (typically a chief justice) becomes
// incapacitated. The institutional DID's Authority_Set publishes
// the succession; Origin_Tip of the dead signer's delegation
// advances; downstream chains transparently redirect to the
// successor.
const SchemaJudicialSuccessionV1 = "judicial-succession-v1"

// JudicialDelegationPayload is the Domain Payload of every
// delegation entry. Every field is required EXCEPT Scope (which
// defaults to the role's DefaultScope), GranterDelegationRef
// (nil only when the granter is the institutional DID at depth 0),
// Rationale, and RationaleArtifact.
type JudicialDelegationPayload struct {
	// SchemaID pins this payload to SchemaJudicialDelegationV1 for
	// schema-aware decoders. Required.
	SchemaID string `json:"schema_id"`

	// GranterDID is the granter's did:key. Must equal the entry's
	// Header.SignerDID — the granter signs with their own key.
	GranterDID string `json:"granter_did"`

	// GranteeDID is the did:key receiving the delegation. Provided
	// by the granter at issuance time; the grantee must already
	// have a wallet (provisioned by Privy or another IdP) before
	// the granter calls IssueDelegation.
	GranteeDID string `json:"grantee_did"`

	// Role is a string keyed against the deployment's RoleCatalog.
	// Admission rejects unknown roles. The role determines max
	// duration and AllowedScope; this delegation's Scope must be
	// a subset of role.AllowedScope.
	Role string `json:"role"`

	// Scope is the explicit token set granted. Empty/missing means
	// "use role.DefaultScope". Tokens are domain-defined strings
	// like "case_filing", "invite:judge", "revoke:any". The
	// AuthorityResolver intersects Scope across the chain.
	Scope []string `json:"scope,omitempty"`

	// ExpiresAt is the moment this delegation stops being valid.
	// Mandatory. Must be in the future at issuance and within
	// role.MaxDuration of IssuedAt. AuthorityResolver rejects any
	// chain whose hops have expired.
	ExpiresAt string `json:"expires_at"` // RFC-3339Nano UTC

	// IssuedAt is when the granter signed this delegation. Used by
	// admission to validate (ExpiresAt - IssuedAt) <= role.MaxDuration.
	IssuedAt string `json:"issued_at"` // RFC-3339Nano UTC

	// GranterDelegationRef is the log position of the granter's own
	// delegation entry. Nil only when GranterDID is the
	// institutional DID at depth 0 (the granter is the institution
	// itself, has no parent delegation). For all depth >= 1, this
	// is required so AuthorityResolver can walk the chain in
	// Domain Payload without re-parsing the SDK header.
	GranterDelegationRef *LogPositionRef `json:"granter_delegation_ref,omitempty"`

	// Rationale is human-readable text explaining why the delegation
	// is being issued. Capped at 2 KiB; larger evidence goes via
	// RationaleArtifact.
	Rationale string `json:"rationale,omitempty"`

	// RationaleArtifact is a CID pointing to encrypted supporting
	// evidence (CV, selection-panel scoring, board approval).
	// Optional; when present, verifiers may demand the artifact and
	// confirm its hash matches.
	RationaleArtifact string `json:"rationale_artifact,omitempty"`
}

// LogPositionRef is the JSON-friendly form of types.LogPosition.
// Mirrors the SDK's LogPosition shape but isolates the schema
// payload from SDK type drift.
type LogPositionRef struct {
	LogDID   string `json:"log_did"`
	Sequence uint64 `json:"sequence"`
}

// MaxRationaleBytes is the on-log Rationale field cap. Anything
// larger goes via RationaleArtifact.
const MaxRationaleBytes = 2 << 10 // 2 KiB

// Validate runs structural validation on a JudicialDelegationPayload.
// Returns nil iff every required field is populated and the
// timestamps parse cleanly. Does NOT validate against a RoleCatalog
// (caller passes the result through RoleCatalog.Validate for that)
// or against chain consistency (AuthorityResolver does that walk).
func (p *JudicialDelegationPayload) Validate() error {
	if p.SchemaID != SchemaJudicialDelegationV1 {
		return fmt.Errorf("schemas/judicial_delegation: schema_id mismatch: got %q want %q",
			p.SchemaID, SchemaJudicialDelegationV1)
	}
	if p.GranterDID == "" {
		return fmt.Errorf("schemas/judicial_delegation: granter_did required")
	}
	if p.GranteeDID == "" {
		return fmt.Errorf("schemas/judicial_delegation: grantee_did required")
	}
	if p.GranterDID == p.GranteeDID {
		return fmt.Errorf("schemas/judicial_delegation: self-delegation rejected (granter == grantee)")
	}
	if p.Role == "" {
		return fmt.Errorf("schemas/judicial_delegation: role required")
	}
	if p.ExpiresAt == "" {
		return fmt.Errorf("schemas/judicial_delegation: expires_at required (mandatory expiration invariant)")
	}
	exp, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil {
		return fmt.Errorf("schemas/judicial_delegation: malformed expires_at: %w", err)
	}
	if p.IssuedAt == "" {
		return fmt.Errorf("schemas/judicial_delegation: issued_at required")
	}
	iss, err := time.Parse(time.RFC3339Nano, p.IssuedAt)
	if err != nil {
		return fmt.Errorf("schemas/judicial_delegation: malformed issued_at: %w", err)
	}
	if !exp.After(iss) {
		return fmt.Errorf("schemas/judicial_delegation: expires_at must be after issued_at")
	}
	if len(p.Rationale) > MaxRationaleBytes {
		return fmt.Errorf("schemas/judicial_delegation: rationale exceeds %d bytes (use rationale_artifact for larger evidence)",
			MaxRationaleBytes)
	}
	return nil
}

// ParsedExpiresAt returns the typed expiration time. Zero value if
// ExpiresAt is empty or malformed.
func (p *JudicialDelegationPayload) ParsedExpiresAt() time.Time {
	t, _ := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	return t.UTC()
}

// ParsedIssuedAt returns the typed issuance time.
func (p *JudicialDelegationPayload) ParsedIssuedAt() time.Time {
	t, _ := time.Parse(time.RFC3339Nano, p.IssuedAt)
	return t.UTC()
}
