/*
FILE PATH: delegation/issue.go

DESCRIPTION:

	IssueDelegation — the canonical write path for the unified
	judicial-delegation-v1 entry type. Replaces the role-specific
	legacy role-specific builders with one function whose role is
	data, not code.

	The flow:

	  1. Validate the request (granter, grantee, role, scope,
	     expiration). Reject self-delegation, malformed timestamps,
	     missing fields.
	  2. Run the catalog gate: ValidateGrant(granter_role,
	     grantee_role, requested_scope, requested_duration).
	     Rejection here is a code/config bug or a deliberate policy
	     violation — log on-log only succeeds after this passes.
	  3. Build the JudicialDelegationPayload with mandatory
	     expires_at and (when not depth-0) granter_delegation_ref.
	  4. Build the EIP-712 typed-data display the wallet will show
	     to the granter at sign time. Domain salt is the
	     institutional DID — cross-court replay structurally blocked.
	  5. Call SDK BuildDelegation to produce the unsigned entry.
	  6. Sign-and-submit via the BuildContext pipeline. The
	     IdentityProvider (Privy in production) shows the granter
	     the typed data and waits for approval.
	  7. Return the assigned LogPositionRef so the caller can
	     persist it (officer registry, downstream chain references).

KEY ARCHITECTURAL DECISIONS:
  - GranterRole is required even when the granter is the
    institutional DID at depth 0, so the catalog can validate
    that the institutional DID may grant the requested role.
    Pass "" for granter_role to skip the granter-role check
    (used when the granter is the institution itself).
  - Scope defaults to the role's DefaultScope when the request
    Scope is empty — convenience for typical issuances.
  - Expiration is mandatory at the schema layer; here we also
    reject expirations beyond role.MaxDuration.

OVERVIEW:

	IssueRequest — caller-supplied parameters.
	IssueResult  — what the caller persists (LogPositionRef +
	               payload echo for audit).
	Issue        — the entry point.

KEY DEPENDENCIES:
  - delegation/builders_common.go (BuildContext, signAndSubmit).
  - schemas/judicial_delegation.go (payload + URI).
*/
package delegation

import (
	"context"
	"fmt"
	"time"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// IssueRequest is the input to Issue.
type IssueRequest struct {
	// GranterDID is the protocol DID of the issuer (signer).
	GranterDID string

	// GranterRole is the role the granter holds at issuance.
	// Required for catalog validation. Pass "" only when the
	// granter is the institutional DID at depth 0.
	GranterRole string

	// GranterDelegationRef points to the granter's own delegation
	// entry. Nil only when GranterRole == "" (institutional grant).
	GranterDelegationRef *schemas.LogPositionRef

	// GranteeDID is the receiver's protocol DID.
	GranteeDID string

	// GranteeRole is the role being granted. Must exist in the
	// catalog.
	GranteeRole string

	// Scope is the explicit token set granted. If empty the role's
	// DefaultScope is used. The catalog enforces subset-of-AllowedScope
	// and (when applicable) subset-of-granter-DelegableScope.
	Scope []string

	// Duration is how long the delegation is valid. If zero the
	// role's DefaultDuration is used. Capped at role.MaxDuration.
	Duration time.Duration

	// Rationale is the on-log human-readable reason. Capped at
	// MaxRationaleBytes; longer evidence goes via RationaleArtifact.
	Rationale string

	// RationaleArtifact is the optional CID of the encrypted
	// supporting evidence (CV, selection-panel scoring, etc.).
	RationaleArtifact string

	// Reason is the wallet-UX confirmation string ("Confirm grant
	// of judge role to <name>"). Not on-log.
	Reason string

	// AttestationPolicyName, when non-nil and non-empty, adopts the
	// named policy declared on judicial-delegation-v1's
	// SchemaParameters.AttestationPolicies (see
	// schemas/attestation_policies.go). Typical value:
	// schemas.PolicyDelegationBoardConcurrence. nil = no policy.
	AttestationPolicyName *string
}

// IssueResult is the output of Issue.
type IssueResult struct {
	// Position is the ledger-assigned log position. Persist this
	// in the officer registry so future chain walks can reference
	// it via granter_delegation_ref.
	Position schemas.LogPositionRef

	// Payload is the on-log JudicialDelegationPayload (echoed for
	// audit-trail correlation; the caller may discard).
	Payload *schemas.JudicialDelegationPayload
}

// Issue creates a judicial-delegation-v1 entry. Validates the
// request, runs the catalog gate, builds the unsigned envelope,
// and drives the sign-and-submit pipeline.
func Issue(ctx context.Context, bc *BuildContext, req IssueRequest) (*IssueResult, error) {
	if bc == nil || bc.Catalog == nil {
		return nil, fmt.Errorf("%w: nil BuildContext / Catalog", ErrInvalidRequest)
	}
	if err := req.validate(); err != nil {
		return nil, err
	}

	role, err := bc.Catalog.Lookup(req.GranteeRole)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCatalogRejection, err)
	}
	scope := req.Scope
	if len(scope) == 0 {
		scope = append([]string(nil), role.DefaultScope...)
	}
	duration := req.Duration
	if duration == 0 {
		duration = role.DefaultDuration
	}
	if err := bc.Catalog.ValidateGrant(req.GranterRole, req.GranteeRole, scope, duration); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCatalogRejection, err)
	}

	now := bc.now()
	payload := &schemas.JudicialDelegationPayload{
		SchemaID:             schemas.SchemaJudicialDelegationV1,
		GranterDID:           req.GranterDID,
		GranteeDID:           req.GranteeDID,
		Role:                 req.GranteeRole,
		Scope:                scope,
		ExpiresAt:            now.Add(duration).Format(time.RFC3339Nano),
		IssuedAt:             now.Format(time.RFC3339Nano),
		GranterDelegationRef: req.GranterDelegationRef,
		Rationale:            req.Rationale,
		RationaleArtifact:    req.RationaleArtifact,
	}
	payloadBytes, err := schemas.MarshalJudicialDelegationPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal payload: %v", ErrInvalidRequest, err)
	}

	entry, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: bc.ExchangeDID,
		SignerDID:   req.GranterDID,
		DelegateDID: req.GranteeDID,
		Payload:     payloadBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBuildFailed, err)
	}
	schemas.SetAttestationPolicy(entry, req.AttestationPolicyName)

	display := issueDisplay(bc.InstitutionalDID, payload)
	reason := req.Reason
	if reason == "" {
		reason = fmt.Sprintf("Grant %s role to %s", req.GranteeRole, req.GranteeDID)
	}

	pos, err := signAndSubmit(ctx, bc, entry, display, reason)
	if err != nil {
		return nil, err
	}
	return &IssueResult{Position: pos, Payload: payload}, nil
}

// issueDisplay renders the EIP-712 typed-data the wallet shows the
// granter. Domain Salt = institutional DID for cross-court replay
// defense; PrimaryType = "Delegation".
func issueDisplay(institutionalDID string, p *schemas.JudicialDelegationPayload) *identity.TypedDataDisplay {
	fields := []identity.EIP712Field{
		{Name: "granter_did", Type: "string", Value: p.GranterDID},
		{Name: "grantee_did", Type: "string", Value: p.GranteeDID},
		{Name: "role", Type: "string", Value: p.Role},
		{Name: "expires_at", Type: "string", Value: p.ExpiresAt},
	}
	for i, s := range p.Scope {
		fields = append(fields, identity.EIP712Field{
			Name:  fmt.Sprintf("scope[%d]", i),
			Type:  "string",
			Value: s,
		})
	}
	return &identity.TypedDataDisplay{
		Domain: identity.EIP712Domain{
			Name:    "Judicial Network",
			Version: "v1",
			Salt:    institutionalDID,
		},
		PrimaryType: "Delegation",
		Fields:      fields,
	}
}

// validate runs structural sanity on an IssueRequest before any
// catalog or SDK call. Returns nil iff every required field is
// populated.
func (r *IssueRequest) validate() error {
	if r.GranterDID == "" {
		return fmt.Errorf("%w: granter_did required", ErrInvalidRequest)
	}
	if r.GranteeDID == "" {
		return fmt.Errorf("%w: grantee_did required", ErrInvalidRequest)
	}
	if r.GranterDID == r.GranteeDID {
		return fmt.Errorf("%w: self-delegation rejected", ErrInvalidRequest)
	}
	if r.GranteeRole == "" {
		return fmt.Errorf("%w: grantee_role required", ErrInvalidRequest)
	}
	// GranterDelegationRef must accompany a non-institutional grant
	// (GranterRole != ""). The catalog will also enforce this via
	// the wildcard / DelegableBy rules.
	if r.GranterRole != "" && r.GranterDelegationRef == nil {
		return fmt.Errorf("%w: granter_delegation_ref required for non-institutional grant", ErrInvalidRequest)
	}
	return nil
}
