/*
FILE PATH: delegation/revoke.go

DESCRIPTION:

	RevokeDelegation — Path A revocation of a previously-issued
	judicial-delegation-v1 entry. Same-signer model: the granter
	who issued the original delegation revokes it via amendment.
	Origin_Tip of the original delegation advances to the
	revocation entry, breaking liveness for the chain.

	The flow:

	  1. Validate the request (granter, target_delegation,
	     reason). Reason is a domain-defined string;
	     "expired" / "officer_transfer" / "performance" /
	     "conflict" / "death_in_office" are conventional but the
	     schema accepts any non-empty string.
	  2. Build the JudicialRevocationPayload.
	  3. Build the EIP-712 typed-data display the wallet renders
	     to the granter at sign time. Domain Salt =
	     institutional DID; PrimaryType = "Revocation".
	  4. Call SDK BuildRevocation. TargetRoot is the original
	     delegation's LogPosition.
	  5. Sign-and-submit via the BuildContext pipeline.
	  6. Return the assigned LogPositionRef.

	Authority model: the catalog gate does NOT apply here. The
	authority to revoke comes from being the original granter —
	AuthorityResolver will reject revocation entries whose signer
	does not match the targeted delegation's GranterDID at admission
	time.

OVERVIEW:

	RevokeRequest — caller-supplied parameters.
	RevokeResult  — assigned position + payload echo.
	Revoke        — entry point.

KEY DEPENDENCIES:
  - delegation/builders_common.go (BuildContext, signAndSubmit).
  - schemas/judicial_amendments.go (JudicialRevocationPayload).
*/
package delegation

import (
	"context"
	"fmt"
	"time"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// RevokeRequest is the input to Revoke.
type RevokeRequest struct {
	// GranterDID is the protocol DID signing the revocation. Must
	// equal the original delegation's GranterDID — the caller
	// enforces this against their officer registry; admission
	// re-validates against the chain.
	GranterDID string

	// TargetDelegation is the LogPositionRef of the delegation
	// being revoked.
	TargetDelegation schemas.LogPositionRef

	// Reason is the domain-defined revocation reason. Required.
	// Conventional values: "expired", "officer_transfer",
	// "performance", "conflict", "death_in_office".
	Reason string

	// EventReason is the wallet-UX confirmation string. Optional;
	// defaults to "Revoke delegation <target>".
	EventReason string
}

// RevokeResult is the output of Revoke.
type RevokeResult struct {
	Position schemas.LogPositionRef
	Payload  *schemas.JudicialRevocationPayload
}

// Revoke creates a judicial-revocation-v1 entry. Validates the
// request, builds the revocation envelope (Path A), signs via
// IdentityProvider, submits to the ledger.
func Revoke(ctx context.Context, bc *BuildContext, req RevokeRequest) (*RevokeResult, error) {
	if bc == nil {
		return nil, fmt.Errorf("%w: nil BuildContext", ErrInvalidRequest)
	}
	if err := req.validate(); err != nil {
		return nil, err
	}

	payload := &schemas.JudicialRevocationPayload{
		SchemaID:         schemas.SchemaJudicialRevocationV1,
		TargetDelegation: req.TargetDelegation,
		Reason:           req.Reason,
		RevokedAt:        bc.now().Format(time.RFC3339Nano),
	}
	payloadBytes, err := schemas.MarshalJudicialRevocationPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal payload: %v", ErrInvalidRequest, err)
	}

	target := types.LogPosition{
		LogDID:   req.TargetDelegation.LogDID,
		Sequence: req.TargetDelegation.Sequence,
	}
	entry, err := builder.BuildRevocation(builder.RevocationParams{
		Destination: bc.ExchangeDID,
		SignerDID:   req.GranterDID,
		TargetRoot:  target,
		Payload:     payloadBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBuildFailed, err)
	}

	display := revokeDisplay(bc.InstitutionalDID, payload)
	reason := req.EventReason
	if reason == "" {
		reason = fmt.Sprintf("Revoke delegation %s#%d (%s)",
			req.TargetDelegation.LogDID, req.TargetDelegation.Sequence, req.Reason)
	}

	pos, err := signAndSubmit(ctx, bc, entry, display, reason)
	if err != nil {
		return nil, err
	}
	return &RevokeResult{Position: pos, Payload: payload}, nil
}

// revokeDisplay renders the EIP-712 typed-data for the wallet UX.
// Cross-court replay is structurally blocked by the institutional
// DID Salt.
func revokeDisplay(institutionalDID string, p *schemas.JudicialRevocationPayload) *identity.TypedDataDisplay {
	return &identity.TypedDataDisplay{
		Domain: identity.EIP712Domain{
			Name:    "Judicial Network",
			Version: "v1",
			Salt:    institutionalDID,
		},
		PrimaryType: "Revocation",
		Fields: []identity.EIP712Field{
			{Name: "target_log_did", Type: "string", Value: p.TargetDelegation.LogDID},
			{Name: "target_sequence", Type: "uint64", Value: fmt.Sprintf("%d", p.TargetDelegation.Sequence)},
			{Name: "reason", Type: "string", Value: p.Reason},
			{Name: "revoked_at", Type: "string", Value: p.RevokedAt},
		},
	}
}

// validate runs structural sanity on a RevokeRequest.
func (r *RevokeRequest) validate() error {
	if r.GranterDID == "" {
		return fmt.Errorf("%w: granter_did required", ErrInvalidRequest)
	}
	if r.TargetDelegation.LogDID == "" {
		return fmt.Errorf("%w: target_delegation.log_did required", ErrInvalidRequest)
	}
	if r.Reason == "" {
		return fmt.Errorf("%w: reason required", ErrInvalidRequest)
	}
	return nil
}
