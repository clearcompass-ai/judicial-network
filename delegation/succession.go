/*
FILE PATH: delegation/succession.go

DESCRIPTION:
    Succeed — top-of-chain succession when an irreplaceable signer
    (typically chief justice) dies, resigns, or is removed. Path A
    Authority_Set entry: signed by the institutional DID with
    cosignatures from the Authority_Set members per the
    institution's cosignature_threshold (typically 2-of-3).

    Origin_Tip of the target delegation advances to this succession
    entry. AuthorityResolver follows the SuccessorDID transparently:
    downstream chains (judges, clerks, deputies) granted by the
    deceased signer remain valid, with their on-log granter
    redirected to the successor.

    Inheritance modes:
      - "full"        — successor inherits the original scope.
      - "narrowed"    — successor inherits only the listed
                        narrowed_scope tokens.
      - "clean_slate" — successor inherits no chain authority;
                        downstream re-issuance is required.

    Authority model: the catalog gate does NOT apply. The authority
    to publish a succession comes from the institutional DID's
    Authority_Set, enforced upstream by the
    lifecycle.ScopeGovernance / Authority_Set cosignature contract.

OVERVIEW:
    SuccessionRequest — caller-supplied parameters.
    SuccessionResult  — assigned position + payload echo.
    Succeed           — entry point.

KEY DEPENDENCIES:
    - delegation/builders_common.go (BuildContext, signAndSubmit).
    - schemas/judicial_amendments.go (JudicialSuccessionPayload).

LEGACY NOTE:
    Replaces the pre-Wave-2 RotateJudge / SuccessionConfig /
    SuccessionResult shapes. The new model carries inheritance
    semantics in the Domain Payload and is consumed by
    AuthorityResolver's origin-aware chain walker.
*/
package delegation

import (
	"context"
	"fmt"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// SuccessionRequest is the input to Succeed.
type SuccessionRequest struct {
	// SignerDID is the DID signing the succession — typically the
	// institutional DID. The cosignature collection is the caller's
	// responsibility (lifecycle.ScopeGovernance) before this call.
	SignerDID string

	// TargetDelegation is the LogPositionRef of the original
	// delegation being succeeded.
	TargetDelegation schemas.LogPositionRef

	// SuccessorDID is the new DID inheriting authority. Required.
	SuccessorDID string

	// Reason is the domain-defined succession reason. Required.
	// Conventional values: "death_in_office", "resignation",
	// "removal".
	Reason string

	// Inheritance is the closed-set mode: InheritanceFull,
	// InheritanceNarrowed, InheritanceCleanSlate.
	Inheritance string

	// NarrowedScope is required when Inheritance == "narrowed".
	NarrowedScope []string

	// AuthoritySetCosigs lists the cosigner DIDs whose signatures
	// authorized this succession. The on-log payload records them
	// for transparency; the SDK's cosignature verifier enforces
	// presence at admission time.
	AuthoritySetCosigs []string

	// EventReason is the wallet-UX confirmation string. Optional.
	EventReason string
}

// SuccessionResult is the output of Succeed.
type SuccessionResult struct {
	Position schemas.LogPositionRef
	Payload  *schemas.JudicialSuccessionPayload
}

// Succeed creates a judicial-succession-v1 entry. Validates the
// request, builds the succession envelope (Path A on the
// institutional DID's log), signs via IdentityProvider, submits.
func Succeed(ctx context.Context, bc *BuildContext, req SuccessionRequest) (*SuccessionResult, error) {
	if bc == nil {
		return nil, fmt.Errorf("%w: nil BuildContext", ErrInvalidRequest)
	}
	if err := req.validate(); err != nil {
		return nil, err
	}

	payload := &schemas.JudicialSuccessionPayload{
		SchemaID:           schemas.SchemaJudicialSuccessionV1,
		TargetDelegation:   req.TargetDelegation,
		SuccessorDID:       req.SuccessorDID,
		Reason:             req.Reason,
		Inheritance:        req.Inheritance,
		NarrowedScope:      req.NarrowedScope,
		EffectiveAt:        bc.now().Format(time.RFC3339Nano),
		AuthoritySetCosigs: req.AuthoritySetCosigs,
	}
	payloadBytes, err := schemas.MarshalJudicialSuccessionPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal payload: %v", ErrInvalidRequest, err)
	}

	target := types.LogPosition{
		LogDID:   req.TargetDelegation.LogDID,
		Sequence: req.TargetDelegation.Sequence,
	}
	entry, err := builder.BuildSuccession(builder.SuccessionParams{
		Destination:  bc.ExchangeDID,
		SignerDID:    req.SignerDID,
		TargetRoot:   target,
		NewSignerDID: req.SuccessorDID,
		Payload:      payloadBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBuildFailed, err)
	}

	display := successionDisplay(bc.InstitutionalDID, payload)
	reason := req.EventReason
	if reason == "" {
		reason = fmt.Sprintf("Succession: %s → %s (%s)",
			req.TargetDelegation.LogDID, req.SuccessorDID, req.Reason)
	}

	pos, err := signAndSubmit(ctx, bc, entry, display, reason)
	if err != nil {
		return nil, err
	}
	return &SuccessionResult{Position: pos, Payload: payload}, nil
}

// successionDisplay renders the EIP-712 typed-data for the wallet
// UX. The institutional DID's Authority_Set members see the
// succession's targets and inheritance mode before approving.
func successionDisplay(institutionalDID string, p *schemas.JudicialSuccessionPayload) *identity.TypedDataDisplay {
	fields := []identity.EIP712Field{
		{Name: "target_log_did", Type: "string", Value: p.TargetDelegation.LogDID},
		{Name: "target_sequence", Type: "uint64", Value: fmt.Sprintf("%d", p.TargetDelegation.Sequence)},
		{Name: "successor_did", Type: "string", Value: p.SuccessorDID},
		{Name: "reason", Type: "string", Value: p.Reason},
		{Name: "inheritance", Type: "string", Value: p.Inheritance},
		{Name: "effective_at", Type: "string", Value: p.EffectiveAt},
	}
	for i, s := range p.NarrowedScope {
		fields = append(fields, identity.EIP712Field{
			Name:  fmt.Sprintf("narrowed_scope[%d]", i),
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
		PrimaryType: "Succession",
		Fields:      fields,
	}
}

// validate runs structural sanity on a SuccessionRequest.
func (r *SuccessionRequest) validate() error {
	if r.SignerDID == "" {
		return fmt.Errorf("%w: signer_did required", ErrInvalidRequest)
	}
	if r.TargetDelegation.LogDID == "" {
		return fmt.Errorf("%w: target_delegation.log_did required", ErrInvalidRequest)
	}
	if r.SuccessorDID == "" {
		return fmt.Errorf("%w: successor_did required", ErrInvalidRequest)
	}
	if r.Reason == "" {
		return fmt.Errorf("%w: reason required", ErrInvalidRequest)
	}
	switch r.Inheritance {
	case schemas.InheritanceFull, schemas.InheritanceNarrowed, schemas.InheritanceCleanSlate:
	default:
		return fmt.Errorf("%w: inheritance must be one of {full, narrowed, clean_slate}, got %q",
			ErrInvalidRequest, r.Inheritance)
	}
	return nil
}
