/*
FILE PATH: parties/binding.go

DESCRIPTION:

	Party-case binding creation on the parties log. Per the v1.6
	Event Dictionary (.cleanup-3): parties have NO DIDs.
	The party_binding event mints a case-local `binding_id` as the
	only public reference; the party's name (when public) is in
	the payload's PartyName field.

KEY ARCHITECTURAL DECISIONS:
  - BuildRootEntity for new bindings (creates SMT leaf on the
    parties log).
  - BuildAmendment for status changes (active → withdrawn →
    dismissed).
  - Domain Payload carries binding_id, party_class, party_name,
    case_ref, status — all routed through the typed
    schemas.PartyBindingPayload.
  - Each binding is a root entity — not a sub-entity of the case.

OVERVIEW:

	BindingConfig + CreateBinding → root entity.
	UpdateBindingConfig + UpdateBinding → status amendment.

KEY DEPENDENCIES:
  - schemas.PartyBindingPayload (typed v1.6 shape).
  - attesta/builder (BuildRootEntity, BuildAmendment).
*/
package parties

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// BindingConfig configures a new party-case binding.
type BindingConfig struct {
	Destination string // DID of target exchange. Required.
	SignerDID   string // Court clerk or authorized officer (Signer). Required.

	// BindingID is the case-local mint (e.g., "p-001", "d-001").
	// Required, unique per CaseRef. The aggregator
	// enforces case-local uniqueness; the writer is responsible
	// for generating a non-colliding value.
	BindingID string

	// PartyClass — plaintiff/defendant/respondent/petitioner/state.
	// Required. Validated against the schemas.PartyClass closed set.
	PartyClass schemas.PartyClass

	// PartyName — public name when the binding is not sealed;
	// empty otherwise. Optional.
	PartyName string

	CaseRef string // Docket number. Required.
	CaseDID string // Cases log DID (cross-log reference). Optional.
	CaseSeq uint64 // Case root sequence on the cases log. Optional.

	SchemaRef *types.LogPosition
	EventTime int64
}

// BindingResult holds the new binding entry.
type BindingResult struct {
	Entry   *envelope.Entry
	Payload *schemas.PartyBindingPayload // echoed for audit-trail correlation
}

// CreateBinding creates a new party-case binding on the parties log.
func CreateBinding(cfg BindingConfig) (*BindingResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("parties/binding: empty signer DID")
	}
	if cfg.BindingID == "" {
		return nil, fmt.Errorf("parties/binding: empty binding_id")
	}
	if !cfg.PartyClass.IsValid() {
		return nil, fmt.Errorf("parties/binding: invalid party_class %q", string(cfg.PartyClass))
	}
	if cfg.CaseRef == "" {
		return nil, fmt.Errorf("parties/binding: empty case_ref")
	}

	payload := &schemas.PartyBindingPayload{
		BindingID:  cfg.BindingID,
		PartyClass: cfg.PartyClass,
		PartyName:  cfg.PartyName,
		CaseRef:    cfg.CaseRef,
		CaseDID:    cfg.CaseDID,
		CaseSeq:    cfg.CaseSeq,
		Status:     "active",
	}
	body, err := schemas.SerializePartyBindingPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("parties/binding: serialize: %w", err)
	}

	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: cfg.Destination,
		SignerDID:   cfg.SignerDID,
		Payload:     body,
		SchemaRef:   cfg.SchemaRef,
		EventTime:   cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("parties/binding: build root entity: %w", err)
	}

	return &BindingResult{Entry: entry, Payload: payload}, nil
}

// UpdateBindingConfig configures a binding status change.
type UpdateBindingConfig struct {
	Destination string // DID of target exchange. Required.
	SignerDID   string // Must be same signer as original binding.
	BindingPos  types.LogPosition

	// NewStatus — "active" | "withdrawn" | "dismissed". Required.
	// (PartyClass is structural — once a defendant, always a
	// defendant for that binding. Identity changes mint a new
	// binding_id; this amendment only changes lifecycle status.)
	NewStatus string

	SchemaRef *types.LogPosition
	EventTime int64
}

// UpdateBinding amends a party binding's status.
func UpdateBinding(cfg UpdateBindingConfig) (*envelope.Entry, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("parties/binding: empty signer DID")
	}
	if cfg.BindingPos.IsNull() {
		return nil, fmt.Errorf("parties/binding: null binding position")
	}
	switch cfg.NewStatus {
	case "active", "withdrawn", "dismissed":
	default:
		return nil, fmt.Errorf("parties/binding: invalid status %q (want active|withdrawn|dismissed)",
			cfg.NewStatus)
	}

	payloadBytes, _ := json.Marshal(map[string]interface{}{
		"amendment_type": "binding_update",
		"new_status":     cfg.NewStatus,
	})

	return builder.BuildAmendment(builder.AmendmentParams{
		Destination: cfg.Destination,
		SignerDID:   cfg.SignerDID,
		TargetRoot:  cfg.BindingPos,
		Payload:     payloadBytes,
		SchemaRef:   cfg.SchemaRef,
		EventTime:   cfg.EventTime,
	})
}
