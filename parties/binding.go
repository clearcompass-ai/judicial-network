/*
FILE PATH: parties/binding.go
DESCRIPTION: Party-case binding creation on the parties log.
KEY ARCHITECTURAL DECISIONS:
    - BuildRootEntity for new bindings (creates SMT leaf on parties log).
    - BuildAmendment for role changes (witness → co-defendant).
    - Domain Payload carries party_did, case_ref, role, status.
    - Each binding is a root entity — not a sub-entity of the case.
OVERVIEW: CreateBinding → root entity. UpdateBinding → amendment.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/types
*/
package parties

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// BindingConfig configures a new party-case binding.
type BindingConfig struct {
	SignerDID string // Court clerk or authorized officer
	PartyDID  string // Party's real DID
	CaseRef   string // Docket number
	CaseDID   string // Cases log DID (for cross-log reference)
	CaseSeq   uint64 // Case root sequence
	Role      string // plaintiff, defendant, witness, victim, guardian_ad_litem
	SchemaRef *types.LogPosition
	EventTime int64
}

// BindingResult holds the new binding entry.
type BindingResult struct {
	Entry *envelope.Entry
}

// CreateBinding creates a new party-case binding on the parties log.
func CreateBinding(cfg BindingConfig) (*BindingResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("parties/binding: empty signer DID")
	}
	if cfg.PartyDID == "" {
		return nil, fmt.Errorf("parties/binding: empty party DID")
	}
	if cfg.CaseRef == "" {
		return nil, fmt.Errorf("parties/binding: empty case ref")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"party_did": cfg.PartyDID,
		"case_ref":  cfg.CaseRef,
		"case_did":  cfg.CaseDID,
		"case_seq":  cfg.CaseSeq,
		"role":      cfg.Role,
		"status":    "active",
	})

	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		SignerDID: cfg.SignerDID,
		Payload:   payload,
		SchemaRef: cfg.SchemaRef,
		EventTime: cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("parties/binding: build root entity: %w", err)
	}

	return &BindingResult{Entry: entry}, nil
}

// UpdateBindingConfig configures a binding role or status change.
type UpdateBindingConfig struct {
	SignerDID   string // Must be same signer as original binding
	BindingPos  types.LogPosition
	NewRole     string // Empty to keep current
	NewStatus   string // "active", "withdrawn", "dismissed"
	SchemaRef   *types.LogPosition
	EventTime   int64
}

// UpdateBinding amends a party binding (role change or status update).
func UpdateBinding(cfg UpdateBindingConfig) (*envelope.Entry, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("parties/binding: empty signer DID")
	}
	if cfg.BindingPos.IsNull() {
		return nil, fmt.Errorf("parties/binding: null binding position")
	}

	payload := map[string]interface{}{
		"amendment_type": "binding_update",
	}
	if cfg.NewRole != "" {
		payload["new_role"] = cfg.NewRole
	}
	if cfg.NewStatus != "" {
		payload["new_status"] = cfg.NewStatus
	}
	payloadBytes, _ := json.Marshal(payload)

	return builder.BuildAmendment(builder.AmendmentParams{
		SignerDID:  cfg.SignerDID,
		TargetRoot: cfg.BindingPos,
		Payload:    payloadBytes,
		SchemaRef:  cfg.SchemaRef,
		EventTime:  cfg.EventTime,
	})
}
