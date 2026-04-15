/*
FILE PATH:
    schemas/family_case.go

DESCRIPTION:
    Defines tn-family-case-v1. AES-GCM encryption, open grant mode.
    Always vendor_specific identifier scope — all parties get vendor-specific
    DIDs to protect family privacy.

KEY ARCHITECTURAL DECISIONS:
    - vendor_specific always: no real DIDs appear on the log for family cases.
    - Open grant mode: routine family case filings accessible without
      scope authority gating. Privacy is structural (vendor-specific DIDs),
      not access-control-based.

OVERVIEW:
    Family case schema (divorce, custody, adoption). CaseSubType for
    sub-classification. Vendor-specific DIDs protect participant identity.

KEY DEPENDENCIES:
    - schemas/registry.go: SchemaPosition, SchemaRegistration
*/
package schemas

import "encoding/json"

// -------------------------------------------------------------------------------------------------
// 1) Family case Domain Payload
// -------------------------------------------------------------------------------------------------

// FamilyCasePayload is the Domain Payload for tn-family-case-v1.
type FamilyCasePayload struct {
	// ── SDK well-known fields ────────────────────────────────────────
	ActivationDelay         int64           `json:"activation_delay,omitempty"`
	CosignatureThreshold    int             `json:"cosignature_threshold,omitempty"`
	OverrideRequiresWitness bool            `json:"override_requires_witness,omitempty"`
	MigrationPolicy         string          `json:"migration_policy,omitempty"`
	ArtifactEncryption      string          `json:"artifact_encryption,omitempty"`
	GrantAuthorizationMode  string          `json:"grant_authorization_mode,omitempty"`
	GrantEntryRequired      bool            `json:"grant_entry_required,omitempty"`
	GrantRequiresAuditEntry bool            `json:"grant_requires_audit_entry,omitempty"`
	PredecessorSchema       *SchemaPosition `json:"predecessor_schema,omitempty"`

	// ── Judicial fields ──────────────────────────────────────────────
	DocketNumber string `json:"docket_number"`
	CaseType     string `json:"case_type"`
	FiledDate    string `json:"filed_date"`
	Status       string `json:"status"`
	CaseSubType  string `json:"case_sub_type,omitempty"`
	DocumentCID  string `json:"document_cid,omitempty"`
}

// -------------------------------------------------------------------------------------------------
// 2) Schema entry defaults
// -------------------------------------------------------------------------------------------------

func DefaultFamilyCaseParams() []byte {
	params := map[string]interface{}{
		"identifier_scope":           "vendor_specific",
		"override_requires_witness":  true,
		"artifact_encryption":        "aes_gcm",
		"grant_authorization_mode":   "open",
		"grant_entry_required":       false,
		"grant_requires_audit_entry": false,
		"migration_policy":           "amendment",
		"enforcement_behaviors": map[string]interface{}{
			"sealing_order":   map[string]interface{}{"activation_delay": 259200, "cosignatures": 0},
			"unsealing_order": map[string]interface{}{"activation_delay": 604800, "cosignatures": 1},
		},
	}
	b, _ := json.Marshal(params)
	return b
}

// -------------------------------------------------------------------------------------------------
// 3) Serialization
// -------------------------------------------------------------------------------------------------

func SerializeFamilyCasePayload(p *FamilyCasePayload) ([]byte, error) { return json.Marshal(p) }

func DeserializeFamilyCasePayload(data []byte) (*FamilyCasePayload, error) {
	var p FamilyCasePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Registry registration
// -------------------------------------------------------------------------------------------------

func familyCaseRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaFamilyCaseV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*FamilyCasePayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeFamilyCasePayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) { return DeserializeFamilyCasePayload(data) },
		DefaultParams:   DefaultFamilyCaseParams,
		IdentifierScope: IdentifierScopeVendorSpecific,
	}
}
