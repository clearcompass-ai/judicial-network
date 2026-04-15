/*
FILE PATH:
    schemas/civil_case.go

DESCRIPTION:
    Defines tn-civil-case-v1. AES-GCM encryption, open grant mode,
    real_did identifier scope. Always real_did, aes_gcm, open, no grant entry.

KEY ARCHITECTURAL DECISIONS:
    - Open grant mode: no authorization check on routine civil filings.
    - Same sealing/unsealing enforcement behaviors as criminal case.

OVERVIEW:
    Civil litigation schema with plaintiff/defendant/claim_amount fields.
    All SDK well-known fields included for SchemaParameterExtractor delegation.

KEY DEPENDENCIES:
    - schemas/registry.go: ThresholdConfig, SchemaPosition, SchemaRegistration
*/
package schemas

import "encoding/json"

// -------------------------------------------------------------------------------------------------
// 1) Civil case Domain Payload
// -------------------------------------------------------------------------------------------------

// CivilCasePayload is the Domain Payload for tn-civil-case-v1.
type CivilCasePayload struct {
	// ── SDK well-known fields ────────────────────────────────────────
	ActivationDelay         int64            `json:"activation_delay,omitempty"`
	CosignatureThreshold    int              `json:"cosignature_threshold,omitempty"`
	OverrideRequiresWitness bool             `json:"override_requires_witness,omitempty"`
	MigrationPolicy         string           `json:"migration_policy,omitempty"`
	ArtifactEncryption      string           `json:"artifact_encryption,omitempty"`
	GrantAuthorizationMode  string           `json:"grant_authorization_mode,omitempty"`
	GrantEntryRequired      bool             `json:"grant_entry_required,omitempty"`
	GrantRequiresAuditEntry bool             `json:"grant_requires_audit_entry,omitempty"`
	ReEncryptionThreshold   *ThresholdConfig `json:"re_encryption_threshold,omitempty"`
	PredecessorSchema       *SchemaPosition  `json:"predecessor_schema,omitempty"`

	// ── Judicial fields ──────────────────────────────────────────────
	DocketNumber string `json:"docket_number"`
	CaseType     string `json:"case_type"`
	FiledDate    string `json:"filed_date"`
	Status       string `json:"status"`
	Plaintiff    string `json:"plaintiff,omitempty"`
	Defendant    string `json:"defendant,omitempty"`
	ClaimAmount  string `json:"claim_amount,omitempty"`
	DocumentCID  string `json:"document_cid,omitempty"`
}

// -------------------------------------------------------------------------------------------------
// 2) Schema entry defaults
// -------------------------------------------------------------------------------------------------

func DefaultCivilCaseParams() []byte {
	params := map[string]interface{}{
		"identifier_scope":           "real_did",
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

func SerializeCivilCasePayload(p *CivilCasePayload) ([]byte, error) { return json.Marshal(p) }

func DeserializeCivilCasePayload(data []byte) (*CivilCasePayload, error) {
	var p CivilCasePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Registry registration
// -------------------------------------------------------------------------------------------------

func civilCaseRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaCivilCaseV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*CivilCasePayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeCivilCasePayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) { return DeserializeCivilCasePayload(data) },
		DefaultParams:   DefaultCivilCaseParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
