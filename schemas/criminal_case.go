/*
FILE PATH:
    schemas/criminal_case.go

DESCRIPTION:
    Defines tn-criminal-case-v1. AES-GCM encryption, open grant mode.
    Sealing order activation delay 72h, unsealing 168h.

KEY ARCHITECTURAL DECISIONS:
    - Open grant mode (spec-mandated): routine criminal case filings use
      grant_authorization_mode="open" (the default, zero-value). Any party
      with a valid retrieval request can access. Sealed evidence uses the
      separate tn-evidence-artifact-v1 schema with sealed mode.
    - real_did identifier scope: parties identified by real DIDs.
    - Commutative operations limited to witness_attestation.

OVERVIEW:
    Schema parameters: artifact_encryption=aes_gcm, grant_authorization_mode=open,
    grant_entry_required=false, override_requires_witness=true. Enforcement:
    sealing 72h/0 cosig, unsealing 168h/1 cosig.

KEY DEPENDENCIES:
    - schemas/registry.go: ThresholdConfig, SchemaPosition, SchemaRegistration
*/
package schemas

import "encoding/json"

// -------------------------------------------------------------------------------------------------
// 1) Enforcement behavior types
// -------------------------------------------------------------------------------------------------

// SealingBehavior configures activation delay and cosignature requirements.
type SealingBehavior struct {
	ActivationDelay int64 `json:"activation_delay"`
	Cosignatures    int   `json:"cosignatures"`
}

// CaseEnforcementBehaviors groups enforcement behaviors for a case schema.
type CaseEnforcementBehaviors struct {
	SealingOrder   SealingBehavior `json:"sealing_order"`
	UnsealingOrder SealingBehavior `json:"unsealing_order"`
}

// -------------------------------------------------------------------------------------------------
// 2) Criminal case Domain Payload
// -------------------------------------------------------------------------------------------------

// CriminalCasePayload is the Domain Payload for tn-criminal-case-v1.
type CriminalCasePayload struct {
	// ── SDK well-known fields ────────────────────────────────────────
	ActivationDelay         int64            `json:"activation_delay,omitempty"`
	CosignatureThreshold    int              `json:"cosignature_threshold,omitempty"`
	MaturationEpoch         int64            `json:"maturation_epoch,omitempty"`
	OverrideRequiresWitness bool             `json:"override_requires_witness,omitempty"`
	MigrationPolicy         string           `json:"migration_policy,omitempty"`
	ArtifactEncryption      string           `json:"artifact_encryption,omitempty"`
	GrantAuthorizationMode  string           `json:"grant_authorization_mode,omitempty"`
	GrantEntryRequired      bool             `json:"grant_entry_required,omitempty"`
	GrantRequiresAuditEntry bool             `json:"grant_requires_audit_entry,omitempty"`
	ReEncryptionThreshold   *ThresholdConfig `json:"re_encryption_threshold,omitempty"`
	PredecessorSchema       *SchemaPosition  `json:"predecessor_schema,omitempty"`

	// ── Judicial fields (public) ─────────────────────────────────────
	DocketNumber string   `json:"docket_number"`
	CaseType     string   `json:"case_type"`
	FiledDate    string   `json:"filed_date"`
	Status       string   `json:"status"`
	Charges      []string `json:"charges,omitempty"`
	DocumentCID  string   `json:"document_cid,omitempty"`

	// ── Judicial fields (private) ────────────────────────────────────
	VictimInfo     string   `json:"victim_info,omitempty"`
	SealedExhibits []string `json:"sealed_exhibits,omitempty"`
}

// -------------------------------------------------------------------------------------------------
// 3) Schema entry defaults
// -------------------------------------------------------------------------------------------------

func DefaultCriminalCaseParams() []byte {
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
		"commutative_operations": []string{"witness_attestation"},
	}
	b, _ := json.Marshal(params)
	return b
}

// -------------------------------------------------------------------------------------------------
// 4) Serialization
// -------------------------------------------------------------------------------------------------

func SerializeCriminalCasePayload(p *CriminalCasePayload) ([]byte, error) {
	return json.Marshal(p)
}

func DeserializeCriminalCasePayload(data []byte) (*CriminalCasePayload, error) {
	var p CriminalCasePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// -------------------------------------------------------------------------------------------------
// 5) Registry registration
// -------------------------------------------------------------------------------------------------

func criminalCaseRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaCriminalCaseV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*CriminalCasePayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeCriminalCasePayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return DeserializeCriminalCasePayload(data)
		},
		DefaultParams:   DefaultCriminalCaseParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
