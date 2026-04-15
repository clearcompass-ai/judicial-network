/*
FILE PATH:
    schemas/juvenile_case.go

DESCRIPTION:
    Defines tn-juvenile-case-v1. AES-GCM encryption, open grant mode.
    Always vendor_specific identifier scope. Automatic sealing at disposition
    per TCA 37-1-153 (sealing_order activation_delay=0).

KEY ARCHITECTURAL DECISIONS:
    - Open grant mode: juvenile case filings use open authorization. Privacy
      is structural (vendor_specific DIDs, auto-seal at disposition), not
      grant-level access control.
    - Auto-seal at disposition: sealing_order activation_delay=0 (immediate).
      TCA 37-1-153 mandates automatic sealing of juvenile records upon
      disposition. Once sealed, the sealing check in retrieve.go blocks access.
    - vendor_specific always: juvenile identities never appear on the log.

OVERVIEW:
    Juvenile case schema with disposition tracking and auto-seal metadata.
    Auto-seal fields (auto_seal_authority, auto_seal_at_disposition) are
    domain-specific — the SDK never reads them.

KEY DEPENDENCIES:
    - schemas/registry.go: SchemaPosition, SchemaRegistration
*/
package schemas

import "encoding/json"

// -------------------------------------------------------------------------------------------------
// 1) Juvenile case Domain Payload
// -------------------------------------------------------------------------------------------------

// JuvenileCasePayload is the Domain Payload for tn-juvenile-case-v1.
type JuvenileCasePayload struct {
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
	DocketNumber    string `json:"docket_number"`
	CaseType        string `json:"case_type"`
	FiledDate       string `json:"filed_date"`
	Status          string `json:"status"`
	Disposition     string `json:"disposition,omitempty"`
	DispositionDate string `json:"disposition_date,omitempty"`
	DocumentCID     string `json:"document_cid,omitempty"`

	// ── Auto-seal metadata ───────────────────────────────────────────
	AutoSealAuthority     string `json:"auto_seal_authority,omitempty"`
	AutoSealAtDisposition bool   `json:"auto_seal_at_disposition,omitempty"`
}

// -------------------------------------------------------------------------------------------------
// 2) Schema entry defaults
// -------------------------------------------------------------------------------------------------

func DefaultJuvenileCaseParams() []byte {
	params := map[string]interface{}{
		"identifier_scope":           "vendor_specific",
		"override_requires_witness":  true,
		"artifact_encryption":        "aes_gcm",
		"grant_authorization_mode":   "open",
		"grant_entry_required":       false,
		"grant_requires_audit_entry": false,
		"migration_policy":           "amendment",
		"auto_seal_authority":        "TCA 37-1-153",
		"auto_seal_at_disposition":   true,
		"enforcement_behaviors": map[string]interface{}{
			"sealing_order":   map[string]interface{}{"activation_delay": 0, "cosignatures": 0},
			"unsealing_order": map[string]interface{}{"activation_delay": 604800, "cosignatures": 1},
		},
	}
	b, _ := json.Marshal(params)
	return b
}

// -------------------------------------------------------------------------------------------------
// 3) Serialization
// -------------------------------------------------------------------------------------------------

func SerializeJuvenileCasePayload(p *JuvenileCasePayload) ([]byte, error) { return json.Marshal(p) }

func DeserializeJuvenileCasePayload(data []byte) (*JuvenileCasePayload, error) {
	var p JuvenileCasePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Registry registration
// -------------------------------------------------------------------------------------------------

func juvenileCaseRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaJuvenileCaseV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*JuvenileCasePayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeJuvenileCasePayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) { return DeserializeJuvenileCasePayload(data) },
		DefaultParams:   DefaultJuvenileCaseParams,
		IdentifierScope: IdentifierScopeVendorSpecific,
	}
}
