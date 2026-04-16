/*
FILE PATH: schemas/party_binding.go
DESCRIPTION: tn-party-binding-v1. Public party-case bindings on the parties log.
    AES-GCM encryption, restricted grant mode, real_did.
KEY ARCHITECTURAL DECISIONS:
    - Restricted grant: scope authority members gate access to party data.
    - real_did: parties in criminal/civil cases use real DIDs.
    - Root entities on parties log, linked to cases via cross-log commentary.
OVERVIEW: PartyBindingPayload with role, case_ref, status.
KEY DEPENDENCIES: schemas/registry.go
*/
package schemas

import "encoding/json"

type PartyBindingPayload struct {
	// ── SDK well-known fields ────────────────────────────────────────
	ActivationDelay        int64           `json:"activation_delay,omitempty"`
	OverrideRequiresWitness bool           `json:"override_requires_witness,omitempty"`
	MigrationPolicy        string          `json:"migration_policy,omitempty"`
	ArtifactEncryption     string          `json:"artifact_encryption,omitempty"`
	GrantAuthorizationMode string          `json:"grant_authorization_mode,omitempty"`
	GrantEntryRequired     bool            `json:"grant_entry_required,omitempty"`
	PredecessorSchema      *SchemaPosition `json:"predecessor_schema,omitempty"`

	// ── Party binding fields ─────────────────────────────────────────
	PartyDID  string `json:"party_did"`
	CaseRef   string `json:"case_ref"`             // docket number or case root CID
	Role      string `json:"role"`                  // plaintiff, defendant, witness, victim, guardian
	Status    string `json:"status"`                // active, withdrawn, dismissed
	FiledDate string `json:"filed_date,omitempty"`
	CaseDID   string `json:"case_did,omitempty"`    // cases log DID for cross-log reference
	CaseSeq   uint64 `json:"case_seq,omitempty"`    // case root sequence on cases log
}

func DefaultPartyBindingParams() []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"identifier_scope":           "real_did",
		"artifact_encryption":        "aes_gcm",
		"grant_authorization_mode":   "restricted",
		"grant_entry_required":       true,
		"grant_requires_audit_entry": false,
		"override_requires_witness":  false,
		"migration_policy":           "amendment",
	})
	return b
}

func SerializePartyBindingPayload(p *PartyBindingPayload) ([]byte, error) { return json.Marshal(p) }

func DeserializePartyBindingPayload(data []byte) (*PartyBindingPayload, error) {
	var p PartyBindingPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func partyBindingRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaPartyBindingV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*PartyBindingPayload)
			if !ok { return nil, ErrDeserialize }
			return SerializePartyBindingPayload(p)
		},
		Deserialize:     func(data []byte) (interface{}, error) { return DeserializePartyBindingPayload(data) },
		DefaultParams:   DefaultPartyBindingParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
