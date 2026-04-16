/*
FILE PATH: schemas/party_binding_sealed.go
DESCRIPTION: tn-party-binding-sealed-v1. Sealed party bindings for juvenile/family.
    Umbral PRE encryption, sealed grant mode, vendor_specific.
KEY ARCHITECTURAL DECISIONS:
    - Sealed grant: only named authorized recipients can access the identity mapping.
    - vendor_specific: real identity never appears on the log.
    - PRE-encrypted mapping: only scope authority officers can resolve vendor DID → real DID.
    - Same re_encryption_threshold as evidence (m:3, n:5).
OVERVIEW: PartyBindingSealedPayload with vendor_did, encrypted_mapping_cid.
KEY DEPENDENCIES: schemas/registry.go
*/
package schemas

import "encoding/json"

type PartyBindingSealedPayload struct {
	// ── SDK well-known fields ────────────────────────────────────────
	ActivationDelay        int64            `json:"activation_delay,omitempty"`
	OverrideRequiresWitness bool            `json:"override_requires_witness,omitempty"`
	MigrationPolicy        string           `json:"migration_policy,omitempty"`
	ArtifactEncryption     string           `json:"artifact_encryption"`
	GrantAuthorizationMode string           `json:"grant_authorization_mode"`
	GrantEntryRequired     bool             `json:"grant_entry_required"`
	GrantRequiresAuditEntry bool            `json:"grant_requires_audit_entry"`
	ReEncryptionThreshold  *ThresholdConfig `json:"re_encryption_threshold,omitempty"`
	PredecessorSchema      *SchemaPosition  `json:"predecessor_schema,omitempty"`

	// ── Sealed party binding fields ──────────────────────────────────
	VendorDID           string `json:"vendor_did"`                      // opaque DID on the log
	CaseRef             string `json:"case_ref"`
	Role                string `json:"role"`
	Status              string `json:"status"`
	EncryptedMappingCID string `json:"encrypted_mapping_cid,omitempty"` // PRE-encrypted real-identity artifact
	Capsule             string `json:"capsule,omitempty"`               // PRE capsule for the mapping artifact
	PkDel               string `json:"pk_del,omitempty"`                // delegation public key
	CaseDID             string `json:"case_did,omitempty"`
	CaseSeq             uint64 `json:"case_seq,omitempty"`
}

func DefaultPartyBindingSealedParams() []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"identifier_scope":           "vendor_specific",
		"artifact_encryption":        "umbral_pre",
		"grant_authorization_mode":   "sealed",
		"grant_entry_required":       true,
		"grant_requires_audit_entry": true,
		"re_encryption_threshold":    map[string]interface{}{"m": 3, "n": 5},
		"override_requires_witness":  true,
		"migration_policy":           "amendment",
	})
	return b
}

func SerializePartyBindingSealedPayload(p *PartyBindingSealedPayload) ([]byte, error) {
	return json.Marshal(p)
}

func DeserializePartyBindingSealedPayload(data []byte) (*PartyBindingSealedPayload, error) {
	var p PartyBindingSealedPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func partyBindingSealedRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaPartyBindingSealedV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*PartyBindingSealedPayload)
			if !ok { return nil, ErrDeserialize }
			return SerializePartyBindingSealedPayload(p)
		},
		Deserialize:     func(data []byte) (interface{}, error) { return DeserializePartyBindingSealedPayload(data) },
		DefaultParams:   DefaultPartyBindingSealedParams,
		IdentifierScope: IdentifierScopeVendorSpecific,
	}
}
