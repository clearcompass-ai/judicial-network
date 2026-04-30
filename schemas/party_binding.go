/*
FILE PATH: schemas/party_binding.go

DESCRIPTION:
    tn-party-binding-v1 — public party-case bindings on the parties
    log. Per the v1.6 Event Dictionary (Phase 3D.cleanup-3):

      - Parties are NOT network entities and have NO DIDs.
      - party_binding mints a case-local `binding_id` as the only
        public reference to the party.
      - The party's identity (when public) is recorded as
        `party_name`. When sealed, the underlying identity lives
        in the encrypted-mapping CID of the sealed mirror schema
        (tn-party-binding-sealed-v1) and `party_name` is left
        empty — the binding_id is the public reference either way.

KEY ARCHITECTURAL DECISIONS:
    - Closed-set party_class enum — plaintiff / defendant /
      respondent / petitioner / state. Validators reject unknown
      classes.
    - binding_id is opaque to the log — the writer chooses its
      shape (e.g. "p-001", "d-001"). Uniqueness is per case_ref;
      the aggregator (Phase 3E) enforces case-local uniqueness.
    - real_did identifier_scope, AES-GCM encryption restricted
      grant. Restricted grant: scope authority members gate access
      to party data.

OVERVIEW:
    PartyClass            — closed-set role enum.
    PartyBindingPayload   — v1.6 schema.
    Validate              — structural sanity.

KEY DEPENDENCIES:
    - schemas/registry.go (registration)
*/
package schemas

import (
	"encoding/json"
	"errors"
	"fmt"
)

// PartyClass enumerates the closed-set party roles per v1.6 Part 1.
type PartyClass string

const (
	PartyClassPlaintiff  PartyClass = "plaintiff"
	PartyClassDefendant  PartyClass = "defendant"
	PartyClassRespondent PartyClass = "respondent"
	PartyClassPetitioner PartyClass = "petitioner"
	PartyClassState      PartyClass = "state"
)

// IsValid reports whether c is a defined party class.
func (c PartyClass) IsValid() bool {
	switch c {
	case PartyClassPlaintiff, PartyClassDefendant,
		PartyClassRespondent, PartyClassPetitioner, PartyClassState:
		return true
	default:
		return false
	}
}

// PartyBindingPayload is the v1.6 party-binding shape.
type PartyBindingPayload struct {
	// ── SDK well-known fields ────────────────────────────────────────
	ActivationDelay         int64           `json:"activation_delay,omitempty"`
	OverrideRequiresWitness bool            `json:"override_requires_witness,omitempty"`
	MigrationPolicy         string          `json:"migration_policy,omitempty"`
	ArtifactEncryption      string          `json:"artifact_encryption,omitempty"`
	GrantAuthorizationMode  string          `json:"grant_authorization_mode,omitempty"`
	GrantEntryRequired      bool            `json:"grant_entry_required,omitempty"`
	PredecessorSchema       *SchemaPosition `json:"predecessor_schema,omitempty"`

	// ── v1.6 party fields ────────────────────────────────────────────
	// BindingID is the case-local mint. The ONLY public reference
	// to this party. Required, unique per case_ref (uniqueness
	// enforced by the aggregator).
	BindingID string `json:"binding_id"`

	// PartyClass classifies the role per the closed-set enum.
	PartyClass PartyClass `json:"party_class"`

	// PartyName is the public name when the party is not sealed.
	// Empty when sealed (the underlying identity lives in the
	// sealed mirror's encrypted_mapping_cid). Optional.
	PartyName string `json:"party_name,omitempty"`

	// CaseRef is the docket number or case-root CID. Required.
	CaseRef string `json:"case_ref"`

	// Status — "active" | "withdrawn" | "dismissed". SerializePartyBindingPayload
	// defaults empty to "active".
	Status string `json:"status"`

	// FiledDate, CaseDID, CaseSeq — optional cross-log references.
	FiledDate string `json:"filed_date,omitempty"`
	CaseDID   string `json:"case_did,omitempty"`
	CaseSeq   uint64 `json:"case_seq,omitempty"`
}

// ─── Sentinel errors ────────────────────────────────────────────────

var (
	ErrPartyBindingInvalid    = errors.New("schemas/party_binding: invalid")
	ErrPartyBindingUnknownCls = errors.New("schemas/party_binding: party_class not in {plaintiff, defendant, respondent, petitioner, state}")
)

// Validate runs structural sanity.
func (p *PartyBindingPayload) Validate() error {
	if p == nil {
		return fmt.Errorf("%w: nil payload", ErrPartyBindingInvalid)
	}
	if p.BindingID == "" {
		return fmt.Errorf("%w: binding_id required", ErrPartyBindingInvalid)
	}
	if !p.PartyClass.IsValid() {
		return fmt.Errorf("%w: got %q", ErrPartyBindingUnknownCls, string(p.PartyClass))
	}
	if p.CaseRef == "" {
		return fmt.Errorf("%w: case_ref required", ErrPartyBindingInvalid)
	}
	switch p.Status {
	case "", "active", "withdrawn", "dismissed":
	default:
		return fmt.Errorf("%w: status %q not in {active, withdrawn, dismissed}",
			ErrPartyBindingInvalid, p.Status)
	}
	return nil
}

// ─── Default params ─────────────────────────────────────────────────

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

// ─── Serialize / Deserialize ────────────────────────────────────────

func SerializePartyBindingPayload(p *PartyBindingPayload) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil payload", ErrPartyBindingInvalid)
	}
	if p.Status == "" {
		cp := *p
		cp.Status = "active"
		p = &cp
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

func DeserializePartyBindingPayload(data []byte) (*PartyBindingPayload, error) {
	var p PartyBindingPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("schemas/party_binding: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// ─── Registry entry ─────────────────────────────────────────────────

func partyBindingRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaPartyBindingV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*PartyBindingPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializePartyBindingPayload(p)
		},
		Deserialize:     func(data []byte) (interface{}, error) { return DeserializePartyBindingPayload(data) },
		DefaultParams:   DefaultPartyBindingParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
