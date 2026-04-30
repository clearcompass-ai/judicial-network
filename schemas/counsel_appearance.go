/*
FILE PATH: schemas/counsel_appearance.go

DESCRIPTION:
    tn-counsel-appearance-v1 — attorney goes on record as
    representing one or more parties on a case root. Mints a
    case-local `appearance_id`. Per v1.8 §1:

      - The attorney has a network DID (recorded as
        attorney_did); the represented parties are referenced
        by their case-local binding_id values minted by prior
        party_binding events on this case root.
      - Withdrawals (counsel_withdrawal, motion_withdraw_counsel)
        reference this event's appearance_id.
      - The cosignature mix at the bundle requires court_clerk
        cosignature; the attorney is a Filer (no signing key).

KEY ARCHITECTURAL DECISIONS:
    - appearance_id is opaque to the log — the writer chooses
      its shape (e.g. "ap-001"). Uniqueness is per case_ref;
      the aggregator enforces case-local uniqueness.
    - represents is a list of binding_id strings. The order is
      preserved so the aggregator can reconstruct
      attorney→party associations exactly.
    - Per v1.8 prereq policy: case_initiated is Hard ancestor;
      every binding_id in represents is Advisory ancestor
      (legitimate cross-ordering occurs in real filings).

OVERVIEW:
    CounselAppearancePayload  — v1.8 schema.
    Validate                  — structural sanity.
    Serialize / Deserialize   — JSON round-trip.

KEY DEPENDENCIES:
    - schemas/registry.go (registration).
*/
package schemas

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SchemaCounselAppearanceV1 is the schema URI.
const SchemaCounselAppearanceV1 = "tn-counsel-appearance-v1"

// CounselAppearancePayload is the v1.8 counsel_appearance shape.
type CounselAppearancePayload struct {
	// ── SDK well-known fields ────────────────────────────────────────
	ActivationDelay         int64           `json:"activation_delay,omitempty"`
	OverrideRequiresWitness bool            `json:"override_requires_witness,omitempty"`
	MigrationPolicy         string          `json:"migration_policy,omitempty"`
	ArtifactEncryption      string          `json:"artifact_encryption,omitempty"`
	GrantAuthorizationMode  string          `json:"grant_authorization_mode,omitempty"`
	GrantEntryRequired      bool            `json:"grant_entry_required,omitempty"`
	PredecessorSchema       *SchemaPosition `json:"predecessor_schema,omitempty"`

	// ── v1.8 counsel_appearance fields ───────────────────────────────

	// AppearanceID is the case-local mint. The ONLY public
	// reference to this appearance. Required, unique per
	// case_ref (uniqueness enforced by the aggregator).
	AppearanceID string `json:"appearance_id"`

	// AttorneyDID is the network DID of the attorney filing the
	// appearance. Required.
	AttorneyDID string `json:"attorney_did"`

	// Represents lists every binding_id this appearance covers.
	// Each entry must reference a prior party_binding on the
	// same case root (Advisory prereq — see prerequisites).
	// Length ≥ 1 required; at least one party must be represented.
	Represents []string `json:"represents"`

	// CaseRef is the docket number or case-root CID. Required.
	CaseRef string `json:"case_ref"`

	// Status — "active" | "withdrawn". Defaults to "active" on
	// serialize when empty. counsel_withdrawal flips this to
	// "withdrawn" on the case root via amendment.
	Status string `json:"status"`

	// FiledDate, CaseDID, CaseSeq — optional cross-log refs.
	FiledDate string `json:"filed_date,omitempty"`
	CaseDID   string `json:"case_did,omitempty"`
	CaseSeq   uint64 `json:"case_seq,omitempty"`
}

// ─── Sentinel errors ────────────────────────────────────────────────

var (
	ErrCounselAppearanceInvalid = errors.New("schemas/counsel_appearance: invalid")
)

// Validate runs structural sanity. Returns the first violation
// it finds; callers append context as needed.
func (p *CounselAppearancePayload) Validate() error {
	if p == nil {
		return fmt.Errorf("%w: nil payload", ErrCounselAppearanceInvalid)
	}
	if p.AppearanceID == "" {
		return fmt.Errorf("%w: appearance_id required", ErrCounselAppearanceInvalid)
	}
	if p.AttorneyDID == "" {
		return fmt.Errorf("%w: attorney_did required", ErrCounselAppearanceInvalid)
	}
	if len(p.Represents) == 0 {
		return fmt.Errorf("%w: represents must list ≥1 binding_id",
			ErrCounselAppearanceInvalid)
	}
	for i, b := range p.Represents {
		if b == "" {
			return fmt.Errorf("%w: represents[%d] is empty",
				ErrCounselAppearanceInvalid, i)
		}
	}
	if p.CaseRef == "" {
		return fmt.Errorf("%w: case_ref required", ErrCounselAppearanceInvalid)
	}
	switch p.Status {
	case "", "active", "withdrawn":
	default:
		return fmt.Errorf("%w: status %q not in {active, withdrawn}",
			ErrCounselAppearanceInvalid, p.Status)
	}
	return nil
}

// ─── Default params ─────────────────────────────────────────────────

// DefaultCounselAppearanceParams returns the SDK well-known
// envelope-params for counsel_appearance entries.
func DefaultCounselAppearanceParams() []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"identifier_scope":           "real_did",
		"artifact_encryption":        "aes_gcm",
		"grant_authorization_mode":   "open",
		"grant_entry_required":       false,
		"grant_requires_audit_entry": false,
		"override_requires_witness":  false,
		"migration_policy":           "amendment",
	})
	return b
}

// ─── Serialize / Deserialize ────────────────────────────────────────

// SerializeCounselAppearancePayload validates p and JSON-encodes
// it. Defaults Status to "active" if empty.
func SerializeCounselAppearancePayload(p *CounselAppearancePayload) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil payload", ErrCounselAppearanceInvalid)
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

// DeserializeCounselAppearancePayload parses JSON bytes into a
// validated CounselAppearancePayload.
func DeserializeCounselAppearancePayload(data []byte) (*CounselAppearancePayload, error) {
	var p CounselAppearancePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("schemas/counsel_appearance: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// ─── Registry entry ─────────────────────────────────────────────────

// counselAppearanceRegistration returns the SchemaRegistration
// for tn-counsel-appearance-v1.
func counselAppearanceRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaCounselAppearanceV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*CounselAppearancePayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeCounselAppearancePayload(p)
		},
		Deserialize:     func(data []byte) (interface{}, error) { return DeserializeCounselAppearancePayload(data) },
		DefaultParams:   DefaultCounselAppearanceParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
