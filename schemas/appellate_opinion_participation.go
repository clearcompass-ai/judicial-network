/*
FILE PATH: schemas/appellate_opinion_participation.go

DESCRIPTION:

	tn-appellate-opinion-participation-v1 — a judge's
	relationship to a specific opinion. Per v1.8 §7B.2:

	  - One participation event per (judge, opinion).
	  - References opinion_id from the publication event.
	  - role: closed-set per the destination Bundle's
	    AppellateVocabulary.ParticipationRoles.
	  - parts: optional list when role is joined_in_part /
	    joined_except_as_to.

	Multiple participation events compose freely: a single
	judge in a single case can join one opinion, dissent from
	another, and recuse from a third.
*/
package schemas

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SchemaAppellateOpinionParticipationV1 is the schema URI.
const SchemaAppellateOpinionParticipationV1 = "tn-appellate-opinion-participation-v1"

// AppellateOpinionParticipationPayload is the v1.8 §7B.2 shape.
type AppellateOpinionParticipationPayload struct {
	// ── SDK well-known fields ────────────────────────────────────────
	ActivationDelay         int64           `json:"activation_delay,omitempty"`
	OverrideRequiresWitness bool            `json:"override_requires_witness,omitempty"`
	MigrationPolicy         string          `json:"migration_policy,omitempty"`
	ArtifactEncryption      string          `json:"artifact_encryption,omitempty"`
	GrantAuthorizationMode  string          `json:"grant_authorization_mode,omitempty"`
	GrantEntryRequired      bool            `json:"grant_entry_required,omitempty"`
	PredecessorSchema       *SchemaPosition `json:"predecessor_schema,omitempty"`

	// ── v1.8 §7B.2 fields ─────────────────────────────────────────────

	// OpinionID references the publication event's mint. Required.
	OpinionID string `json:"opinion_id"`

	// JudgeDID is the participating Adjudicator's DID. Required.
	JudgeDID string `json:"judge_did"`

	// Role is the v1.8 §7B.2 enum value (joined,
	// joined_in_part, joined_except_as_to, did_not_join,
	// recused, did_not_participate). Per-jurisdiction membership
	// validated by the verifier against
	// bundle.AppellateVocabulary().ParticipationRoles().
	Role string `json:"role"`

	// Parts is the part-identifier list when Role is
	// joined_in_part or joined_except_as_to; nil/empty
	// otherwise.
	Parts []string `json:"parts,omitempty"`

	// CaseRef is the appellate case-root reference. Required.
	CaseRef string `json:"case_ref"`

	// FiledDate, CaseDID, CaseSeq — optional cross-log refs.
	FiledDate string `json:"filed_date,omitempty"`
	CaseDID   string `json:"case_did,omitempty"`
	CaseSeq   uint64 `json:"case_seq,omitempty"`
}

var (
	ErrOpinionParticipationInvalid = errors.New("schemas/appellate_opinion_participation: invalid")
)

// Validate runs structural sanity. Per-jurisdiction Role enum
// membership is enforced separately by the verifier.
func (p *AppellateOpinionParticipationPayload) Validate() error {
	if p == nil {
		return fmt.Errorf("%w: nil payload", ErrOpinionParticipationInvalid)
	}
	if p.OpinionID == "" {
		return fmt.Errorf("%w: opinion_id required", ErrOpinionParticipationInvalid)
	}
	if p.JudgeDID == "" {
		return fmt.Errorf("%w: judge_did required", ErrOpinionParticipationInvalid)
	}
	if p.Role == "" {
		return fmt.Errorf("%w: role required", ErrOpinionParticipationInvalid)
	}
	if p.CaseRef == "" {
		return fmt.Errorf("%w: case_ref required", ErrOpinionParticipationInvalid)
	}
	return nil
}

// DefaultOpinionParticipationParams returns the SDK envelope-params.
func DefaultOpinionParticipationParams() []byte {
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

// SerializeOpinionParticipationPayload validates p and JSON-encodes.
func SerializeOpinionParticipationPayload(p *AppellateOpinionParticipationPayload) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil payload", ErrOpinionParticipationInvalid)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// DeserializeOpinionParticipationPayload parses + validates.
func DeserializeOpinionParticipationPayload(data []byte) (*AppellateOpinionParticipationPayload, error) {
	var p AppellateOpinionParticipationPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("schemas/appellate_opinion_participation: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func opinionParticipationRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaAppellateOpinionParticipationV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*AppellateOpinionParticipationPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeOpinionParticipationPayload(p)
		},
		Deserialize:     func(data []byte) (interface{}, error) { return DeserializeOpinionParticipationPayload(data) },
		DefaultParams:   DefaultOpinionParticipationParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
