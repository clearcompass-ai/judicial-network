/*
FILE PATH: schemas/appellate_opinion_publication.go

DESCRIPTION:

	tn-appellate-opinion-publication-v1 — publication of an
	opinion by an appellate panel. Mints the case-local
	`opinion_id`. Per v1.8 §7B.2:

	  - Case-local mint: opinion_id is unique within an
	    appellate case root (the aggregator enforces).
	  - opinion_type: closed-set per the destination Bundle's
	    AppellateVocabulary (jurisdiction.AppellateVocab).
	  - author_did: the authoring Adjudicator's DID, or empty
	    for per_curiam.
	  - parts: optional list of part identifiers for opinions
	    structurally subdivided to support join-by-section.

	The schema layer pins the structural shape; per-jurisdiction
	enum membership is enforced by the verifier consulting the
	Bundle's AppellateVocabulary at submit time.
*/
package schemas

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SchemaAppellateOpinionPublicationV1 is the schema URI.
const SchemaAppellateOpinionPublicationV1 = "tn-appellate-opinion-publication-v1"

// AppellateOpinionPublicationPayload is the v1.8 §7B.2 shape.
type AppellateOpinionPublicationPayload struct {
	// ── SDK well-known fields ────────────────────────────────────────
	ActivationDelay         int64           `json:"activation_delay,omitempty"`
	OverrideRequiresWitness bool            `json:"override_requires_witness,omitempty"`
	MigrationPolicy         string          `json:"migration_policy,omitempty"`
	ArtifactEncryption      string          `json:"artifact_encryption,omitempty"`
	GrantAuthorizationMode  string          `json:"grant_authorization_mode,omitempty"`
	GrantEntryRequired      bool            `json:"grant_entry_required,omitempty"`
	PredecessorSchema       *SchemaPosition `json:"predecessor_schema,omitempty"`

	// ── v1.8 §7B.2 fields ─────────────────────────────────────────────

	// OpinionID is the case-local mint. Required.
	OpinionID string `json:"opinion_id"`

	// OpinionType is the v1.8 §7B.2 enum value. Validated
	// against bundle.AppellateVocabulary().OpinionTypes() at
	// submit time. Required, non-empty.
	OpinionType string `json:"opinion_type"`

	// AuthorDID is the authoring Adjudicator's DID. Empty for
	// per_curiam.
	AuthorDID string `json:"author_did,omitempty"`

	// Parts is the optional part-identifier list for
	// structurally subdivided opinions.
	Parts []string `json:"parts,omitempty"`

	// ContentHash is the cryptographic hash of the opinion
	// text. The text itself lives in artifact storage.
	ContentHash string `json:"content_hash,omitempty"`

	// CaseRef is the appellate case-root reference. Required.
	CaseRef string `json:"case_ref"`

	// FiledDate, CaseDID, CaseSeq — optional cross-log refs.
	FiledDate string `json:"filed_date,omitempty"`
	CaseDID   string `json:"case_did,omitempty"`
	CaseSeq   uint64 `json:"case_seq,omitempty"`
}

// ─── Sentinel errors ────────────────────────────────────────────────

var (
	ErrOpinionPublicationInvalid = errors.New("schemas/appellate_opinion_publication: invalid")
)

// Validate runs structural sanity. Per-jurisdiction OpinionType
// enum membership is enforced separately by the verifier.
func (p *AppellateOpinionPublicationPayload) Validate() error {
	if p == nil {
		return fmt.Errorf("%w: nil payload", ErrOpinionPublicationInvalid)
	}
	if p.OpinionID == "" {
		return fmt.Errorf("%w: opinion_id required", ErrOpinionPublicationInvalid)
	}
	if p.OpinionType == "" {
		return fmt.Errorf("%w: opinion_type required", ErrOpinionPublicationInvalid)
	}
	if p.CaseRef == "" {
		return fmt.Errorf("%w: case_ref required", ErrOpinionPublicationInvalid)
	}
	return nil
}

// ─── Default params ─────────────────────────────────────────────────

// DefaultOpinionPublicationParams returns the SDK well-known
// envelope-params.
func DefaultOpinionPublicationParams() []byte {
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

// SerializeOpinionPublicationPayload validates p and JSON-encodes.
func SerializeOpinionPublicationPayload(p *AppellateOpinionPublicationPayload) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil payload", ErrOpinionPublicationInvalid)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// DeserializeOpinionPublicationPayload parses + validates.
func DeserializeOpinionPublicationPayload(data []byte) (*AppellateOpinionPublicationPayload, error) {
	var p AppellateOpinionPublicationPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("schemas/appellate_opinion_publication: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// ─── Registry entry ─────────────────────────────────────────────────

func opinionPublicationRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaAppellateOpinionPublicationV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*AppellateOpinionPublicationPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeOpinionPublicationPayload(p)
		},
		Deserialize:     func(data []byte) (interface{}, error) { return DeserializeOpinionPublicationPayload(data) },
		DefaultParams:   DefaultOpinionPublicationParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
