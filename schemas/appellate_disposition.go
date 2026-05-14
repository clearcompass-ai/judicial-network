/*
FILE PATH: schemas/appellate_disposition.go

DESCRIPTION:

	tn-appellate-disposition-v1 — the appellate panel's bottom-
	line case outcome. Per v1.8 §7B.3:

	  - outcome: closed-set per the destination Bundle's
	    AppellateVocabulary.DispositionOutcomes (e.g.,
	    affirmed, reversed, vacated, remanded,
	    affirmed_in_part_reversed_in_part, dismissed).
	  - panel: list of participating judge DIDs (typically 3
	    for TN COA, 5 for TN Sup Ct).
	  - vote_tally: informational summary (e.g., "3-0", "2-1").
	    Authoritative source remains the participation events.

	Prereq: at least one merits-level
	appellate_opinion_publication (majority, plurality,
	per_curiam, or memorandum) on this case root. The verifier
	enforces the merits-subset constraint by consulting the
	bundle's MeritsOpinionTypes().
*/
package schemas

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SchemaAppellateDispositionV1 is the schema URI.
const SchemaAppellateDispositionV1 = "tn-appellate-disposition-v1"

// AppellateDispositionPayload is the v1.8 §7B.3 shape.
type AppellateDispositionPayload struct {
	// ── SDK well-known fields ──────────────────────────────────────
	ActivationDelay         int64           `json:"activation_delay,omitempty"`
	OverrideRequiresWitness bool            `json:"override_requires_witness,omitempty"`
	MigrationPolicy         string          `json:"migration_policy,omitempty"`
	ArtifactEncryption      string          `json:"artifact_encryption,omitempty"`
	GrantAuthorizationMode  string          `json:"grant_authorization_mode,omitempty"`
	GrantEntryRequired      bool            `json:"grant_entry_required,omitempty"`
	PredecessorSchema       *SchemaPosition `json:"predecessor_schema,omitempty"`

	// ── v1.8 §7B.3 fields ──────────────────────────────────────────

	// Outcome is the closed-set v1.8 §7B.3 enum value.
	// Per-jurisdiction membership validated by the verifier
	// against bundle.AppellateVocabulary().DispositionOutcomes().
	// Required.
	Outcome string `json:"outcome"`

	// Panel is the list of participating judge DIDs. Required,
	// length ≥ 1. The cosig fixture enforces the per-Bundle
	// quorum (3 for TN COA, 3 for TN Sup Ct).
	Panel []string `json:"panel"`

	// VoteTally is the informational summary. Authoritative
	// source remains the participation events. Optional.
	VoteTally string `json:"vote_tally,omitempty"`

	// CaseRef is the appellate case-root reference. Required.
	CaseRef string `json:"case_ref"`

	// FiledDate, CaseDID, CaseSeq — optional cross-log refs.
	FiledDate string `json:"filed_date,omitempty"`
	CaseDID   string `json:"case_did,omitempty"`
	CaseSeq   uint64 `json:"case_seq,omitempty"`
}

var (
	ErrDispositionInvalid = errors.New("schemas/appellate_disposition: invalid")
)

// Validate runs structural sanity. Per-jurisdiction Outcome
// enum membership is enforced separately by the verifier.
func (p *AppellateDispositionPayload) Validate() error {
	if p == nil {
		return fmt.Errorf("%w: nil payload", ErrDispositionInvalid)
	}
	if p.Outcome == "" {
		return fmt.Errorf("%w: outcome required", ErrDispositionInvalid)
	}
	if len(p.Panel) == 0 {
		return fmt.Errorf("%w: panel must list ≥1 judge DID",
			ErrDispositionInvalid)
	}
	for i, did := range p.Panel {
		if did == "" {
			return fmt.Errorf("%w: panel[%d] is empty",
				ErrDispositionInvalid, i)
		}
	}
	if p.CaseRef == "" {
		return fmt.Errorf("%w: case_ref required", ErrDispositionInvalid)
	}
	return nil
}

// DefaultDispositionParams returns the SDK envelope-params.
func DefaultDispositionParams() []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"identifier_scope":           "real_did",
		"artifact_encryption":        "aes_gcm",
		"grant_authorization_mode":   "open",
		"grant_entry_required":       false,
		"grant_requires_audit_entry": false,
		"override_requires_witness":  false,
		"migration_policy":           "amendment",
		// v1.3.0 wire field — see schemas/attestation_policies.go.
		"attestation_policies": appellateDispositionPolicies(),
	})
	return b
}

// SerializeDispositionPayload validates p and JSON-encodes.
func SerializeDispositionPayload(p *AppellateDispositionPayload) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil payload", ErrDispositionInvalid)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// DeserializeDispositionPayload parses + validates.
func DeserializeDispositionPayload(data []byte) (*AppellateDispositionPayload, error) {
	var p AppellateDispositionPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("schemas/appellate_disposition: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func dispositionRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaAppellateDispositionV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*AppellateDispositionPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeDispositionPayload(p)
		},
		Deserialize:     func(data []byte) (interface{}, error) { return DeserializeDispositionPayload(data) },
		DefaultParams:   DefaultDispositionParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
