/*
FILE PATH: cases/initiation.go
DESCRIPTION: New case → root entity on cases log via SDK BuildRootEntity.
KEY ARCHITECTURAL DECISIONS:
  - BuildRootEntity creates SMT leaf with OriginTip=self, AuthorityTip=self.
  - Domain Payload carries event_type="case_initiation" (the closed-set
    Event Dictionary key the cosignature gate reads) plus docket_number,
    case_type, filed_date, status.
  - Cosigners are emitted into the payload's signed_by_capacities block so
    the destination's cosignature policy (tn/trial requires a court_clerk
    cosignature on a new case) is verifiable with no off-log registry. The
    cosigner SIGNATURES are attached client-side (the JN holds no keys);
    this builder only declares who must sign.
  - Returns root entity position for all subsequent filings.
  - AttestationPolicyName is OPTIONAL: when set the entry adopts the
    named policy declared on the case schema (see
    schemas/attestation_policies.go); when nil the entry is admitted
    on the primary signature alone. The ledger's self-gating
    admission gate enforces the K-of-N composite.

OVERVIEW: InitiateCase → root entity entry with case schema payload.
KEY DEPENDENCIES: attesta/builder
*/
package cases

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// InitiationConfig configures a new case filing.
type InitiationConfig struct {
	Destination  string // DID of target exchange. Required.
	SignerDID    string // Court clerk or filing attorney DID
	DocketNumber string
	CaseType     string // "criminal", "civil", "family", "juvenile"
	FiledDate    string // ISO 8601
	SchemaRef    *types.LogPosition
	ExtraPayload map[string]interface{} // charges, plaintiff, defendant, etc.
	EventTime    int64

	// AttestationPolicyName, when non-nil and non-empty, adopts the
	// named policy declared on the case schema's
	// SchemaParameters.AttestationPolicies. Typical values for case
	// filings: schemas.PolicyCivilPanelReview,
	// schemas.PolicyCriminalSeniorJudgeConcurrence. nil = no policy
	// (default behavior: primary signature alone admits the entry).
	AttestationPolicyName *string

	// Cosigners declares the Signer cosigners (other than the primary
	// filer at Signatures[0]) whose signatures the destination's
	// cosignature policy requires on a case_initiation entry. For the
	// TN trial framework the court_clerk who accepts the filing is
	// declared here; the policy (deployments/tn/trial) requires their
	// intra-exchange cosignature. Each entry is emitted into the
	// payload's signed_by_capacities block so the verifier's
	// PayloadRoleResolver can map cosigner DID → role + exchange. The
	// actual signatures are attached client-side; this only declares
	// who must sign.
	Cosigners []schemas.SignedByCapacity
}

// InitiationResult holds the root entity entry.
type InitiationResult struct {
	Entry *envelope.Entry
}

// InitiateCase creates a new case root entity on the cases log.
func InitiateCase(cfg InitiationConfig) (*InitiationResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("cases/initiation: empty signer DID")
	}
	if cfg.DocketNumber == "" {
		return nil, fmt.Errorf("cases/initiation: empty docket number")
	}
	for i := range cfg.Cosigners {
		if err := cfg.Cosigners[i].Validate(); err != nil {
			return nil, fmt.Errorf("cases/initiation: cosigner[%d]: %w", i, err)
		}
	}

	payload := map[string]interface{}{
		"docket_number": cfg.DocketNumber,
		"case_type":     cfg.CaseType,
		"filed_date":    cfg.FiledDate,
		"status":        "active",
	}
	for k, v := range cfg.ExtraPayload {
		payload[k] = v
	}
	// event_type is the closed-set Event Dictionary key the cosignature
	// gate reads (verification/cosignature_check.go). Set AFTER
	// ExtraPayload so a caller cannot clobber the load-bearing value.
	payload["event_type"] = "case_initiation"
	if len(cfg.Cosigners) > 0 {
		payload["signed_by_capacities"] = cfg.Cosigners
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("cases/initiation: marshal payload: %w", err)
	}

	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: cfg.Destination,
		SignerDID:   cfg.SignerDID,
		Payload:     payloadBytes,
		SchemaRef:   cfg.SchemaRef,
		EventTime:   cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("cases/initiation: build root entity: %w", err)
	}

	schemas.SetAttestationPolicy(entry, cfg.AttestationPolicyName)

	return &InitiationResult{Entry: entry}, nil
}
