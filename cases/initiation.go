/*
FILE PATH: cases/initiation.go
DESCRIPTION: New case → root entity on cases log via SDK BuildRootEntity.
KEY ARCHITECTURAL DECISIONS:
    - BuildRootEntity creates SMT leaf with OriginTip=self, AuthorityTip=self.
    - Docket number, initial status, filed_date in Domain Payload.
    - Returns root entity position for all subsequent filings.
OVERVIEW: InitiateCase → root entity entry with case schema payload.
KEY DEPENDENCIES: ortholog-sdk/builder
*/
package cases

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// InitiationConfig configures a new case filing.
type InitiationConfig struct {
	Destination string // DID of target exchange. Required.
	SignerDID    string // Court clerk or filing attorney DID
	DocketNumber string
	CaseType     string // "criminal", "civil", "family", "juvenile"
	FiledDate    string // ISO 8601
	SchemaRef    *types.LogPosition
	ExtraPayload map[string]interface{} // charges, plaintiff, defendant, etc.
	EventTime    int64
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

	payload := map[string]interface{}{
		"docket_number": cfg.DocketNumber,
		"case_type":     cfg.CaseType,
		"filed_date":    cfg.FiledDate,
		"status":        "active",
	}
	for k, v := range cfg.ExtraPayload {
		payload[k] = v
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("cases/initiation: marshal payload: %w", err)
	}

	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: cfg.Destination,
		SignerDID: cfg.SignerDID,
		Payload:   payloadBytes,
		SchemaRef: cfg.SchemaRef,
		EventTime: cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("cases/initiation: build root entity: %w", err)
	}

	return &InitiationResult{Entry: entry}, nil
}
