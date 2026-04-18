/*
FILE PATH: delegation/judge.go
DESCRIPTION: Depth 1 delegation: division → judge. SDK BuildDelegation with
    court_officer schema payload (role="judge").
KEY ARCHITECTURAL DECISIONS: Depth 1 of max 3. Uses CourtOfficerPayload.
OVERVIEW: DelegateJudge → delegation entry on officers log.
KEY DEPENDENCIES: ortholog-sdk/builder, schemas (CourtOfficerPayload)
*/
package delegation

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// JudgeDelegationConfig configures a judge delegation.
type JudgeDelegationConfig struct {
	Destination string // DID of target exchange. Required.
	DivisionDID   string // Who is delegating (division scope authority)
	JudgeDID      string // Who receives delegated authority
	Division      string // "criminal", "civil", etc.
	AppointedDate string // ISO 8601
	BarNumber     string
	Title         string
	SchemaRef     *types.LogPosition
	EventTime     int64
}

// DelegateJudge creates a depth-1 delegation entry from division to judge.
func DelegateJudge(cfg JudgeDelegationConfig) (*envelope.Entry, error) {
	if cfg.DivisionDID == "" || cfg.JudgeDID == "" {
		return nil, fmt.Errorf("delegation/judge: division DID and judge DID required")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"role":           "judge",
		"division":       cfg.Division,
		"appointed_date": cfg.AppointedDate,
		"bar_number":     cfg.BarNumber,
		"title":          cfg.Title,
		"delegated_by":   cfg.DivisionDID,
		"max_depth":      2, // judge can delegate to clerk (depth 2) and deputy (depth 3)
	})

	return builder.BuildDelegation(builder.DelegationParams{
		Destination: cfg.Destination,
		SignerDID:   cfg.DivisionDID,
		DelegateDID: cfg.JudgeDID,
		Payload:     payload,
		SchemaRef:   cfg.SchemaRef,
		EventTime:   cfg.EventTime,
	})
}
