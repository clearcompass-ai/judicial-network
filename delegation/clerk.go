/*
FILE PATH: delegation/clerk.go
DESCRIPTION: Depth 2 delegation: judge → clerk. SDK BuildDelegation with
    court_officer schema payload (role="clerk").
KEY ARCHITECTURAL DECISIONS: Depth 2 of max 3.
OVERVIEW: DelegateClerk → delegation entry.
KEY DEPENDENCIES: ortholog-sdk/builder
*/
package delegation

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

type ClerkDelegationConfig struct {
	JudgeDID      string
	ClerkDID      string
	Division      string
	AppointedDate string
	ScopeLimit    string // e.g., "filings_only", "full_case_management"
	Title         string
	SchemaRef     *types.LogPosition
	EventTime     int64
}

func DelegateClerk(cfg ClerkDelegationConfig) (*envelope.Entry, error) {
	if cfg.JudgeDID == "" || cfg.ClerkDID == "" {
		return nil, fmt.Errorf("delegation/clerk: judge DID and clerk DID required")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"role":           "clerk",
		"division":       cfg.Division,
		"appointed_date": cfg.AppointedDate,
		"scope_limit":    cfg.ScopeLimit,
		"title":          cfg.Title,
		"delegated_by":   cfg.JudgeDID,
		"max_depth":      1,
	})

	return builder.BuildDelegation(builder.DelegationParams{
		SignerDID:   cfg.JudgeDID,
		DelegateDID: cfg.ClerkDID,
		Payload:     payload,
		SchemaRef:   cfg.SchemaRef,
		EventTime:   cfg.EventTime,
	})
}
