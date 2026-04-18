/*
FILE PATH: delegation/deputy.go
DESCRIPTION: Depth 3 delegation: clerk → deputy. Maximum depth per protocol.
KEY ARCHITECTURAL DECISIONS: Depth 3 = max. No further delegation allowed.
OVERVIEW: DelegateDeputy → delegation entry.
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

type DeputyDelegationConfig struct {
	Destination string // DID of target exchange. Required.
	ClerkDID      string
	DeputyDID     string
	Division      string
	AppointedDate string
	ScopeLimit    string
	SchemaRef     *types.LogPosition
	EventTime     int64
}

func DelegateDeputy(cfg DeputyDelegationConfig) (*envelope.Entry, error) {
	if cfg.ClerkDID == "" || cfg.DeputyDID == "" {
		return nil, fmt.Errorf("delegation/deputy: clerk DID and deputy DID required")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"role":           "deputy",
		"division":       cfg.Division,
		"appointed_date": cfg.AppointedDate,
		"scope_limit":    cfg.ScopeLimit,
		"delegated_by":   cfg.ClerkDID,
		"max_depth":      0,
	})

	return builder.BuildDelegation(builder.DelegationParams{
		Destination: cfg.Destination,
		SignerDID:   cfg.ClerkDID,
		DelegateDID: cfg.DeputyDID,
		Payload:     payload,
		SchemaRef:   cfg.SchemaRef,
		EventTime:   cfg.EventTime,
	})
}
