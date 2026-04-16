/*
FILE PATH: delegation/division.go
DESCRIPTION: Division DID creation. Each division (criminal, civil, family,
    juvenile) gets its own scope under the court.
KEY ARCHITECTURAL DECISIONS: BuildScopeCreation with division-specific Authority_Set.
OVERVIEW: CreateDivision → scope entity for a court division.
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

// DivisionConfig configures a division scope creation.
type DivisionConfig struct {
	CourtDID     string
	DivisionName string // "criminal", "civil", "family", "juvenile"
	AuthoritySet map[string]struct{}
	SchemaRef    *types.LogPosition
	EventTime    int64
}

// CreateDivision creates a scope entity for a court division.
func CreateDivision(cfg DivisionConfig) (*envelope.Entry, error) {
	if cfg.CourtDID == "" || cfg.DivisionName == "" {
		return nil, fmt.Errorf("delegation/division: court DID and division name required")
	}
	if len(cfg.AuthoritySet) == 0 {
		return nil, fmt.Errorf("delegation/division: empty authority set")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"profile_type": "court_division",
		"division":     cfg.DivisionName,
		"court_did":    cfg.CourtDID,
	})

	return builder.BuildScopeCreation(builder.ScopeCreationParams{
		SignerDID:    cfg.CourtDID,
		AuthoritySet: cfg.AuthoritySet,
		Payload:      payload,
		SchemaRef:    cfg.SchemaRef,
		EventTime:    cfg.EventTime,
	})
}
