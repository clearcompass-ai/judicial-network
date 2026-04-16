/*
FILE PATH: delegation/court_profile.go
DESCRIPTION: Institutional DID creation via SDK BuildScopeCreation.
KEY ARCHITECTURAL DECISIONS: Uses BuildScopeCreation with court.yaml Authority_Set.
OVERVIEW: CreateCourtProfile → scope entity with institutional DID + Authority_Set.
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

// CourtProfileConfig configures institutional DID creation.
type CourtProfileConfig struct {
	CourtDID     string
	CourtName    string
	AuthoritySet map[string]struct{}
	Divisions    []string
	SchemaRef    *types.LogPosition
	EventTime    int64
}

// CourtProfileResult holds the scope creation entry.
type CourtProfileResult struct {
	ScopeEntry *envelope.Entry
}

// CreateCourtProfile creates a scope entity for the institutional court DID.
// The scope establishes the initial Authority_Set (presiding judges, chief clerk).
func CreateCourtProfile(cfg CourtProfileConfig) (*CourtProfileResult, error) {
	if cfg.CourtDID == "" {
		return nil, fmt.Errorf("delegation/court_profile: empty court DID")
	}
	if len(cfg.AuthoritySet) == 0 {
		return nil, fmt.Errorf("delegation/court_profile: empty authority set")
	}
	if _, ok := cfg.AuthoritySet[cfg.CourtDID]; !ok {
		return nil, fmt.Errorf("delegation/court_profile: court DID must be in authority set")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"profile_type": "court_institution",
		"court_name":   cfg.CourtName,
		"divisions":    cfg.Divisions,
	})

	entry, err := builder.BuildScopeCreation(builder.ScopeCreationParams{
		SignerDID:    cfg.CourtDID,
		AuthoritySet: cfg.AuthoritySet,
		Payload:      payload,
		SchemaRef:    cfg.SchemaRef,
		EventTime:    cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("delegation/court_profile: build scope: %w", err)
	}

	return &CourtProfileResult{ScopeEntry: entry}, nil
}
