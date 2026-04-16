/*
FILE PATH: onboarding/provision.go
DESCRIPTION: Three-log bootstrap for a new court. Thin wrapper around
    SDK lifecycle.ProvisionThreeLogs that understands judicial conventions:
    officers / cases / parties log roles, the schema registry, and the
    initial Authority_Set from court.yaml.
KEY ARCHITECTURAL DECISIONS:
    - Uses lifecycle.ProvisionThreeLogs for the actual entry construction.
    - Loads initial schemas from the judicial-network schemas.Registry
      and targets them to the cases log (convention).
    - Returns the provisioning result for the caller to submit to the
      three operators. Submission is the caller's responsibility.
OVERVIEW: ProvisionCourt → ProvisionResult with entries for all three logs.
KEY DEPENDENCIES: ortholog-sdk/lifecycle, judicial-network/schemas, judicial-network/topology
*/
package onboarding

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"

	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/topology"
)

// CourtProvisionConfig configures a new court deployment.
type CourtProvisionConfig struct {
	// Spoke names the three log DIDs + institutional DID.
	Spoke *topology.SpokeConfig

	// AuthoritySet is the initial scope authority set. Must include the court DID.
	// Typical: chief judge, clerk of court, presiding judges.
	AuthoritySet map[string]struct{}

	// InitialOfficers is the officer roster to bootstrap immediately.
	InitialOfficers []InitialOfficer

	// SchemaURIs selects which schemas to publish on the cases log.
	// If empty, publishes all judicial schemas registered in the default registry.
	SchemaURIs []string

	// EventTime overrides the provisioning timestamp. Zero → time.Now().
	EventTime int64
}

// InitialOfficer describes one delegation to create at bootstrap.
type InitialOfficer struct {
	DelegateDID string
	Role        string // "judge" | "clerk" | "deputy"
	Division    string
	// LogTargets restricts this delegation to specific logs.
	// Empty means all three.
	LogTargets []string
}

// ProvisionCourt builds all provisioning entries for a new court.
// The returned ProvisionResult carries per-log entry lists. The caller
// submits each log's entries to the corresponding operator's API.
func ProvisionCourt(cfg CourtProvisionConfig, registry *schemas.Registry) (*lifecycle.ProvisionResult, error) {
	if cfg.Spoke == nil {
		return nil, fmt.Errorf("onboarding/provision: nil spoke config")
	}
	if cfg.Spoke.CourtDID == "" {
		return nil, fmt.Errorf("onboarding/provision: empty court DID")
	}
	if len(cfg.AuthoritySet) == 0 {
		return nil, fmt.Errorf("onboarding/provision: empty authority set")
	}
	if _, ok := cfg.AuthoritySet[cfg.Spoke.CourtDID]; !ok {
		return nil, fmt.Errorf("onboarding/provision: court DID must be in authority set")
	}

	eventTime := cfg.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	// Build delegation specs.
	var delegations []lifecycle.DelegationSpec
	for _, officer := range cfg.InitialOfficers {
		scopeLimit := buildOfficerScopeLimit(officer)
		delegations = append(delegations, lifecycle.DelegationSpec{
			DelegateDID: officer.DelegateDID,
			ScopeLimit:  scopeLimit,
			LogDIDs:     officer.LogTargets,
		})
	}

	// Build schema specs (published on the cases log by convention).
	schemaSpecs, err := buildSchemaSpecs(cfg.SchemaURIs, cfg.Spoke.CasesDID, registry)
	if err != nil {
		return nil, fmt.Errorf("onboarding/provision: build schemas: %w", err)
	}

	sdkCfg := lifecycle.ProvisionConfig{
		CourtDID:           cfg.Spoke.CourtDID,
		OfficersLogDID:     cfg.Spoke.OfficersDID,
		CasesLogDID:        cfg.Spoke.CasesDID,
		PartiesLogDID:      cfg.Spoke.PartiesDID,
		AuthoritySet:       cfg.AuthoritySet,
		InitialDelegations: delegations,
		Schemas:            schemaSpecs,
		EventTime:          eventTime,
	}

	result, err := lifecycle.ProvisionThreeLogs(sdkCfg)
	if err != nil {
		return nil, fmt.Errorf("onboarding/provision: SDK provision: %w", err)
	}
	return result, nil
}

// buildOfficerScopeLimit produces the scope_limit JSON payload for a
// delegation entry following the tn-court-officer-v1 schema conventions.
func buildOfficerScopeLimit(officer InitialOfficer) []byte {
	payload, _ := json.Marshal(schemas.CourtOfficerPayload{
		Role:     officer.Role,
		Division: officer.Division,
	})
	return payload
}

// buildSchemaSpecs resolves URIs from the registry and builds
// lifecycle.SchemaSpec entries targeted at the cases log.
func buildSchemaSpecs(uris []string, casesLogDID string, registry *schemas.Registry) ([]lifecycle.SchemaSpec, error) {
	if registry == nil {
		return nil, fmt.Errorf("nil schema registry")
	}

	// Empty URIs → use every registered schema.
	if len(uris) == 0 {
		uris = registry.URIs()
	}

	var specs []lifecycle.SchemaSpec
	for _, uri := range uris {
		reg, err := registry.Lookup(uri)
		if err != nil {
			return nil, fmt.Errorf("schema %s: %w", uri, err)
		}
		specs = append(specs, lifecycle.SchemaSpec{
			Payload: reg.DefaultParams(),
			LogDID:  casesLogDID,
		})
	}
	return specs, nil
}
