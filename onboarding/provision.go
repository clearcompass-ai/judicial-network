/*
FILE PATH: onboarding/provision.go

DESCRIPTION:
    Three-log bootstrap for a new court. Composes three calls to
    lifecycle.ProvisionSingleLog (one per log) with judicial-specific
    filtering applied locally.

KEY ARCHITECTURAL DECISIONS:
    - The SDK provides ProvisionSingleLog for single-log provisioning.
      Domain-specific orchestration (which delegations target which
      logs, which schemas live on which log) is the domain's
      responsibility. This file is where that orchestration lives
      for the judicial network.
    - Per-log filtering replaces the previous DelegationSpec.LogDIDs
      and SchemaSpec.LogDID fields (removed from SDK). Officers list
      which logs they apply to via InitialOfficer.LogTargets; schemas
      target the cases log by judicial convention. The provisionOne
      helper applies the filters before calling the SDK.
    - ScopePayload carries court_did + log_did so verifiers can
      identify both the institutional context and the specific log.

OVERVIEW:
    ProvisionCourt(cfg, registry) →
      provisionOne(officers log)
      provisionOne(cases log)
      provisionOne(parties log)
    Returns CourtProvision with three LogProvision pointers.

KEY DEPENDENCIES:
    - ortholog-sdk/lifecycle: ProvisionSingleLog, SingleLogConfig,
      DelegationSpec, SchemaSpec, LogProvision
    - judicial-network/schemas: schema registry for resolving URIs
    - judicial-network/topology: SpokeConfig (court + three log DIDs)
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

// ─────────────────────────────────────────────────────────────────────
// Domain types
// ─────────────────────────────────────────────────────────────────────

// CourtProvisionConfig configures a new court deployment.
type CourtProvisionConfig struct {
	// Spoke names the three log DIDs + institutional DID.
	Spoke *topology.SpokeConfig

	// AuthoritySet is the initial scope authority set. Must include
	// the court DID. Typical: chief judge, clerk of court, presiding
	// judges.
	AuthoritySet map[string]struct{}

	// InitialOfficers is the officer roster to bootstrap immediately.
	InitialOfficers []InitialOfficer

	// SchemaURIs selects which schemas to publish on the cases log.
	// If empty, publishes all judicial schemas registered in the
	// default registry.
	SchemaURIs []string

	// EventTime overrides the provisioning timestamp. Zero → time.Now().
	EventTime int64
}

// InitialOfficer describes one delegation to create at bootstrap.
type InitialOfficer struct {
	DelegateDID string
	Role        string // "judge" | "clerk" | "deputy"
	Division    string

	// LogTargets restricts this delegation to specific logs. Empty
	// means all three. Values must be log DIDs from the SpokeConfig.
	LogTargets []string
}

// CourtProvision is the three-log result. Each field carries the
// per-log lifecycle.LogProvision returned by the SDK.
//
// Callers iterate per-log via Officers.AllEntries(),
// Cases.AllEntries(), Parties.AllEntries() — each returns entries
// in submission order for that log's operator.
type CourtProvision struct {
	Officers *lifecycle.LogProvision
	Cases    *lifecycle.LogProvision
	Parties  *lifecycle.LogProvision
}

// ─────────────────────────────────────────────────────────────────────
// ProvisionCourt
// ─────────────────────────────────────────────────────────────────────

// ProvisionCourt builds all provisioning entries for a new court.
// The returned CourtProvision carries per-log entry lists. The caller
// submits each log's entries to the corresponding operator's API.
func ProvisionCourt(cfg CourtProvisionConfig, registry *schemas.Registry) (*CourtProvision, error) {
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

	// Resolve schemas once. All schemas target the cases log by
	// judicial convention.
	schemaSpecs, err := buildSchemaSpecs(cfg.SchemaURIs, registry)
	if err != nil {
		return nil, fmt.Errorf("onboarding/provision: build schemas: %w", err)
	}

	officers, err := provisionOne(cfg, cfg.Spoke.OfficersDID, nil, eventTime)
	if err != nil {
		return nil, fmt.Errorf("officers log: %w", err)
	}
	cases, err := provisionOne(cfg, cfg.Spoke.CasesDID, schemaSpecs, eventTime)
	if err != nil {
		return nil, fmt.Errorf("cases log: %w", err)
	}
	parties, err := provisionOne(cfg, cfg.Spoke.PartiesDID, nil, eventTime)
	if err != nil {
		return nil, fmt.Errorf("parties log: %w", err)
	}

	return &CourtProvision{
		Officers: officers,
		Cases:    cases,
		Parties:  parties,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Internal
// ─────────────────────────────────────────────────────────────────────

// provisionOne calls the SDK once for a single log, applying per-log
// officer filtering. Schemas are passed in pre-filtered (only the
// cases log gets schemas in this domain).
func provisionOne(
	cfg CourtProvisionConfig,
	logDID string,
	schemaSpecs []lifecycle.SchemaSpec,
	eventTime int64,
) (*lifecycle.LogProvision, error) {
	// Filter officers to those targeting this log.
	var delegations []lifecycle.DelegationSpec
	for _, officer := range cfg.InitialOfficers {
		if !officerTargetsLog(officer, logDID) {
			continue
		}
		delegations = append(delegations, lifecycle.DelegationSpec{
			DelegateDID: officer.DelegateDID,
			ScopeLimit:  buildOfficerScopeLimit(officer),
		})
	}

	// Judicial scope payload pins this log to its court.
	scopePayload, err := json.Marshal(map[string]any{
		"log_did":   logDID,
		"court_did": cfg.Spoke.CourtDID,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal scope payload: %w", err)
	}

	return lifecycle.ProvisionSingleLog(lifecycle.SingleLogConfig{
		SignerDID:    cfg.Spoke.CourtDID,
		LogDID:       logDID,
		AuthoritySet: cfg.AuthoritySet,
		Delegations:  delegations,
		Schemas:      schemaSpecs,
		ScopePayload: scopePayload,
		EventTime:    eventTime,
	})
}

// officerTargetsLog returns true when this officer should appear in
// the given log's delegation list. Empty LogTargets means "all logs".
func officerTargetsLog(officer InitialOfficer, logDID string) bool {
	if len(officer.LogTargets) == 0 {
		return true
	}
	for _, target := range officer.LogTargets {
		if target == logDID {
			return true
		}
	}
	return false
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
// lifecycle.SchemaSpec entries. No per-spec log target — the SDK's
// SchemaSpec carries Payload and CommutativeOperations only.
func buildSchemaSpecs(uris []string, registry *schemas.Registry) ([]lifecycle.SchemaSpec, error) {
	if registry == nil {
		return nil, fmt.Errorf("nil schema registry")
	}

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
		})
	}
	return specs, nil
}
