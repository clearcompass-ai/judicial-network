/*
FILE PATH: deployments/davidson_county/court_ops.go

DESCRIPTION:
    Operational helpers specific to Davidson County. Handles division
    creation, officer roster synchronization, and schema updates.

    Division creation is Scenario 1 from the court forking analysis:
    new division DID as a root entity on the officers log, then
    delegations for the division's judge and clerk.

KEY DEPENDENCIES:
    - ortholog-sdk/builder: BuildRootEntity, BuildDelegation,
      BuildRevocation (guide §11.3)
    - judicial-network/onboarding: officer bootstrap helpers
    - judicial-network/schemas: schema registry
*/
package davidson_county

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
)

// DivisionConfig describes a new division within Davidson County.
type DivisionConfig struct {
	// SignerDID is the institutional DID (did:web:courts.nashville.gov).
	SignerDID string

	// DivisionName is the human-readable name (e.g., "Business Court").
	DivisionName string

	// DivisionDID is the DID for the new division.
	// Example: did:web:courts.nashville.gov:business
	DivisionDID string

	// PresidingJudgeDID is the initial presiding judge for the division.
	PresidingJudgeDID string

	// ClerkDID is the initial division clerk.
	ClerkDID string

	// ScopeLimit defines what the division's officers can do.
	ScopeLimit []string
}

// CreateDivision creates a new division within Davidson County.
// This is a root entity on the officers log (no new log needed).
// Returns the division entity entry and initial delegation entries.
func CreateDivision(cfg DivisionConfig) (*DivisionProvision, error) {
	if cfg.SignerDID == "" || cfg.DivisionDID == "" {
		return nil, fmt.Errorf("davidson/court_ops: signer and division DIDs required")
	}

	// Step 1: Create division entity on officers log.
	divPayload, _ := json.Marshal(map[string]any{
		"division":    cfg.DivisionName,
		"division_did": cfg.DivisionDID,
		"court_did":   cfg.SignerDID,
	})

	divEntity, err := builder.BuildRootEntity(builder.RootEntityParams{
		SignerDID:     cfg.SignerDID,
		DomainPayload: divPayload,
	})
	if err != nil {
		return nil, fmt.Errorf("davidson/court_ops: division entity: %w", err)
	}

	provision := &DivisionProvision{
		DivisionEntity: divEntity,
	}

	// Step 2: Delegate presiding judge (depth 1).
	if cfg.PresidingJudgeDID != "" {
		scopeLimit, _ := json.Marshal(map[string]any{
			"role":        "presiding_judge",
			"division":    cfg.DivisionName,
			"scope_limit": cfg.ScopeLimit,
		})

		judgeDelegation, err := builder.BuildDelegation(builder.DelegationParams{
			SignerDID:     cfg.SignerDID,
			DelegateDID:   cfg.PresidingJudgeDID,
			DomainPayload: scopeLimit,
		})
		if err != nil {
			return nil, fmt.Errorf("davidson/court_ops: judge delegation: %w", err)
		}
		provision.JudgeDelegation = judgeDelegation
	}

	// Step 3: Delegate clerk (depth 2, under judge).
	if cfg.ClerkDID != "" && cfg.PresidingJudgeDID != "" {
		clerkScope, _ := json.Marshal(map[string]any{
			"role":        "division_clerk",
			"division":    cfg.DivisionName,
			"scope_limit": []string{"scheduling", "docket_management", "filing_acceptance"},
		})

		clerkDelegation, err := builder.BuildDelegation(builder.DelegationParams{
			SignerDID:     cfg.PresidingJudgeDID,
			DelegateDID:   cfg.ClerkDID,
			DomainPayload: clerkScope,
		})
		if err != nil {
			return nil, fmt.Errorf("davidson/court_ops: clerk delegation: %w", err)
		}
		provision.ClerkDelegation = clerkDelegation
	}

	return provision, nil
}

// DivisionProvision carries all entries for a new division.
type DivisionProvision struct {
	DivisionEntity  *builder.EntryBuildResult
	JudgeDelegation *builder.EntryBuildResult
	ClerkDelegation *builder.EntryBuildResult
}

// RevokeOfficer creates a revocation entry for an officer who has
// left Davidson County or been removed. The revocation advances the
// delegation's Origin_Tip, breaking the chain for future entries.
// Past entries remain historically valid (the delegation was live at
// time of signing).
func RevokeOfficer(signerDID, officerDID string, reason string) (*builder.EntryBuildResult, error) {
	payload, _ := json.Marshal(map[string]any{
		"revocation_reason": reason,
		"officer_did":       officerDID,
	})

	return builder.BuildRevocation(builder.RevocationParams{
		SignerDID:     signerDID,
		TargetDID:     officerDID,
		DomainPayload: payload,
	})
}

// PublishRecusal creates a commentary entry recording a judge's recusal
// from a case. The delegation stays live — recusal is a domain-level
// convention enforced by the CMS bridge and public API.
func PublishRecusal(
	judgeDID string,
	caseDocketNumber string,
	reason string,
) (*builder.EntryBuildResult, error) {
	payload, _ := json.Marshal(map[string]any{
		"type":           "recusal",
		"docket_number":  caseDocketNumber,
		"reason":         reason,
		"judge_did":      judgeDID,
	})

	return builder.BuildCommentary(builder.CommentaryParams{
		SignerDID:     judgeDID,
		DomainPayload: payload,
	})
}
