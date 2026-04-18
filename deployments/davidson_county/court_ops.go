package davidson_county

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// DivisionConfig describes a new division within Davidson County.
type DivisionConfig struct {
	Destination string // DID of target exchange. Required.
	SignerDID         string
	DivisionName      string
	DivisionDID       string
	PresidingJudgeDID string
	ClerkDID          string
	ScopeLimit        []string
}

// DivisionProvision carries all entries for a new division.
type DivisionProvision struct {
	DivisionEntity  *envelope.Entry
	JudgeDelegation *envelope.Entry
	ClerkDelegation *envelope.Entry
}

// CreateDivision creates a new division within Davidson County.
func CreateDivision(cfg DivisionConfig) (*DivisionProvision, error) {
	if cfg.SignerDID == "" || cfg.DivisionDID == "" {
		return nil, fmt.Errorf("davidson/court_ops: signer and division DIDs required")
	}

	divPayload, _ := json.Marshal(map[string]any{
		"division":     cfg.DivisionName,
		"division_did": cfg.DivisionDID,
		"court_did":    cfg.SignerDID,
	})

	divEntity, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: cfg.Destination,
		SignerDID: cfg.SignerDID,
		Payload:   divPayload,
	})
	if err != nil {
		return nil, fmt.Errorf("davidson/court_ops: division entity: %w", err)
	}

	provision := &DivisionProvision{DivisionEntity: divEntity}

	if cfg.PresidingJudgeDID != "" {
		scopeLimit, _ := json.Marshal(map[string]any{
			"role":        "presiding_judge",
			"division":    cfg.DivisionName,
			"scope_limit": cfg.ScopeLimit,
		})

		judgeDelegation, err := builder.BuildDelegation(builder.DelegationParams{
			Destination: cfg.Destination,
			SignerDID:   cfg.SignerDID,
			DelegateDID: cfg.PresidingJudgeDID,
			Payload:     scopeLimit,
		})
		if err != nil {
			return nil, fmt.Errorf("davidson/court_ops: judge delegation: %w", err)
		}
		provision.JudgeDelegation = judgeDelegation
	}

	if cfg.ClerkDID != "" && cfg.PresidingJudgeDID != "" {
		clerkScope, _ := json.Marshal(map[string]any{
			"role":        "division_clerk",
			"division":    cfg.DivisionName,
			"scope_limit": []string{"scheduling", "docket_management", "filing_acceptance"},
		})

		clerkDelegation, err := builder.BuildDelegation(builder.DelegationParams{
			Destination: cfg.Destination,
			SignerDID:   cfg.PresidingJudgeDID,
			DelegateDID: cfg.ClerkDID,
			Payload:     clerkScope,
		})
		if err != nil {
			return nil, fmt.Errorf("davidson/court_ops: clerk delegation: %w", err)
		}
		provision.ClerkDelegation = clerkDelegation
	}

	return provision, nil
}

// RevokeOfficer creates a revocation entry. TargetPos is the log
// position of the delegation entry being revoked.
func RevokeOfficer(signerDID string, targetPos uint64, reason, destination string) (*envelope.Entry, error) {
	payload, _ := json.Marshal(map[string]any{
		"revocation_reason": reason,
	})

	return builder.BuildRevocation(builder.RevocationParams{
		Destination: destination,
		SignerDID:  signerDID,
		TargetRoot: types.LogPosition{Sequence: targetPos},
		Payload:    payload,
	})
}

// PublishRecusal creates a commentary entry recording a judge's recusal.
func PublishRecusal(judgeDID, caseDocketNumber, reason, destination string) (*envelope.Entry, error) {
	payload, _ := json.Marshal(map[string]any{
		"type":          "recusal",
		"docket_number": caseDocketNumber,
		"reason":        reason,
		"judge_did":     judgeDID,
	})

	return builder.BuildCommentary(builder.CommentaryParams{
		Destination: destination,
		SignerDID: judgeDID,
		Payload:   payload,
	})
}
