/*
FILE PATH: enforcement/sealing.go
DESCRIPTION: Path C sealing order via SDK BuildEnforcement.
KEY ARCHITECTURAL DECISIONS:
    - Judge signer must be in scope authority set (Path C requirement).
    - Advances AuthorityTip on case entity leaf → retrieve.go blocks access.
    - Activation pattern: EvaluateConditions → CheckActivationReady →
      EvaluateContest → if unblocked → activate.
    - Also handles protective orders (same Path C mechanism).
OVERVIEW: SealCase → enforcement entry. CheckSealingActivation → activation gate.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/verifier, ortholog-sdk/schema
*/
package enforcement

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

type SealingConfig struct {
	JudgeDID       string
	CaseRootPos    types.LogPosition
	ScopePos       types.LogPosition
	PriorAuthority *types.LogPosition
	SchemaRef      *types.LogPosition
	OrderType      string // "seal", "unseal", "auto_seal"
	Authority      string // TCA citation
	Reason         string
	ArtifactCIDs   []string
	EventTime      int64
}

type SealingResult struct {
	EnforcementEntry *envelope.Entry
}

// SealCase publishes a sealing enforcement entry (Path C).
// The judge must be in the scope's AuthoritySet. Once processed by the
// builder, AuthorityTip advances on the case leaf → retrieve.go's
// checkEntityAccess returns ErrSealed.
func SealCase(cfg SealingConfig) (*SealingResult, error) {
	if cfg.JudgeDID == "" {
		return nil, fmt.Errorf("enforcement/sealing: empty judge DID")
	}
	if cfg.CaseRootPos.IsNull() {
		return nil, fmt.Errorf("enforcement/sealing: null case root position")
	}
	if cfg.ScopePos.IsNull() {
		return nil, fmt.Errorf("enforcement/sealing: null scope position")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"order_type":         cfg.OrderType,
		"authority":          cfg.Authority,
		"reason":             cfg.Reason,
		"affected_artifacts": cfg.ArtifactCIDs,
	})

	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		SignerDID:      cfg.JudgeDID,
		TargetRoot:     cfg.CaseRootPos,
		ScopePointer:   cfg.ScopePos,
		PriorAuthority: cfg.PriorAuthority,
		Payload:        payload,
		SchemaRef:      cfg.SchemaRef,
		EventTime:      cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("enforcement/sealing: build enforcement: %w", err)
	}

	return &SealingResult{EnforcementEntry: entry}, nil
}

// ActivationCheck holds the result of checking whether a sealing order
// can be activated (conditions met + no unresolved contest).
type ActivationCheck struct {
	ConditionsReady bool
	ContestBlocked  bool
	ContestResult   *verifier.ContestResult
	Reason          string
}

// CheckSealingActivation verifies that a pending sealing order is ready
// to activate. Pattern: CheckActivationReady → EvaluateContest.
func CheckSealingActivation(
	pendingPos types.LogPosition,
	fetcher builder.EntryFetcher,
	leafReader smt.LeafReader,
	extractor schema.SchemaParameterExtractor,
	now interface{ UTC() interface{ UnixMicro() int64 } },
) (*ActivationCheck, error) {
	result := &ActivationCheck{}

	// Step 1: Check activation conditions (delay elapsed, cosig threshold).
	ready, err := verifier.CheckActivationReady(verifier.EvaluateConditionsParams{
		PendingPos: pendingPos,
		Fetcher:    fetcher,
		Extractor:  extractor,
	})
	if err != nil {
		return nil, fmt.Errorf("enforcement/sealing: check activation: %w", err)
	}
	result.ConditionsReady = ready

	if !ready {
		result.Reason = "activation conditions not yet met"
		return result, nil
	}

	// Step 2: Check for unresolved contest (SDK correction #7).
	contestResult, err := verifier.EvaluateContest(pendingPos, fetcher, leafReader, extractor)
	if err != nil {
		return nil, fmt.Errorf("enforcement/sealing: evaluate contest: %w", err)
	}
	result.ContestResult = contestResult

	if contestResult.OperationBlocked {
		result.ContestBlocked = true
		result.Reason = "contested: " + contestResult.Reason
		return result, nil
	}

	result.Reason = "ready to activate"
	return result, nil
}
