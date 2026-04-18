/*
FILE PATH: enforcement/sealing.go
DESCRIPTION: Path C sealing order via SDK BuildEnforcement.
KEY ARCHITECTURAL DECISIONS:
    - Judge signer must be in scope authority set (Path C requirement).
    - Advances AuthorityTip on case entity leaf → retrieve.go blocks access.
    - Activation pattern: discover cosignatures → EvaluateConditions (now +
      cosigs threaded through) → EvaluateContest → if unblocked → activate.
    - Also handles protective orders (same Path C mechanism).

BUGFIX NOTES (§5.1, §5.10):
    - Prior version accepted a duck-typed clock type
        now interface{ UTC() interface{ UnixMicro() int64 } }
      that was never forwarded to verifier.CheckActivationReady. Result:
      every activation-delay check resolved to ConditionPending forever,
      and every cosignature-threshold check resolved to 0/N because no
      cosignatures were ever passed in.
    - CheckSealingActivation now takes plain time.Time plus an explicit
      []types.EntryWithMetadata cosignatures slice (or a CosignatureQuerier
      to discover them), and threads both into EvaluateConditionsParams.
    - CosignatureQuerier is exposed so callers can pass log.OperatorQueryAPI
      directly (structural typing — QueryByCosignatureOf is the one method
      we need).

OVERVIEW: SealCase → enforcement entry. CheckSealingActivation → activation gate.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/verifier, ortholog-sdk/schema
*/
package enforcement

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// CosignatureQuerier discovers cosignature entries referencing a given
// pending position. Satisfied by log.OperatorQueryAPI via structural typing.
type CosignatureQuerier interface {
	QueryByCosignatureOf(pos types.LogPosition) ([]types.EntryWithMetadata, error)
}

// SealingConfig configures a sealing order.
type SealingConfig struct {
	Destination string // DID of target exchange. Required.
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

// SealingResult holds the sealing enforcement entry.
type SealingResult struct {
	EnforcementEntry *envelope.Entry
}

// SealCase publishes a sealing enforcement entry (Path C).
// The judge must be in the scope's AuthoritySet. Once the builder
// processes the entry, AuthorityTip advances on the case leaf and
// retrieve.go's checkEntityAccess returns ErrSealed.
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
		Destination: cfg.Destination,
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
	ConditionsReady  bool
	ContestBlocked   bool
	ConditionResult  *verifier.ConditionResult
	ContestResult    *verifier.ContestResult
	CosignatureCount int
	Reason           string
}

// CheckSealingActivation verifies that a pending sealing order is ready
// to activate. Pattern: discover cosignatures → EvaluateConditions →
// EvaluateContest (correction #7).
//
// now: evaluation time. Callers pass time.Now().UTC() in production or a
// fixed time in tests. Zero values are replaced with time.Now().UTC().
//
// cosigs: pre-fetched cosignatures for the pending position. If nil and
// querier is non-nil, this function queries them via QueryByCosignatureOf.
// If both are nil, the cosignature-threshold condition will resolve as 0/N.
func CheckSealingActivation(
	pendingPos types.LogPosition,
	fetcher builder.EntryFetcher,
	leafReader smt.LeafReader,
	extractor schema.SchemaParameterExtractor,
	now time.Time,
	cosigs []types.EntryWithMetadata,
	querier CosignatureQuerier,
) (*ActivationCheck, error) {
	result := &ActivationCheck{}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Discover cosignatures if caller didn't provide them.
	if cosigs == nil && querier != nil {
		discovered, err := querier.QueryByCosignatureOf(pendingPos)
		if err != nil {
			return nil, fmt.Errorf("enforcement/sealing: query cosignatures: %w", err)
		}
		cosigs = discovered
	}

	// Step 1: full condition evaluation.
	condResult, err := verifier.EvaluateConditions(verifier.EvaluateConditionsParams{
		PendingPos:   pendingPos,
		Fetcher:      fetcher,
		Extractor:    extractor,
		Cosignatures: cosigs,
		Now:          now,
	})
	if err != nil {
		return nil, fmt.Errorf("enforcement/sealing: evaluate conditions: %w", err)
	}
	result.ConditionResult = condResult
	result.ConditionsReady = condResult.AllMet
	result.CosignatureCount = condResult.CosignatureCount

	if !condResult.AllMet {
		result.Reason = "activation conditions not yet met"
		return result, nil
	}

	// Step 2: unresolved-contest check (correction #7).
	contestResult, err := verifier.EvaluateContest(pendingPos, fetcher, leafReader, extractor)
	if err != nil {
		return nil, fmt.Errorf("enforcement/sealing: evaluate contest: %w", err)
	}
	result.ContestResult = contestResult

	if contestResult != nil && contestResult.OperationBlocked {
		result.ContestBlocked = true
		result.Reason = "contested: " + contestResult.Reason
		return result, nil
	}

	result.Reason = "ready to activate"
	return result, nil
}
