/*
FILE PATH: verification/sealing_check.go
DESCRIPTION: Authority_Tip → enforcement status via SDK verifier.EvaluateAuthority.
KEY ARCHITECTURAL DECISIONS:
    - SDK correction #3: Uses verifier.EvaluateAuthority (walks Prior_Authority
      chain, handles snapshots, skip pointers). Not manual authority chain scan.
    - SDK correction #7: Checks EvaluateContest for pending enforcements.
OVERVIEW: CheckEnforcementStatus → active/pending constraints + contest status.
KEY DEPENDENCIES: ortholog-sdk/verifier, ortholog-sdk/schema
*/
package verification

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

type EnforcementStatus struct {
	ActiveConstraintCount int
	PendingCount          int
	ChainLength           int
	UsedSnapshot          bool
	HasPendingContest     bool
	ContestReason         string
}

// CheckEnforcementStatus evaluates the authority chain for a case entity.
func CheckEnforcementStatus(
	caseRootPos types.LogPosition,
	leafReader smt.LeafReader,
	fetcher builder.EntryFetcher,
	extractor schema.SchemaParameterExtractor,
) (*EnforcementStatus, error) {
	leafKey := smt.DeriveKey(caseRootPos)

	authEval, err := verifier.EvaluateAuthority(leafKey, leafReader, fetcher, extractor)
	if err != nil {
		return nil, fmt.Errorf("verification/sealing_check: %w", err)
	}

	status := &EnforcementStatus{
		ActiveConstraintCount: len(authEval.ActiveConstraints),
		PendingCount:          authEval.PendingCount,
		ChainLength:           authEval.ChainLength,
		UsedSnapshot:          authEval.UsedSnapshot,
	}

	// Check for pending contests on active enforcement entries (SDK correction #7).
	for _, constraint := range authEval.ActiveConstraints {
		contestResult, cErr := verifier.EvaluateContest(
			constraint.Position, fetcher, leafReader, extractor,
		)
		if cErr == nil && contestResult != nil && contestResult.OperationBlocked {
			status.HasPendingContest = true
			status.ContestReason = contestResult.Reason
			break
		}
	}

	return status, nil
}
