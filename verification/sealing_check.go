/*
FILE PATH: verification/sealing_check.go
DESCRIPTION: Authority_Tip → enforcement status via SDK
verifier.EvaluateAuthorityWithTrust (fed by a verification/trust LocalTrust
adapter — byte-for-byte parity with the legacy walker; see
trust.TestLocalTrust_LegacyParity_EvaluateAuthority).
KEY ARCHITECTURAL DECISIONS:
  - SDK correction #3: Uses verifier.EvaluateAuthorityWithTrust (walks
    Prior_Authority chain, handles snapshots, skip pointers). Not manual
    authority chain scan.
  - SDK correction #7: Checks EvaluateContest for pending enforcements.

OVERVIEW: CheckEnforcementStatus → active/pending constraints + contest status.
KEY DEPENDENCIES: attesta/verifier, attesta/schema
*/
package verification

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/schema"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/judicial-network/verification/trust"
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
	ctx context.Context,
	caseRootPos types.LogPosition,
	leafReader smt.LeafReader,
	fetcher types.EntryFetcher,
	extractor schema.SchemaParameterExtractor,
) (*EnforcementStatus, error) {
	// v1.34 migration: legacy verifier.EvaluateAuthority is deprecated.
	// Migrated to verifier.EvaluateAuthorityWithTrust via a LocalTrust
	// adapter — same (fetcher, leafReader) inputs, parity locked by
	// trust.TestLocalTrust_LegacyParity_EvaluateAuthority.
	authEval, err := verifier.EvaluateAuthorityWithTrust(
		ctx, caseRootPos,
		trust.NewLocalTrust(fetcher, leafReader),
		extractor, verifier.AsOf{})
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
		contestResult, cErr := verifier.EvaluateContest(ctx,
			constraint.Position, fetcher, leafReader, extractor)

		if cErr == nil && contestResult != nil && contestResult.OperationBlocked {
			status.HasPendingContest = true
			status.ContestReason = contestResult.Reason
			break
		}
	}

	return status, nil
}
