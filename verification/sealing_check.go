/*
FILE PATH: verification/sealing_check.go
DESCRIPTION: Authority_Tip → enforcement status via SDK
verifier.EvaluateAuthorityWithTrust, fed by a verification/trust
LocalTrust adapter.
KEY ARCHITECTURAL DECISIONS:
  - SDK correction #3: Uses verifier.EvaluateAuthorityWithTrust (walks
    Prior_Authority chain, handles snapshots, skip pointers). Not manual
    authority chain scan.
  - SDK correction #7: Checks EvaluateContest for pending enforcements.

OVERVIEW: CheckEnforcementStatus → active/pending constraints + contest status.
KEY DEPENDENCIES: baseproof/verifier, baseproof/schema
*/
package verification

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/schema"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
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
//
// trustProvider is the C-3 dispatch seam (deps.PickTrust() at the
// handler caller). asOf pins the head the walker evaluates against:
// the live-status surface uses AsOf{} (latest known head) because
// callers asking "is this case sealed RIGHT NOW?" want the freshest
// trust root; a future historical-status surface threads a non-zero
// asOf. fetcher + leafReader stay in the signature for
// EvaluateContest's per-active-constraint check.
func CheckEnforcementStatus(
	ctx context.Context,
	caseRootPos types.LogPosition,
	trustProvider verifier.LogTrustProvider,
	asOf verifier.AsOf,
	leafReader smt.LeafReader,
	fetcher types.EntryFetcher,
	extractor schema.SchemaParameterExtractor,
) (*EnforcementStatus, error) {
	if trustProvider == nil {
		return nil, fmt.Errorf("verification/sealing_check: nil trustProvider (use deps.PickTrust())")
	}
	// ZT-IMM-01 (baseproof v1.43.0): the live-status surface passes AsOf{}
	// ("is this sealed RIGHT NOW?"); the SDK no longer treats a null AsOf as
	// an implicit wall-clock latest, so resolve it to a pinned head here —
	// a deliberate, reproducible "now".
	if asOf.IsNull() {
		latest, rerr := verifier.ResolveLatest(ctx, trustProvider, caseRootPos.LogDID)
		if rerr != nil {
			return nil, fmt.Errorf("verification/sealing_check: resolve latest head: %w", rerr)
		}
		asOf = latest
	}
	authEval, err := verifier.EvaluateAuthorityWithTrust(
		ctx, caseRootPos, trustProvider, extractor, asOf)
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
