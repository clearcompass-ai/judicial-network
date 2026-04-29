/*
FILE PATH: verification/case_status.go
DESCRIPTION: Origin_Tip → current case state via SDK verifier.EvaluateOrigin.
KEY ARCHITECTURAL DECISIONS:
    - Uses SDK EvaluateOrigin (not raw SMT reads) — handles path compression,
      revocation, succession.
    - Returns typed CaseState with human-readable status.
OVERVIEW: GetCaseStatus → CaseState{Active, Amended, Sealed, Transferred, Closed}.
KEY DEPENDENCIES: ortholog-sdk/verifier, ortholog-sdk/core/smt
*/
package verification

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

type CaseState struct {
	OriginState  verifier.OriginState
	IsSealed     bool
	OriginTip    types.LogPosition
	AuthorityTip types.LogPosition
	Description  string
}

// GetCaseStatus evaluates the current state of a case entity using the
// SDK's verifier.EvaluateOrigin for origin lane + authority lane check.
func GetCaseStatus(
	caseRootPos types.LogPosition,
	leafReader smt.LeafReader,
	fetcher types.EntryFetcher,
) (*CaseState, error) {
	leafKey := smt.DeriveKey(caseRootPos)

	eval, err := verifier.EvaluateOrigin(leafKey, leafReader, fetcher)
	if err != nil {
		return nil, fmt.Errorf("verification/case_status: %w", err)
	}

	state := &CaseState{
		OriginState: eval.State,
		
	}

	switch eval.State {
	case verifier.OriginOriginal:
		state.Description = "active (original, no amendments)"
	case verifier.OriginAmended:
		state.Description = "active (amended)"
	case verifier.OriginRevoked:
		state.Description = "closed or transferred (revoked)"
	case verifier.OriginSucceeded:
		state.Description = "superseded (succession)"
	default:
		state.Description = "unknown"
	}

	// Authority lane check for sealing.
	leaf, lErr := leafReader.Get(leafKey)
	if lErr == nil && leaf != nil {
		state.OriginTip = leaf.OriginTip
		state.AuthorityTip = leaf.AuthorityTip
		if !leaf.AuthorityTip.Equal(caseRootPos) && !leaf.AuthorityTip.Equal(leaf.OriginTip) {
			state.IsSealed = true
			state.Description += " [SEALED]"
		}
	}

	return state, nil
}
