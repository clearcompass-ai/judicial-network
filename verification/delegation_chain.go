/*
FILE PATH: verification/delegation_chain.go
DESCRIPTION: Delegation provenance verification for a specific filing.
KEY ARCHITECTURAL DECISIONS:
    - SDK correction #1: Uses verifier.VerifyDelegationProvenance (NOT
      WalkDelegationTree). VerifyDelegationProvenance walks Delegation_Pointers
      linearly and checks per-hop liveness. WalkDelegationTree is BFS over
      the entire graph — wrong for single-chain verification.
OVERVIEW: VerifyFilingDelegation → []DelegationHop with liveness.
KEY DEPENDENCIES: ortholog-sdk/verifier, ortholog-sdk/core/smt
*/
package verification

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

type DelegationVerification struct {
	Hops     []verifier.DelegationHop
	AllLive  bool
	Depth    int
	FirstDead *types.LogPosition
}

// VerifyFilingDelegation verifies the delegation chain for a specific filing.
// Uses VerifyDelegationProvenance (linear walk) not WalkDelegationTree (BFS).
func VerifyFilingDelegation(
	delegationPointers []types.LogPosition,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
) (*DelegationVerification, error) {
	if len(delegationPointers) == 0 {
		return &DelegationVerification{AllLive: true}, nil
	}

	hops, err := verifier.VerifyDelegationProvenance(delegationPointers, fetcher, leafReader)
	if err != nil {
		return nil, fmt.Errorf("verification/delegation_chain: %w", err)
	}

	result := &DelegationVerification{
		Hops:  hops,
		Depth: len(hops),
		AllLive: true,
	}

	for i := range hops {
		if !hops[i].IsLive {
			result.AllLive = false
			if result.FirstDead == nil {
				pos := hops[i].Position
				result.FirstDead = &pos
			}
		}
	}

	return result, nil
}
