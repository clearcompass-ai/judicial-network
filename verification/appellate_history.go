/*
FILE PATH: verification/appellate_history.go
DESCRIPTION: Appeal chain reconstruction across logs.
KEY ARCHITECTURAL DECISIONS:
    - Uses verifier.BuildCrossLogProof + VerifyCrossLogProof.
    - Walks: municipal → county → state → supreme court.
OVERVIEW: ReconstructAppealChain → ordered list of appeal steps with proofs.
KEY DEPENDENCIES: ortholog-sdk/verifier
*/
package verification

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/topology"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

type AppealStep struct {
	Level         string // "trial", "appellate", "supreme"
	CasePos       types.LogPosition
	LogDID        string
	Outcome       string
	Proof         *types.CrossLogProof
	ProofVerified bool
}

// VerifyAppealChain verifies a sequence of cross-log appeal references.
// Each step's cross-log proof is verified against the source witness keys.
func VerifyAppealChain(
	steps []AppealStep,
	witnessKeysByLog map[string][]types.WitnessPublicKey,
	quorumByLog map[string]int,
	blsVerifier signatures.BLSVerifier,
) ([]AppealStep, error) {
	for i := range steps {
		if steps[i].Proof == nil {
			continue
		}

		sourceKeys := witnessKeysByLog[steps[i].LogDID]
		quorum := quorumByLog[steps[i].LogDID]
		if len(sourceKeys) == 0 || quorum == 0 {
			steps[i].ProofVerified = false
			continue
		}

		err := verifier.VerifyCrossLogProof(*steps[i].Proof, sourceKeys, quorum, blsVerifier, topology.ExtractAnchorPayload)
		if err != nil {
			steps[i].ProofVerified = false
			continue
		}
		steps[i].ProofVerified = true
	}

	// Verify chain continuity.
	for i := 1; i < len(steps); i++ {
		if !steps[i].ProofVerified {
			return steps, fmt.Errorf("verification/appellate_history: broken at step %d", i)
		}
	}

	return steps, nil
}
