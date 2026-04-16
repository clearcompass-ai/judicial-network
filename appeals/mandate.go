/*
FILE PATH: appeals/mandate.go
DESCRIPTION: Mandate issuance — makes appellate decision effective on lower court.
KEY ARCHITECTURAL DECISIONS:
    - Reverse/remand: BuildEnforcement on lower court cases log (Path C).
    - Affirm: BuildCommentary on lower court noting affirmance.
    - Cross-log proof references appellate decision.
    - EvaluateContest before enforcement activation (SDK correction #7).
OVERVIEW: IssueMandateReverse → enforcement. IssueMandateAffirm → commentary.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/verifier
*/
package appeals

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

type MandateConfig struct {
	SignerDID          string
	LowerCourtCasePos  types.LogPosition
	LowerCourtScopePos types.LogPosition
	PriorAuthority     *types.LogPosition
	AppellateDecisionPos types.LogPosition
	Outcome            string
	RemandInstructions string
	SchemaRef          *types.LogPosition
	EventTime          int64
}

type MandateResult struct {
	MandateEntry  *envelope.Entry
	CrossLogProof *types.CrossLogProof
}

// IssueMandateReverse publishes an enforcement entry on the lower court
// log for reverse/remand outcomes. The enforcement references the appellate
// decision via cross-log proof.
func IssueMandateReverse(
	cfg MandateConfig,
	fetcher verifier.EntryFetcher,
	leafReader smt.LeafReader,
	extractor schema.SchemaParameterExtractor,
	sourceProver verifier.MerkleProver,
	localProver verifier.MerkleProver,
	sourceHead types.CosignedTreeHead,
	localHead types.CosignedTreeHead,
	anchorRef types.LogPosition,
) (*MandateResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("appeals/mandate: empty signer DID")
	}

	// Contest check before enforcement (SDK correction #7).
	contestResult, err := verifier.EvaluateContest(
		cfg.LowerCourtCasePos, fetcher, leafReader, extractor,
	)
	if err == nil && contestResult != nil && contestResult.OperationBlocked {
		return nil, fmt.Errorf("appeals/mandate: blocked by contest: %s", contestResult.Reason)
	}

	// Cross-log proof for appellate decision.
	proof, err := verifier.BuildCrossLogProof(
		cfg.AppellateDecisionPos, anchorRef, fetcher,
		sourceProver, localProver, sourceHead, localHead,
	)
	if err != nil {
		return nil, fmt.Errorf("appeals/mandate: cross-log proof: %w", err)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"mandate_type":        cfg.Outcome,
		"appellate_decision":  cfg.AppellateDecisionPos.String(),
		"remand_instructions": cfg.RemandInstructions,
	})

	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		SignerDID:      cfg.SignerDID,
		TargetRoot:     cfg.LowerCourtCasePos,
		ScopePointer:   cfg.LowerCourtScopePos,
		PriorAuthority: cfg.PriorAuthority,
		Payload:        payload,
		SchemaRef:      cfg.SchemaRef,
		EventTime:      cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("appeals/mandate: build enforcement: %w", err)
	}

	return &MandateResult{MandateEntry: entry, CrossLogProof: proof}, nil
}

// IssueMandateAffirm publishes a commentary entry on the lower court
// log noting the affirmance. No enforcement — the lower court case stands.
func IssueMandateAffirm(cfg MandateConfig) (*envelope.Entry, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"mandate_type":       "affirm",
		"appellate_decision": cfg.AppellateDecisionPos.String(),
	})

	return builder.BuildCommentary(builder.CommentaryParams{
		SignerDID: cfg.SignerDID,
		Payload:   payload,
		EventTime: cfg.EventTime,
	})
}
