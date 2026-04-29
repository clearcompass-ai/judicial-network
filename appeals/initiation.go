/*
FILE PATH: appeals/initiation.go
DESCRIPTION: Notice of appeal → root entity on appellate court's cases log.
KEY ARCHITECTURAL DECISIONS:
    - BuildRootEntity on appellate log (separate from lower court log).
    - BuildCrossLogProof proves lower court case exists and is final.
    - Domain Payload: lower_court_did, lower_court_case_pos, appeal_grounds.
    - References lower court's case schema (no dedicated appellate schema).
OVERVIEW: FileAppeal → root entity + cross-log proof.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/verifier
*/
package appeals

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

type AppealInitiationConfig struct {
	Destination string // DID of target exchange. Required.
	SignerDID          string
	LowerCourtCasePos  types.LogPosition
	LowerCourtDID      string
	AppealNumber       string
	AppealGrounds      string
	SchemaRef          *types.LogPosition
	EventTime          int64
}

type AppealInitiationResult struct {
	AppealEntry   *envelope.Entry
	CrossLogProof *types.CrossLogProof
}

// FileAppeal creates a notice of appeal on the appellate court's cases log.
// Includes a cross-log proof demonstrating the lower court case exists.
func FileAppeal(
	cfg AppealInitiationConfig,
	fetcher types.EntryFetcher,
	sourceProver verifier.MerkleProver,
	localProver verifier.MerkleProver,
	sourceHead types.CosignedTreeHead,
	localHead types.CosignedTreeHead,
	anchorRef types.LogPosition,
) (*AppealInitiationResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("appeals/initiation: empty signer DID")
	}

	// Build cross-log proof for the lower court case.
	proof, err := verifier.BuildCrossLogProof(
		cfg.LowerCourtCasePos, anchorRef, fetcher,
		sourceProver, localProver, sourceHead, localHead,
	)
	if err != nil {
		return nil, fmt.Errorf("appeals/initiation: cross-log proof: %w", err)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"appeal_number":         cfg.AppealNumber,
		"appeal_grounds":        cfg.AppealGrounds,
		"lower_court_did":       cfg.LowerCourtDID,
		"lower_court_case_seq":  cfg.LowerCourtCasePos.Sequence,
		"status":                "pending",
	})

	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: cfg.Destination,
		SignerDID: cfg.SignerDID,
		Payload:   payload,
		SchemaRef: cfg.SchemaRef,
		EventTime: cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("appeals/initiation: build root entity: %w", err)
	}

	return &AppealInitiationResult{
		AppealEntry:   entry,
		CrossLogProof: proof,
	}, nil
}
