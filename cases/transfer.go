/*
FILE PATH: cases/transfer.go
DESCRIPTION: Cross-division and cross-county case transfer.
KEY ARCHITECTURAL DECISIONS:
    - Division transfer: BuildAmendment (Path A) on case root.
    - County transfer: verifier.BuildCrossLogProof + BuildAmendment +
      delegation.BulkMirrorSync for delegation mirrors on target log.
    - DRIFT 2 FIX: CountyTransferResult includes DelegationMirrors for
      the target county log so its operator knows which judges have authority.
    - Uses BuildCrossLogProof (Gap 12), NOT ResolveCrossLogRef.
OVERVIEW: TransferDivision (intra-county) and TransferCounty (inter-county).
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/verifier, delegation/mirror
*/
package cases

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"

	"github.com/clearcompass-ai/judicial-network/delegation"
)

// DivisionTransferConfig configures an intra-county division transfer.
type DivisionTransferConfig struct {
	SignerDID      string
	CaseRootPos    types.LogPosition
	TargetDivision string
	Reason         string
	SchemaRef      *types.LogPosition
	EventTime      int64
}

// TransferDivision moves a case between divisions within the same county.
func TransferDivision(cfg DivisionTransferConfig) (*envelope.Entry, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("cases/transfer: empty signer DID")
	}
	if cfg.CaseRootPos.IsNull() {
		return nil, fmt.Errorf("cases/transfer: null case root position")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"transfer_type":   "division_transfer",
		"target_division": cfg.TargetDivision,
		"reason":          cfg.Reason,
	})

	return builder.BuildAmendment(builder.AmendmentParams{
		SignerDID:  cfg.SignerDID,
		TargetRoot: cfg.CaseRootPos,
		Payload:    payload,
		SchemaRef:  cfg.SchemaRef,
		EventTime:  cfg.EventTime,
	})
}

// CountyTransferConfig configures an inter-county case transfer.
type CountyTransferConfig struct {
	SignerDID       string
	SourceCasePos   types.LogPosition
	TargetCountyDID string
	Reason          string

	// Delegation mirror fields (Drift 2 fix).
	OfficersRootPos types.LogPosition // Root entity on source officers log
	MirrorSignerDID string            // DID signing mirror entries on target log
	SourceLogDID    string            // Officers log DID (source county)

	EventTime int64
}

// CountyTransferResult holds cross-log proof, amendment, and delegation mirrors.
type CountyTransferResult struct {
	CrossLogProof    *types.CrossLogProof
	SourceAmendment  *envelope.Entry

	// DRIFT 2 FIX: Delegation mirrors for the target county log.
	// The target county operator needs these to know which judges have
	// authority over the transferred case. Caller submits to target log.
	DelegationMirrors []*envelope.Entry
}

// TransferCounty initiates a cross-county transfer. Builds cross-log proof,
// marks source case as transferred, and produces delegation mirror entries
// for the target county log.
func TransferCounty(
	cfg CountyTransferConfig,
	fetcher verifier.EntryFetcher,
	sourceProver verifier.MerkleProver,
	localProver verifier.MerkleProver,
	sourceHead types.CosignedTreeHead,
	localHead types.CosignedTreeHead,
	anchorRef types.LogPosition,
	// Delegation mirror dependencies.
	builderFetcher builder.EntryFetcher,
	leafReader smt.LeafReader,
	querier verifier.DelegationQuerier,
) (*CountyTransferResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("cases/transfer: empty signer DID")
	}

	// Build cross-log proof.
	proof, err := verifier.BuildCrossLogProof(
		cfg.SourceCasePos, anchorRef, fetcher,
		sourceProver, localProver, sourceHead, localHead,
	)
	if err != nil {
		return nil, fmt.Errorf("cases/transfer: build cross-log proof: %w", err)
	}

	// Mark source case as transferred.
	payload, _ := json.Marshal(map[string]interface{}{
		"transfer_type": "county_transfer",
		"target_county": cfg.TargetCountyDID,
		"reason":        cfg.Reason,
		"new_status":    "transferred",
	})

	amendment, err := builder.BuildAmendment(builder.AmendmentParams{
		SignerDID:  cfg.SignerDID,
		TargetRoot: cfg.SourceCasePos,
		Payload:    payload,
		EventTime:  cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("cases/transfer: build amendment: %w", err)
	}

	result := &CountyTransferResult{
		CrossLogProof:   proof,
		SourceAmendment: amendment,
	}

	// DRIFT 2 FIX: Build delegation mirrors for the target county log.
	// The target county needs to know which officers from the source county
	// have authority over the transferred case.
	if !cfg.OfficersRootPos.IsNull() && cfg.MirrorSignerDID != "" && cfg.SourceLogDID != "" {
		mirrors, mErr := delegation.BulkMirrorSync(
			cfg.OfficersRootPos,
			cfg.MirrorSignerDID,
			cfg.SourceLogDID,
			builderFetcher,
			leafReader,
			querier,
			cfg.EventTime,
		)
		if mErr == nil {
			result.DelegationMirrors = mirrors
		}
		// Non-fatal: mirrors are informational. Transfer proceeds without them.
	}

	return result, nil
}
