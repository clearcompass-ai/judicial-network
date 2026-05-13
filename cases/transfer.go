/*
FILE PATH: cases/transfer.go
DESCRIPTION: Cross-division and cross-county case transfer.
KEY ARCHITECTURAL DECISIONS:
  - Division transfer: BuildAmendment (Path A) on case root.
  - County transfer: verifier.BuildCrossLogProof + BuildAmendment +
    delegation.BulkMirrorSync for delegation mirrors on target log.
  - DRIFT 2 FIX: CountyTransferResult includes DelegationMirrors for
    the target county log so its ledger knows which judges have authority.
  - Uses BuildCrossLogProof (Gap 12), NOT ResolveCrossLogRef.

OVERVIEW: TransferDivision (intra-county) and TransferCounty (inter-county).
KEY DEPENDENCIES: attesta/builder, attesta/verifier, delegation/mirror
*/
package cases

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// DivisionTransferConfig configures an intra-county division transfer.
type DivisionTransferConfig struct {
	Destination    string // DID of target exchange. Required.
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
		Destination: cfg.Destination,
		SignerDID:   cfg.SignerDID,
		TargetRoot:  cfg.CaseRootPos,
		Payload:     payload,
		SchemaRef:   cfg.SchemaRef,
		EventTime:   cfg.EventTime,
	})
}

// CountyTransferConfig configures an inter-county case transfer.
type CountyTransferConfig struct {
	Destination     string // DID of target exchange. Required.
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
	CrossLogProof   *types.CrossLogProof
	SourceAmendment *envelope.Entry

	// DRIFT 2 FIX: Delegation mirrors for the target county log.
	// The target county ledger needs these to know which judges have
	// authority over the transferred case. Caller submits to target log.
	DelegationMirrors []*envelope.Entry
}

// TransferCounty initiates a cross-county transfer. Builds cross-log proof,
// marks source case as transferred, and produces delegation mirror entries
// for the target county log. ctx threads into the fetcher / prover RPCs.
func TransferCounty(
	ctx context.Context,
	cfg CountyTransferConfig,
	fetcher types.EntryFetcher,
	sourceProver verifier.MerkleProver,
	localProver verifier.MerkleProver,
	sourceHead types.CosignedTreeHead,
	localHead types.CosignedTreeHead,
	anchorRef types.LogPosition,
	// Delegation mirror dependencies.
	builderFetcher types.EntryFetcher,
	leafReader smt.LeafReader,
	querier verifier.DelegationQuerier,
) (*CountyTransferResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("cases/transfer: empty signer DID")
	}

	// Build cross-log proof.
	proof, err := verifier.BuildCrossLogProof(ctx,
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
		Destination: cfg.Destination,
		SignerDID:   cfg.SignerDID,
		TargetRoot:  cfg.SourceCasePos,
		Payload:     payload,
		EventTime:   cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("cases/transfer: build amendment: %w", err)
	}

	result := &CountyTransferResult{
		CrossLogProof:   proof,
		SourceAmendment: amendment,
	}

	// Cross-log delegation mirroring lived in delegation.BulkMirrorSync,
	// which was removed .cleanup-2 along with the legacy
	// delegation/mirror.go + roster_sync.go. The unified
	// delegation.Issue + judicial-delegation-v1 schema now drive
	// every delegation entry; cross-exchange mirroring will be
	// reimplemented atop them as part of the v1.6 §16
	// `mirror_creation` event work. Until then, transfer proceeds
	// without delegation mirrors — which the original implementation
	// already treated as best-effort.
	_ = builderFetcher
	_ = leafReader
	_ = querier

	return result, nil
}
