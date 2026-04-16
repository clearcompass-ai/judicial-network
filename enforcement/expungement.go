/*
FILE PATH: enforcement/expungement.go
DESCRIPTION: Expungement order processing per TCA 40-32-101.
KEY ARCHITECTURAL DECISIONS:
    - Two-phase: (1) BuildEnforcement on case root (Path C, AuthorityTip advance).
      (2) artifact.BatchExpunge for cryptographic erasure of all case artifacts.
    - Both ArtifactKeyStore and DelegationKeyStore keys destroyed.
    - Activation pattern with EvaluateContest before executing erasure.
    - Produces compliance report: which CIDs were erased, which failed.
OVERVIEW: ExpungeCase → enforcement entry + batch erasure + compliance report.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/verifier, cases/artifact
*/
package enforcement

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"

	"github.com/clearcompass-ai/judicial-network/cases/artifact"
)

type ExpungementConfig struct {
	JudgeDID       string
	CaseRootPos    types.LogPosition
	ScopePos       types.LogPosition
	PriorAuthority *types.LogPosition
	SchemaRef      *types.LogPosition
	Authority      string
	ArtifactCIDs   []storage.CID
	EventTime      int64
}

type ExpungementResult struct {
	EnforcementEntry *envelope.Entry
	ExpungeResult    *artifact.BatchExpungeResult
	ComplianceReport map[string]string // CID → "destroyed" | error message
}

// ExpungeCase publishes an expungement enforcement entry and performs
// cryptographic erasure of all case artifacts.
func ExpungeCase(
	cfg ExpungementConfig,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore artifact.DelegationKeyStore,
	contentStore storage.ContentStore,
	fetcher builder.EntryFetcher,
	leafReader smt.LeafReader,
	extractor schema.SchemaParameterExtractor,
) (*ExpungementResult, error) {
	if cfg.JudgeDID == "" {
		return nil, fmt.Errorf("enforcement/expungement: empty judge DID")
	}

	// Check for unresolved contest before proceeding (SDK correction #7).
	// Expungement is irreversible — contest check is critical.
	contestResult, err := verifier.EvaluateContest(
		cfg.CaseRootPos, fetcher, leafReader, extractor,
	)
	if err == nil && contestResult != nil && contestResult.OperationBlocked {
		return nil, fmt.Errorf("enforcement/expungement: blocked by contest: %s", contestResult.Reason)
	}

	cidStrings := make([]string, len(cfg.ArtifactCIDs))
	for i, c := range cfg.ArtifactCIDs {
		cidStrings[i] = c.String()
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"order_type":         "expungement",
		"authority":          cfg.Authority,
		"affected_artifacts": cidStrings,
	})

	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		SignerDID:      cfg.JudgeDID,
		TargetRoot:     cfg.CaseRootPos,
		ScopePointer:   cfg.ScopePos,
		PriorAuthority: cfg.PriorAuthority,
		Payload:        payload,
		SchemaRef:      cfg.SchemaRef,
		EventTime:      cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("enforcement/expungement: build enforcement: %w", err)
	}

	// Phase 2: Cryptographic erasure.
	batchResult, batchErr := artifact.BatchExpunge(
		cfg.ArtifactCIDs, keyStore, delKeyStore, contentStore,
	)

	// Build compliance report.
	report := make(map[string]string, len(cfg.ArtifactCIDs))
	if batchResult != nil {
		for _, cid := range cfg.ArtifactCIDs {
			cidStr := cid.String()
			if errMsg, hasErr := batchResult.Errors[cidStr]; hasErr {
				report[cidStr] = errMsg.Error()
			} else {
				report[cidStr] = "destroyed"
			}
		}
	}

	result := &ExpungementResult{
		EnforcementEntry: entry,
		ExpungeResult:    batchResult,
		ComplianceReport: report,
	}

	if batchErr != nil {
		return result, fmt.Errorf("enforcement/expungement: batch expunge (partial): %w", batchErr)
	}

	return result, nil
}
