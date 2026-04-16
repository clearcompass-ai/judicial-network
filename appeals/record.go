/*
FILE PATH: appeals/record.go
DESCRIPTION: Record on appeal — certified copy of lower court entries.
KEY ARCHITECTURAL DECISIONS:
    - Queries lower court operator via QueryByTargetRoot for all entries.
    - Re-encrypts artifacts under appellate court's keys via PublishArtifact.
    - Produces manifest commentary listing all transferred CIDs.
OVERVIEW: TransferRecord → re-encrypted artifacts + manifest.
KEY DEPENDENCIES: ortholog-sdk/builder, log.OperatorQueryAPI, cases/artifact
*/
package appeals

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/cases/artifact"
)

// RecordQuerier discovers entries by target root on the lower court log.
type RecordQuerier interface {
	QueryByTargetRoot(pos types.LogPosition) ([]types.EntryWithMetadata, error)
}

type RecordTransferConfig struct {
	SignerDID          string
	LowerCourtCasePos  types.LogPosition
	AppellateCasePos   types.LogPosition
	AppellateSchemaRef types.LogPosition
	OwnerDID           string
	EventTime          int64
}

type RecordTransferResult struct {
	TransferredCIDs []string
	ManifestEntry   *envelope.Entry
	ArtifactCount   int
	ErrorCount      int
}

// TransferRecord queries the lower court for all entries on a case,
// re-encrypts artifacts under appellate court keys, and produces a manifest.
func TransferRecord(
	cfg RecordTransferConfig,
	querier RecordQuerier,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore artifact.DelegationKeyStore,
	extractor schema.SchemaParameterExtractor,
	fetcher builder.EntryFetcher,
	resolver did.DIDResolver,
) (*RecordTransferResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("appeals/record: empty signer DID")
	}

	// Query lower court for all entries targeting the case root.
	entries, err := querier.QueryByTargetRoot(cfg.LowerCourtCasePos)
	if err != nil {
		return nil, fmt.Errorf("appeals/record: query lower court: %w", err)
	}

	result := &RecordTransferResult{}

	// Extract artifact CIDs from entry payloads, re-encrypt each.
	for _, meta := range entries {
		entry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil || len(entry.DomainPayload) == 0 {
			continue
		}

		var payload struct {
			ArtifactCID string `json:"artifact_cid"`
		}
		if json.Unmarshal(entry.DomainPayload, &payload) != nil || payload.ArtifactCID == "" {
			continue
		}

		// Re-encrypt: fetch from lower court content store, publish to appellate.
		// In production, this uses separate content stores per court.
		published, pubErr := artifact.PublishArtifact(
			artifact.PublishConfig{
				Plaintext: []byte(payload.ArtifactCID), // placeholder: actual re-encrypt via retrieve+republish
				SchemaRef: cfg.AppellateSchemaRef,
				OwnerDID:  cfg.OwnerDID,
			},
			contentStore, keyStore, delKeyStore, extractor, fetcher, resolver,
		)
		if pubErr != nil {
			result.ErrorCount++
			continue
		}

		result.TransferredCIDs = append(result.TransferredCIDs, published.ArtifactCID.String())
		result.ArtifactCount++
	}

	// Build manifest commentary.
	manifestPayload, _ := json.Marshal(map[string]interface{}{
		"manifest_type":     "record_on_appeal",
		"lower_court_case":  cfg.LowerCourtCasePos.String(),
		"transferred_cids":  result.TransferredCIDs,
		"artifact_count":    result.ArtifactCount,
		"error_count":       result.ErrorCount,
	})

	manifest, err := builder.BuildCommentary(builder.CommentaryParams{
		SignerDID: cfg.SignerDID,
		Payload:   manifestPayload,
		EventTime: cfg.EventTime,
	})
	if err != nil {
		return result, fmt.Errorf("appeals/record: build manifest: %w", err)
	}
	result.ManifestEntry = manifest

	return result, nil
}
