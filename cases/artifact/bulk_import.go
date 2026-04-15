/*
FILE PATH:
    cases/artifact/bulk_import.go

DESCRIPTION:
    Handles batch PublishArtifact operations for historical record digitization.
    Used during court onboarding when migrating records from legacy CMS systems.

KEY ARCHITECTURAL DECISIONS:
    - Sequential processing: historical imports are not latency-sensitive.
      Rate limiting requires sequential control flow.
    - ContinueOnError: individual record failures are recorded but do not
      stop the batch. Legacy records may have corrupt data.
    - Uses builder.EntryFetcher (SDK canonical type) — no local redefinition.
    - PRE delegation key pattern is inherited from PublishArtifact — no
      additional logic needed here.

OVERVIEW:
    Each ImportRecord is encrypted via PublishArtifact with configurable
    rate limiting (tokens/second). Progress callbacks report per-record
    status. Summary report includes per-record CIDs and errors.

KEY DEPENDENCIES:
    - ortholog-sdk/builder: EntryFetcher for schema resolution in PublishArtifact
    - ortholog-sdk/lifecycle: ArtifactKeyStore for key persistence
    - ortholog-sdk/storage: ContentStore for ciphertext push
    - cases/artifact/publish.go: PublishArtifact for per-record encryption
*/
package artifact

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Types
// -------------------------------------------------------------------------------------------------

// ImportRecord describes one historical record to import.
type ImportRecord struct {
	Plaintext         []byte
	SchemaRef         types.LogPosition
	OwnerDID          string
	Metadata          map[string]string
	RecordID          string
	DisclosureScope   string
	InitialRecipients []string
}

// ImportedRecord holds the result for one imported record.
type ImportedRecord struct {
	RecordID  string
	Published *PublishedArtifact
	Error     error
}

// BulkImportConfig configures a bulk import operation.
type BulkImportConfig struct {
	Records          []ImportRecord
	RateLimit        int
	ProgressCallback func(completed, total int, recordID string, err error)
	ContinueOnError  bool
}

// BulkImportResult holds the aggregate outcome.
type BulkImportResult struct {
	Total     int
	Succeeded int
	Failed    int
	Records   []ImportedRecord
	Duration  time.Duration
}

// -------------------------------------------------------------------------------------------------
// 2) BulkImport
// -------------------------------------------------------------------------------------------------

// BulkImport processes a batch of historical records, encrypting and
// pushing each to the content store via PublishArtifact.
func BulkImport(
	cfg BulkImportConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
	extractor schema.SchemaParameterExtractor,
	fetcher builder.EntryFetcher,
	resolver did.DIDResolver,
) (*BulkImportResult, error) {
	if contentStore == nil || keyStore == nil {
		return nil, fmt.Errorf("artifact/bulk_import: nil content store or key store")
	}

	result := &BulkImportResult{
		Total:   len(cfg.Records),
		Records: make([]ImportedRecord, 0, len(cfg.Records)),
	}

	start := time.Now()

	var minInterval time.Duration
	if cfg.RateLimit > 0 {
		minInterval = time.Second / time.Duration(cfg.RateLimit)
	}

	for i, record := range cfg.Records {
		opStart := time.Now()

		published, err := PublishArtifact(
			PublishConfig{
				Plaintext:         record.Plaintext,
				SchemaRef:         record.SchemaRef,
				OwnerDID:          record.OwnerDID,
				Metadata:          record.Metadata,
				DisclosureScope:   record.DisclosureScope,
				InitialRecipients: record.InitialRecipients,
			},
			contentStore,
			keyStore,
			extractor,
			fetcher,
			resolver,
		)

		imported := ImportedRecord{
			RecordID:  record.RecordID,
			Published: published,
			Error:     err,
		}
		result.Records = append(result.Records, imported)

		if err != nil {
			result.Failed++
			if !cfg.ContinueOnError {
				result.Duration = time.Since(start)
				return result, fmt.Errorf("artifact/bulk_import: record %s: %w", record.RecordID, err)
			}
		} else {
			result.Succeeded++
		}

		if cfg.ProgressCallback != nil {
			cfg.ProgressCallback(i+1, result.Total, record.RecordID, err)
		}

		if minInterval > 0 {
			elapsed := time.Since(opStart)
			if elapsed < minInterval {
				time.Sleep(minInterval - elapsed)
			}
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}
