/*
FILE PATH:
    cases/artifact/bulk_import.go

DESCRIPTION:
    Handles batch PublishArtifact operations for historical record digitization.
    Used during court onboarding when migrating records from legacy CMS systems.

KEY ARCHITECTURAL DECISIONS:
    - Sequential processing with rate limiting.
    - ContinueOnError for corrupt legacy records.
    - Passes both keyStore (AES-GCM) and delKeyStore (PRE) through to
      PublishArtifact. Either may be nil depending on the import schemas.

OVERVIEW:
    Each ImportRecord is encrypted via PublishArtifact with configurable
    rate limiting. Progress callbacks report per-record status.

KEY DEPENDENCIES:
    - ortholog-sdk/builder: EntryFetcher
    - ortholog-sdk/lifecycle: ArtifactKeyStore
    - ortholog-sdk/storage: ContentStore
    - DelegationKeyStore (defined in publish.go)
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

// BulkImport processes a batch of historical records.
// keyStore: AES-GCM keys. delKeyStore: PRE delegation keys. Either may be nil.
func BulkImport(
	cfg BulkImportConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore DelegationKeyStore,
	extractor schema.SchemaParameterExtractor,
	fetcher builder.EntryFetcher,
	resolver did.DIDResolver,
) (*BulkImportResult, error) {
	if contentStore == nil {
		return nil, fmt.Errorf("artifact/bulk_import: nil content store")
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
			delKeyStore,
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
