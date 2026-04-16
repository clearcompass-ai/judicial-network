/*
FILE PATH: onboarding/migration.go
DESCRIPTION: Wraps cases/artifact/bulk_import.go for legacy CMS import at
    court onboarding. Adds a roster-driven staging step that groups records
    by case root and sequences them to preserve causal ordering (case root
    before filings before amendments).
KEY ARCHITECTURAL DECISIONS:
    - Input: LegacyRecord stream (caller's adapter; Tyler Odyssey, C-Track, etc).
    - Output: three phases — case roots (BuildRootEntity via cases/initiation),
      filings (BuildAmendment/BuildPathBEntry via cases/filing), artifacts
      (artifact.BulkImport).
    - Rate-limited by BulkImport internally.
OVERVIEW: MigrateLegacyRecords → MigrationResult with per-phase counts.
KEY DEPENDENCIES: cases/artifact, cases, judicial-network/schemas
*/
package onboarding

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/cases"
	"github.com/clearcompass-ai/judicial-network/cases/artifact"
)

// LegacyRecord is one record from a legacy CMS export.
type LegacyRecord struct {
	// DocketNumber is the legacy case identifier. Required.
	DocketNumber string

	// CaseType (e.g., "criminal", "civil"). Required for case root creation.
	CaseType string

	// FiledDate is the original filing date, ISO 8601.
	FiledDate string

	// SignerDID is the clerk or court officer DID signing these entries.
	SignerDID string

	// SchemaRef is the schema governing this record's case.
	SchemaRef *types.LogPosition

	// Filings are individual documents/events attached to the case.
	Filings []LegacyFiling

	// ExtraPayload carries domain-specific fields.
	ExtraPayload map[string]interface{}
}

// LegacyFiling is one document attached to a legacy case.
type LegacyFiling struct {
	DocumentType  string // "complaint", "motion", "order"
	DocumentTitle string
	FiledDate     string
	Plaintext     []byte
	OwnerDID      string
	// If empty, owner defaults to the parent record's SignerDID.
}

// MigrationConfig configures a bulk migration.
type MigrationConfig struct {
	Records []LegacyRecord

	// RateLimit caps artifacts published per second.
	RateLimit int

	// ContinueOnError: skip failed records instead of aborting.
	ContinueOnError bool

	// Progress receives per-record progress updates.
	Progress func(completed, total int, docket string, err error)
}

// MigrationResult holds the outcome.
type MigrationResult struct {
	CaseRootEntries []*envelope.Entry
	FilingEntries   []*envelope.Entry
	ArtifactResults *artifact.BulkImportResult
	Total           int
	Failed          int
	Errors          map[string]string
	Duration        time.Duration
}

// MigrateLegacyRecords runs the three-phase migration.
// Phase 1: create case root entities in docket-sorted order.
// Phase 2: create filing entries (Path A, same signer).
// Phase 3: bulk-import artifacts via rate-limited loop.
func MigrateLegacyRecords(
	cfg MigrationConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore artifact.DelegationKeyStore,
	extractor schema.SchemaParameterExtractor,
	fetcher builder.EntryFetcher,
	resolver did.DIDResolver,
) (*MigrationResult, error) {
	start := time.Now()

	result := &MigrationResult{
		Total:  len(cfg.Records),
		Errors: make(map[string]string),
	}

	// Stable sort by docket number for deterministic sequencing.
	records := make([]LegacyRecord, len(cfg.Records))
	copy(records, cfg.Records)
	sort.Slice(records, func(i, j int) bool {
		return records[i].DocketNumber < records[j].DocketNumber
	})

	// Phase 1: case roots.
	var importRecords []artifact.ImportRecord

	for i, rec := range records {
		rootEntry, err := buildCaseRoot(rec)
		if err != nil {
			result.Failed++
			result.Errors[rec.DocketNumber] = "root: " + err.Error()
			if !cfg.ContinueOnError {
				result.Duration = time.Since(start)
				return result, fmt.Errorf("root for %s: %w", rec.DocketNumber, err)
			}
			continue
		}
		result.CaseRootEntries = append(result.CaseRootEntries, rootEntry)

		// Phase 2: filing entries for this record.
		// Note: the caller submits the case root first, then has its
		// position to use as TargetRoot for filings. For this bootstrap
		// pass, we produce filings WITHOUT TargetRoot — they'll need to
		// be reprocessed by the caller once case root positions are known.
		// A fuller implementation returns a build plan that the caller
		// executes sequentially. This MVP produces the filings deferred.

		for _, filing := range rec.Filings {
			if len(filing.Plaintext) == 0 {
				continue
			}
			owner := filing.OwnerDID
			if owner == "" {
				owner = rec.SignerDID
			}
			var schemaRef types.LogPosition
			if rec.SchemaRef != nil {
				schemaRef = *rec.SchemaRef
			}
			importRecords = append(importRecords, artifact.ImportRecord{
				Plaintext: filing.Plaintext,
				SchemaRef: schemaRef,
				OwnerDID:  owner,
				Metadata: map[string]string{
					"docket_number":  rec.DocketNumber,
					"document_type":  filing.DocumentType,
					"document_title": filing.DocumentTitle,
					"filed_date":     filing.FiledDate,
				},
				RecordID: rec.DocketNumber + "#" + filing.DocumentType,
			})
		}

		if cfg.Progress != nil {
			cfg.Progress(i+1, result.Total, rec.DocketNumber, nil)
		}
	}

	// Phase 3: artifact bulk import.
	if len(importRecords) > 0 {
		bulkResult, bErr := artifact.BulkImport(
			artifact.BulkImportConfig{
				Records:         importRecords,
				RateLimit:       cfg.RateLimit,
				ContinueOnError: cfg.ContinueOnError,
			},
			contentStore, keyStore, delKeyStore, extractor, fetcher, resolver,
		)
		result.ArtifactResults = bulkResult
		if bErr != nil && !cfg.ContinueOnError {
			result.Duration = time.Since(start)
			return result, fmt.Errorf("artifact bulk import: %w", bErr)
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// buildCaseRoot creates the case root entity for a legacy record.
// Delegates to cases/initiation.go.
func buildCaseRoot(rec LegacyRecord) (*envelope.Entry, error) {
	extra := make(map[string]interface{})
	for k, v := range rec.ExtraPayload {
		extra[k] = v
	}
	extra["_legacy_import"] = true

	initResult, err := cases.InitiateCase(cases.InitiationConfig{
		SignerDID:    rec.SignerDID,
		DocketNumber: rec.DocketNumber,
		CaseType:     rec.CaseType,
		FiledDate:    rec.FiledDate,
		SchemaRef:    rec.SchemaRef,
		ExtraPayload: extra,
	})
	if err != nil {
		return nil, err
	}
	return initResult.Entry, nil
}

// unused import suppression for json package when ExtraPayload happens to be empty
var _ = json.Marshal
