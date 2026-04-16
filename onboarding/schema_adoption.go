/*
FILE PATH: onboarding/schema_adoption.go
DESCRIPTION: Adopts schemas from a source log (typically the state AOC log)
    onto the local county log. Verifies the predecessor chain and migration
    policy before publishing local copies.
KEY ARCHITECTURAL DECISIONS:
    - Two-phase design (SDK correction #6):
        Phase 1 — verifier.WalkSchemaChain: builds the full version history
        and checks for cycles / chain depth violations.
        Phase 2 — verifier.EvaluateMigration: evaluates whether referencing
        entries from a prior schema version is allowed under the migration
        policy. Caller gets both results and can make an informed
        adoption decision.
    - Local copy: uses builder.BuildRootEntity with the source payload
      (deterministic — same bytes → same CID).
OVERVIEW: AdoptSchema runs both phases and returns an AdoptionReport plus
    the local entries ready for submission.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/verifier, ortholog-sdk/schema
*/
package onboarding

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// SchemaAdoptionConfig configures schema adoption.
type SchemaAdoptionConfig struct {
	// LocalSignerDID signs the local copy of the schema (court DID).
	LocalSignerDID string

	// SourceSchemaRef is the position of the schema on the source log.
	SourceSchemaRef types.LogPosition

	// HistoricalReference is an optional older schema version the caller
	// wants to verify is still referenceable under the current migration
	// policy. If non-nil, Phase 2 evaluates sourceSchemaRef → HistoricalReference.
	// Zero (IsNull) skips Phase 2.
	HistoricalReference types.LogPosition

	// EventTime overrides the local entry timestamp. Zero → time.Now().
	EventTime int64
}

// AdoptionReport holds the outcome of schema adoption.
type AdoptionReport struct {
	// Phase1: chain walk result.
	SchemaChain *verifier.SchemaChain

	// Phase2: migration compatibility (nil if HistoricalReference was zero).
	Migration *verifier.MigrationResult

	// LocalEntry is the schema entry ready for submission to the local log.
	// Nil if adoption should NOT proceed (chain failure or migration blocked).
	LocalEntry *envelope.Entry

	// AdoptionDecision captures the go/no-go.
	Recommended bool
	Reason      string
}

// AdoptSchema runs the two-phase adoption process.
//
// Phase 1 is mandatory. Phase 2 runs only if HistoricalReference is non-zero.
// A missing predecessor schema in the chain fails Phase 1. Migration
// policies that forbid the reference fail Phase 2.
//
// When both phases succeed, LocalEntry contains a local copy of the schema
// entry, ready for submission. The caller is free to inspect SchemaChain
// and Migration before submitting (e.g., for governance review).
func AdoptSchema(
	cfg SchemaAdoptionConfig,
	fetcher builder.EntryFetcher,
	extractor schema.SchemaParameterExtractor,
) (*AdoptionReport, error) {
	if cfg.LocalSignerDID == "" {
		return nil, fmt.Errorf("onboarding/schema_adoption: empty local signer DID")
	}
	if cfg.SourceSchemaRef.IsNull() {
		return nil, fmt.Errorf("onboarding/schema_adoption: null source schema ref")
	}

	report := &AdoptionReport{}

	// Phase 1: Walk the predecessor chain.
	chain, err := verifier.WalkSchemaChain(cfg.SourceSchemaRef, fetcher, extractor)
	if err != nil {
		report.Reason = fmt.Sprintf("chain walk failed: %v", err)
		return report, nil // Report-level failure, not function-level error.
	}
	report.SchemaChain = chain

	// Phase 2: Migration evaluation (conditional).
	if !cfg.HistoricalReference.IsNull() {
		migResult := verifier.EvaluateMigration(chain, cfg.SourceSchemaRef, cfg.HistoricalReference)
		report.Migration = migResult
		if migResult != nil && !migResult.Allowed {
			report.Reason = fmt.Sprintf(
				"migration forbidden under %s policy: %s",
				migResult.Policy, migResult.Reason,
			)
			return report, nil
		}
	}

	// Build local copy from the source's Domain Payload (deterministic).
	sourceMeta, err := fetcher.Fetch(cfg.SourceSchemaRef)
	if err != nil || sourceMeta == nil {
		report.Reason = "source schema entry not fetchable"
		return report, nil
	}
	sourceEntry, err := envelope.Deserialize(sourceMeta.CanonicalBytes)
	if err != nil {
		report.Reason = "source schema deserialization failed"
		return report, nil
	}

	eventTime := cfg.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	localEntry, err := builder.BuildSchemaEntry(builder.SchemaEntryParams{
		SignerDID:             cfg.LocalSignerDID,
		Payload:               sourceEntry.DomainPayload,
		CommutativeOperations: sourceEntry.Header.CommutativeOperations,
		EventTime:             eventTime,
	})
	if err != nil {
		report.Reason = fmt.Sprintf("build local schema entry: %v", err)
		return report, nil
	}
	report.LocalEntry = localEntry

	report.Recommended = true
	report.Reason = fmt.Sprintf(
		"chain verified (%d versions, policy=%s)",
		len(chain.Versions), chain.MigrationPolicy,
	)
	return report, nil
}
