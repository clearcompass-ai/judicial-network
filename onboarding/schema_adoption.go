/*
FILE PATH: onboarding/schema_adoption.go
DESCRIPTION: Adopts schemas from a source log (typically the state AOC log)

	onto the local county log. Verifies the predecessor chain and migration
	policy before publishing local copies.

KEY ARCHITECTURAL DECISIONS:
  - Two-phase design (SDK correction #6):
    verifier.WalkSchemaChain: builds the full version history
    and checks for cycles / chain depth violations.
    verifier.EvaluateMigration: evaluates whether referencing
    entries from a prior schema version is allowed under the migration
    policy. Caller gets both results and can make an informed
    adoption decision.
  - Local copy: uses builder.BuildRootEntity with the source payload
    (deterministic — same bytes → same CID).

OVERVIEW: AdoptSchema runs both phases and returns an AdoptionReport plus

	the local entries ready for submission.

KEY DEPENDENCIES: attesta/builder, attesta/verifier, attesta/schema
*/
package onboarding

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/schema"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// SchemaAdoptionConfig configures schema adoption.
type SchemaAdoptionConfig struct {
	Destination string // DID of target exchange. Required.
	// LocalSignerDID signs the local copy of the schema (court DID).
	LocalSignerDID string

	// SourceSchemaRef is the position of the schema on the source log.
	SourceSchemaRef types.LogPosition

	// HistoricalReference is an optional older schema version the caller
	// wants to verify is still referenceable under the current migration
	// policy. If non-nil,  evaluates sourceSchemaRef → HistoricalReference.
	// Zero (IsNull) skips .
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
//  is mandatory.  runs only if HistoricalReference is non-zero.
// A missing predecessor schema in the chain fails . Migration
// policies that forbid the reference fail .
//
// When both phases succeed, LocalEntry contains a local copy of the schema
// entry, ready for submission. The caller is free to inspect SchemaChain
// and Migration before submitting (e.g., for governance review).
func AdoptSchema(
	cfg SchemaAdoptionConfig,
	fetcher types.EntryFetcher,
	extractor schema.SchemaParameterExtractor,
) (*AdoptionReport, error) {
	if cfg.LocalSignerDID == "" {
		return nil, fmt.Errorf("onboarding/schema_adoption: empty local signer DID")
	}
	if cfg.SourceSchemaRef.IsNull() {
		return nil, fmt.Errorf("onboarding/schema_adoption: null source schema ref")
	}

	report := &AdoptionReport{}

	// : Walk the predecessor chain.
	chain, err := verifier.WalkSchemaChain(cfg.SourceSchemaRef, fetcher, extractor)
	if err != nil {
		report.Reason = fmt.Sprintf("chain walk failed: %v", err)
		return report, nil // Report-level failure, not function-level error.
	}
	report.SchemaChain = chain

	// : Migration evaluation (conditional).
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

	// Decode the source schema's structured parameters (including
	// CommutativeOperations, which now lives inside types.SchemaParameters
	// rather than on ControlHeader). The local copy is byte-stable
	// because BuildSchemaEntry re-marshals via canonical JSON.
	sourceParams, err := schema.NewJSONParameterExtractor().Extract(sourceEntry)
	if err != nil {
		report.Reason = fmt.Sprintf("extract source schema parameters: %v", err)
		return report, nil
	}

	localEntry, err := builder.BuildSchemaEntry(builder.SchemaEntryParams{
		Destination: cfg.Destination,
		SignerDID:   cfg.LocalSignerDID,
		Parameters:  *sourceParams,
		EventTime:   eventTime,
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
