/*
FILE PATH: escrow/event_builder.go

DESCRIPTION:
    Domain-side wrappers around the SDK's M-of-N escrow-recovery
    primitives + the migration package's arbitration evaluator.

    The SDK provides four pure functions:

      lifecycle.InitiateRecovery     → unsigned commentary entry
      lifecycle.CollectShares        → validates per-share input
      lifecycle.ExecuteRecovery      → reconstructs MasterKey + optional
                                       Succession Entry
      lifecycle.EvaluateArbitration  → hostile-override verdict

    This package wraps Initiate + Migration-record + Arbitrate at the
    domain shape needed by the judicial HTTP surface. CollectShares
    and ExecuteRecovery are deliberately NOT wrapped here — they
    require multi-request server-side state (share accumulation) and
    expose raw 32-byte MasterKey material respectively, both of which
    are operator-tooling territory and not safe to drive from a
    request/response HTTP shape.

    Migration-record is included because every successful recovery
    publishes a permanent commentary entry summarising the migration
    for audit. It's the publish-side complement to Initiate.
*/
package escrow

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/migration"
)

// RecoveryInitiateConfig configures the recovery-request entry. The
// caller signs and submits the returned entry separately (the
// signing key may be air-gapped, HSM-bound, or otherwise not
// reachable at construction time).
type RecoveryInitiateConfig struct {
	// Destination is the consortium / network DID hosting the
	// recovery log. Validated by envelope.ValidateDestination.
	Destination string

	// CourtDID is the court whose escrow package is being recovered.
	// Recorded in the migration audit trail.
	CourtDID string

	// FailedExchangeDID identifies the exchange whose keys are
	// unrecoverable through the cooperative path.
	FailedExchangeDID string

	// NewExchangeDID is the successor exchange whose key signs the
	// Succession Entry built later by ExecuteRecovery.
	NewExchangeDID string

	// EscrowPackageCID locates the holder's escrow package in the
	// content-addressed store. The package carries the M-of-N
	// configuration and per-node ECIES-wrapped shares.
	EscrowPackageCID string
}

// BuildRecoveryRequest produces the unsigned recovery-request
// commentary entry. The result is suitable for signing and
// submission via the standard /v1/entries/submit pipeline.
//
// Wraps migration.InitiateUngracefulMigration; the JN migration
// package adds the court-DID + failed-exchange context the SDK
// recovery primitive doesn't directly carry.
func BuildRecoveryRequest(cfg RecoveryInitiateConfig) (*lifecycle.InitiateRecoveryResult, error) {
	if cfg.CourtDID == "" || cfg.FailedExchangeDID == "" || cfg.NewExchangeDID == "" {
		return nil, fmt.Errorf("escrow/recovery: court / failed-exchange / new-exchange DIDs all required")
	}
	mcfg := migration.UngracefulMigrationConfig{
		Destination:       cfg.Destination,
		CourtDID:          cfg.CourtDID,
		FailedExchangeDID: cfg.FailedExchangeDID,
		NewExchangeDID:    cfg.NewExchangeDID,
		// EscrowPackageCID is plumbed through migration as a
		// storage.CID; the migration helper constructs it. We pass
		// the string form via the migration config which holds it.
	}
	if cfg.EscrowPackageCID != "" {
		cid, err := storage.ParseCID(cfg.EscrowPackageCID)
		if err != nil {
			return nil, fmt.Errorf("escrow/recovery: parse escrow_package_cid: %w", err)
		}
		mcfg.EscrowPackageCID = cid
	}
	return migration.InitiateUngracefulMigration(mcfg)
}

// MigrationRecordConfig configures the post-recovery commentary
// entry that records the migration outcome for the permanent audit
// trail.
type MigrationRecordConfig struct {
	Destination       string
	SignerDID         string
	CourtDID          string
	FailedExchangeDID string
	NewExchangeDID    string
	RecoveryThreshold int
	TriggerCount      int
}

// BuildMigrationRecord wraps migration.PublishMigrationRecord. The
// returned entry is unsigned; caller signs and submits.
func BuildMigrationRecord(cfg MigrationRecordConfig) (*envelope.Entry, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("escrow/migration-record: signer DID required")
	}
	mcfg := migration.UngracefulMigrationConfig{
		Destination:       cfg.Destination,
		CourtDID:          cfg.CourtDID,
		FailedExchangeDID: cfg.FailedExchangeDID,
		NewExchangeDID:    cfg.NewExchangeDID,
		RecoveryThreshold: cfg.RecoveryThreshold,
	}
	// Synthesise an empty trigger slice of the right length so the
	// record's trigger_count payload field reflects the caller's
	// declared count. The migration package only counts the slice.
	if cfg.TriggerCount > 0 {
		mcfg.ObjectiveTriggers = make([]migration.ObjectiveTrigger, cfg.TriggerCount)
	}
	return migration.PublishMigrationRecord(cfg.SignerDID, mcfg)
}

// EvaluateArbitration wraps migration.ArbitrateHostileRecovery,
// which itself wraps lifecycle.EvaluateArbitration. Pure evaluation
// — no entries built, no key material exposed. Suitable for an HTTP
// shape because all inputs are caller-supplied (the caller already
// fetched approvals + witness cosig from the operator).
func EvaluateArbitration(
	recoveryRequestPos types.LogPosition,
	escrowApprovals []types.EntryWithMetadata,
	totalEscrowNodes int,
	escrowNodeSet map[string]bool,
	witnessCosig *types.EntryWithMetadata,
	schemaParams *types.SchemaParameters,
) (*lifecycle.ArbitrationResult, error) {
	return migration.ArbitrateHostileRecovery(
		recoveryRequestPos,
		escrowApprovals,
		totalEscrowNodes,
		escrowNodeSet,
		witnessCosig,
		schemaParams,
	)
}

