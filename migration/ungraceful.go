/*
FILE PATH: migration/ungraceful.go

DESCRIPTION:
    Ungraceful migration: the current exchange has disappeared or is
    uncooperative. The court recovers via M-of-N escrow, stands up a
    new exchange, replays the log, and rotates keys.

    This is NOT a special protocol operation. Every step uses standard
    primitives that every other operation uses:
      - Copy log history: public HTTP tile read
      - Rebuild SMT: ProcessBatch replay
      - Recover keys: M-of-N escrow
      - Rotate keys: three-tier key rotation
      - Update endpoints: DID Document edit

    Carries correction #4: uses ActivateRemoval (guide §20.2) for
    the N-1 scope removal that ejects a failed exchange.

KEY DEPENDENCIES:
    - ortholog-sdk/lifecycle: InitiateRecovery, CollectShares,
      ExecuteRecovery, EvaluateArbitration (guide §20.3)
    - ortholog-sdk/lifecycle: ExecuteRemoval, ActivateRemoval (guide §20.2)
    - ortholog-sdk/builder: BuildKeyRotation, BuildKeyPrecommit,
      BuildAmendment (guide §11.3)
    - ortholog-sdk/verifier: EvaluateKeyRotation (guide §23.5)
*/
package migration

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
)

// UngracefulMigrationConfig configures recovery from a failed exchange.
type UngracefulMigrationConfig struct {
	// CourtDID is the institutional DID of the affected court.
	CourtDID string

	// FailedExchangeDID is the DID of the exchange that disappeared.
	FailedExchangeDID string

	// NewExchangeDID is the DID of the replacement exchange.
	NewExchangeDID string

	// EscrowShareProviders are the escrow nodes from which shares
	// will be collected. Need at least M of N.
	EscrowShareProviders []EscrowShareProvider

	// RecoveryThreshold is M in M-of-N.
	RecoveryThreshold int

	// LogDIDs being recovered.
	OfficersLogDID string
	CasesLogDID    string
	PartiesLogDID  string

	// ObjectiveTriggers are evidence of the exchange's failure, enabling
	// the 7-day reduced time-lock on scope removal (vs 90-day default).
	ObjectiveTriggers []ObjectiveTrigger
}

// EscrowShareProvider identifies an escrow node and the share it holds.
type EscrowShareProvider struct {
	NodeDID string
	Share   []byte
}

// ObjectiveTrigger identifies misbehavior proof for time-lock reduction.
type ObjectiveTrigger struct {
	Type             string   // "equivocation", "missed_sla", "escrow_liveness_failure"
	EvidencePointers []uint64 // log positions of evidence entries
}

// UngracefulMigrationPlan contains the recovery sequence.
type UngracefulMigrationPlan struct {
	// Phase 1: Recovery
	RecoveryRequest *lifecycle.RecoveryRequest
	RecoveredKeys   *lifecycle.RecoveryResult

	// Phase 2: Scope removal of failed exchange
	RemovalExecution *lifecycle.RemovalExecution

	// Phase 3: Key rotation to new exchange
	KeyRotations []*builder.EntryBuildResult

	// Phase 4: DID Document update (off-protocol, DNS)
	DIDDocumentUpdateRequired bool
}

// InitiateUngracefulMigration begins the recovery process.
// Step 1: Publish a recovery request entry on the consortium log.
func InitiateUngracefulMigration(cfg UngracefulMigrationConfig) (*lifecycle.RecoveryRequest, error) {
	if cfg.CourtDID == "" || cfg.FailedExchangeDID == "" || cfg.NewExchangeDID == "" {
		return nil, fmt.Errorf("migration/ungraceful: court, failed, and new exchange DIDs required")
	}

	return lifecycle.InitiateRecovery(lifecycle.RecoveryRequestParams{
		RequesterDID:  cfg.CourtDID,
		TargetDID:     cfg.FailedExchangeDID,
		RecoveryType:  "exchange_failure",
		Reason:        fmt.Sprintf("Exchange %s unresponsive, initiating ungraceful migration", cfg.FailedExchangeDID),
	})
}

// CollectEscrowShares gathers M-of-N shares from escrow nodes.
// Each node provides its share independently.
func CollectEscrowShares(params lifecycle.ShareCollectionParams) (*lifecycle.ShareCollection, error) {
	return lifecycle.CollectShares(params)
}

// ExecuteKeyRecovery reconstructs the signing keys from collected
// shares. Math (Shamir), not policy — no admin override possible.
func ExecuteKeyRecovery(params lifecycle.RecoveryExecutionParams) (*lifecycle.RecoveryResult, error) {
	return lifecycle.ExecuteRecovery(params)
}

// EjectFailedExchange initiates scope removal of the failed exchange
// from the consortium. Uses N-1 consent with optional objective
// triggers for 7-day reduced time-lock.
//
// Correction #4: this is where ActivateRemoval is used.
func EjectFailedExchange(cfg UngracefulMigrationConfig) (*lifecycle.RemovalExecution, error) {
	var evidencePointers []uint64
	for _, trigger := range cfg.ObjectiveTriggers {
		evidencePointers = append(evidencePointers, trigger.EvidencePointers...)
	}

	return lifecycle.ExecuteRemoval(lifecycle.RemovalExecutionParams{
		ExecutorDID:      cfg.CourtDID,
		TargetDID:        cfg.FailedExchangeDID,
		Reason:           fmt.Sprintf("Exchange %s failed, ungraceful migration to %s", cfg.FailedExchangeDID, cfg.NewExchangeDID),
		EvidencePointers: evidencePointers,
	})
}

// ActivateExchangeRemoval finalizes the removal after the time-lock
// expires. This is the terminal step — the failed exchange DID is
// removed from the authority set.
//
// Correction #4: ActivateRemoval with EvidencePointers.
func ActivateExchangeRemoval(
	executorDID string,
	removalEntryPos uint64,
	triggers []ObjectiveTrigger,
) (*lifecycle.RemovalActivation, error) {
	var evidencePointers []uint64
	for _, t := range triggers {
		evidencePointers = append(evidencePointers, t.EvidencePointers...)
	}

	return lifecycle.ActivateRemoval(lifecycle.ActivateRemovalParams{
		ExecutorDID:      executorDID,
		RemovalEntryPos:  removalEntryPos,
		EvidencePointers: evidencePointers,
	})
}

// PublishMigrationRecord creates a commentary entry documenting the
// ungraceful migration for the permanent audit trail.
func PublishMigrationRecord(
	signerDID string,
	cfg UngracefulMigrationConfig,
) (*builder.EntryBuildResult, error) {
	payload, _ := json.Marshal(map[string]any{
		"migration_type":    "ungraceful",
		"failed_exchange":   cfg.FailedExchangeDID,
		"new_exchange":      cfg.NewExchangeDID,
		"recovery_threshold": cfg.RecoveryThreshold,
		"trigger_count":     len(cfg.ObjectiveTriggers),
		"timestamp":         time.Now().UTC(),
	})

	return builder.BuildCommentary(builder.CommentaryParams{
		SignerDID:     signerDID,
		DomainPayload: payload,
	})
}
