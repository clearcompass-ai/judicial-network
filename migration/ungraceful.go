package migration

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// UngracefulMigrationConfig configures recovery from a failed exchange.
type UngracefulMigrationConfig struct {
	CourtDID          string
	FailedExchangeDID string
	NewExchangeDID    string
	EscrowShareProviders []EscrowNodeInfo
	RecoveryThreshold int
	ObjectiveTriggers []ObjectiveTrigger
	EscrowPackageCID  storage.CID
}

// EscrowNodeInfo identifies an escrow node and its share.
type EscrowNodeInfo struct {
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
	RecoveryRequest *lifecycle.InitiateRecoveryResult
	RecoveredKeys   *lifecycle.RecoveryResult

	// Phase 2: Scope removal of failed exchange
	RemovalExecution *lifecycle.RemovalExecution

	// Phase 3: Key rotation to new exchange
	KeyRotations []*envelope.Entry

	// Phase 4: DID Document update (off-protocol, DNS)
	DIDDocumentUpdateRequired bool
}

// InitiateUngracefulMigration begins the recovery process.
// Step 1: Publish a recovery request entry on the consortium log.
func InitiateUngracefulMigration(cfg UngracefulMigrationConfig) (*lifecycle.InitiateRecoveryResult, error) {
	if cfg.CourtDID == "" || cfg.FailedExchangeDID == "" || cfg.NewExchangeDID == "" {
		return nil, fmt.Errorf("migration/ungraceful: court, failed, and new exchange DIDs required")
	}

	return lifecycle.InitiateRecovery(lifecycle.InitiateRecoveryParams{
		NewExchangeDID:   cfg.NewExchangeDID,
		HolderDID:        cfg.FailedExchangeDID,
		Reason:           fmt.Sprintf("Exchange %s unresponsive, initiating ungraceful migration", cfg.FailedExchangeDID),
		EscrowPackageCID: cfg.EscrowPackageCID,
	})
}

// CollectEscrowShares gathers M-of-N shares from escrow nodes.
func CollectEscrowShares(params lifecycle.CollectSharesParams) (*lifecycle.CollectedShares, error) {
	return lifecycle.CollectShares(params)
}

// ExecuteKeyRecovery reconstructs the signing keys from collected shares.
func ExecuteKeyRecovery(params lifecycle.ExecuteRecoveryParams) (*lifecycle.RecoveryResult, error) {
	return lifecycle.ExecuteRecovery(params)
}

// EjectFailedExchange initiates scope removal of the failed exchange
// from the consortium. Uses N-1 consent with optional objective
// triggers for 7-day reduced time-lock.
//
// Correction #4: this is where ActivateRemoval is used.
func EjectFailedExchange(params lifecycle.RemovalParams) (*lifecycle.RemovalExecution, error) {
	return lifecycle.ExecuteRemoval(params)
}

// ActivateExchangeRemoval finalizes the removal after the time-lock
// expires. This is the terminal step — the failed exchange DID is
// removed from the authority set.
//
// Correction #4: ActivateRemoval with EvidencePointers.
func ActivateExchangeRemoval(params lifecycle.ActivateRemovalParams) (*envelope.Entry, error) {
	return lifecycle.ActivateRemoval(params)
}

// PublishMigrationRecord creates a commentary entry documenting the
// ungraceful migration for the permanent audit trail.
func PublishMigrationRecord(
	signerDID string,
	cfg UngracefulMigrationConfig,
) (*envelope.Entry, error) {
	payload, _ := json.Marshal(map[string]any{
		"migration_type":     "ungraceful",
		"failed_exchange":    cfg.FailedExchangeDID,
		"new_exchange":       cfg.NewExchangeDID,
		"recovery_threshold": cfg.RecoveryThreshold,
		"trigger_count":      len(cfg.ObjectiveTriggers),
		"timestamp":          time.Now().UTC(),
	})

	return builder.BuildCommentary(builder.CommentaryParams{
		SignerDID: signerDID,
		Payload:   payload,
	})
}
