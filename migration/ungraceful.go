package migration

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ErrArbitrationDenied surfaces the arbitration verdict when a
// hostile-recovery override fails its policy check (insufficient
// approvals, missing or non-independent witness, etc.). Stable
// sentinel for audit pipelines.
var ErrArbitrationDenied = errors.New("migration/ungraceful: arbitration denied — override not authorized")

// UngracefulMigrationConfig configures recovery from a failed exchange.
type UngracefulMigrationConfig struct {
	Destination string // DID of target exchange. Required.
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
		Destination:      cfg.Destination,
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

// ArbitrateHostileRecovery is the consensus-override path documented
// in ortholog-sdk/docs/recovery.md Part 2: Arbitrated / Hostile
// Recovery. When cooperative escrow recovery is impossible (stolen
// keys, rogue staff, escrow-node failure) the network administrators
// vote and an independent witness cosigns; SDK math evaluates whether
// the supermajority + independence policy was satisfied.
//
// Wraps lifecycle.EvaluateArbitration. Returns the SDK's
// *ArbitrationResult unchanged on the success path; on denial,
// returns *ArbitrationResult AND ErrArbitrationDenied so callers can
// errors.Is the rejection. Infrastructure errors propagate verbatim.
//
// The caller is responsible for:
//   - Discovering EscrowApprovals via QueryByCosignatureOf on the
//     RecoveryRequest entry (typically via OperatorQueryAPI).
//   - Resolving the SchemaParams for the override's governance
//     scope (override threshold + witness requirement).
//   - Supplying the EscrowNodeSet from the consortium config.
//   - Publishing the resulting override entry only AFTER the SDK
//     has authorized; this function does NOT publish.
func ArbitrateHostileRecovery(
	recoveryRequestPos types.LogPosition,
	escrowApprovals []types.EntryWithMetadata,
	totalEscrowNodes int,
	escrowNodeSet map[string]bool,
	witnessCosig *types.EntryWithMetadata,
	schemaParams *types.SchemaParameters,
) (*lifecycle.ArbitrationResult, error) {
	res, err := lifecycle.EvaluateArbitration(lifecycle.ArbitrationParams{
		RecoveryRequestPos: recoveryRequestPos,
		EscrowApprovals:    escrowApprovals,
		TotalEscrowNodes:   totalEscrowNodes,
		EscrowNodeSet:      escrowNodeSet,
		WitnessCosignature: witnessCosig,
		SchemaParams:       schemaParams,
	})
	if err != nil {
		return nil, fmt.Errorf("migration/ungraceful: arbitrate: %w", err)
	}
	if !res.OverrideAuthorized {
		return res, fmt.Errorf("%w: %s (approvals=%d/%d, witness=%v)",
			ErrArbitrationDenied, res.Reason, res.ApprovalCount,
			res.RequiredCount, res.HasWitnessCosig)
	}
	return res, nil
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
		Destination: cfg.Destination,
		SignerDID: signerDID,
		Payload:   payload,
	})
}
