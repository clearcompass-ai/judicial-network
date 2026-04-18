package migration

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// GracefulMigrationConfig configures a cooperative exchange transfer.
type GracefulMigrationConfig struct {
	Destination string // DID of target exchange. Required.
	CourtDID         string
	SourceExchangeDID string
	DestExchangeDID  string
	OfficersLogDID   string
	CasesLogDID      string
	PartiesLogDID    string
	NewAuthorityKeys []KeyMaterial

	// EntityPositions maps log DID → entity position for succession.
	EntityPositions map[string]types.LogPosition
}

// KeyMaterial represents a key for rotation.
type KeyMaterial struct {
	KeyID     string
	PublicKey []byte
	Purpose   string
	EntityPos types.LogPosition // DID profile entity position for TargetRoot.
}

// GracefulMigrationPlan contains all entries needed for the migration.
type GracefulMigrationPlan struct {
	SuccessionEntries  []*envelope.Entry
	KeyRotationEntries []*envelope.Entry
	ArtifactReEncryptions []ArtifactReEncryption
}

// ArtifactReEncryption describes one artifact that needs re-encryption.
type ArtifactReEncryption struct {
	OriginalCID string
	NewCID      string
	EntityDID   string
}

// PlanGracefulMigration builds the complete migration plan.
func PlanGracefulMigration(cfg GracefulMigrationConfig) (*GracefulMigrationPlan, error) {
	if cfg.CourtDID == "" {
		return nil, fmt.Errorf("migration/graceful: empty court DID")
	}
	if cfg.SourceExchangeDID == "" || cfg.DestExchangeDID == "" {
		return nil, fmt.Errorf("migration/graceful: source and dest exchange DIDs required")
	}

	plan := &GracefulMigrationPlan{}

	for _, logDID := range []string{cfg.OfficersLogDID, cfg.CasesLogDID, cfg.PartiesLogDID} {
		if logDID == "" {
			continue
		}

		entityPos, ok := cfg.EntityPositions[logDID]
		if !ok {
			continue
		}

		payload, _ := json.Marshal(map[string]any{
			"migration_type":  "graceful",
			"source_exchange": cfg.SourceExchangeDID,
			"dest_exchange":   cfg.DestExchangeDID,
			"log_did":         logDID,
			"timestamp":       time.Now().UTC(),
		})

		entry, err := builder.BuildSuccession(builder.SuccessionParams{
			Destination: cfg.Destination,
			SignerDID:    cfg.CourtDID,
			TargetRoot:   entityPos,
			NewSignerDID: cfg.DestExchangeDID,
			Payload:      payload,
		})
		if err != nil {
			return nil, fmt.Errorf("migration/graceful: succession for %s: %w", logDID, err)
		}
		plan.SuccessionEntries = append(plan.SuccessionEntries, entry)
	}

	for _, key := range cfg.NewAuthorityKeys {
		payload, _ := json.Marshal(map[string]any{
			"rotation_reason": "exchange_migration",
			"key_id":          key.KeyID,
			"purpose":         key.Purpose,
		})

		entry, err := builder.BuildKeyRotation(builder.KeyRotationParams{
			Destination: cfg.Destination,
			SignerDID:    cfg.CourtDID,
			TargetRoot:   key.EntityPos,
			NewPublicKey: key.PublicKey,
			Payload:      payload,
		})
		if err != nil {
			return nil, fmt.Errorf("migration/graceful: key rotation for %s: %w", key.KeyID, err)
		}
		plan.KeyRotationEntries = append(plan.KeyRotationEntries, entry)
	}

	return plan, nil
}

// ReEncryptArtifact re-encrypts a single artifact under new keys.
func ReEncryptArtifact(params lifecycle.ReEncryptWithGrantParams) (*lifecycle.ReEncryptWithGrantResult, error) {
	return lifecycle.ReEncryptWithGrant(params)
}
