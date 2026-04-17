/*
FILE PATH: migration/graceful.go

DESCRIPTION:
    Graceful migration of a court from one exchange to another. Both
    exchanges cooperate. Exchange A provides keys, Exchange B creates
    new entries. The protocol sees normal entries — it doesn't know
    a migration is happening.

    Steps:
    1. Exchange B stands up new infrastructure
    2. Exchange B mirrors tiles from Exchange A (public HTTP)
    3. Exchange A provides decryption keys to Exchange B
    4. Exchange B creates succession entries
    5. Exchange B re-encrypts artifacts under new keys
    6. Exchange B publishes key rotations
    7. Court updates DID Document to point to Exchange B

KEY DEPENDENCIES:
    - ortholog-sdk/builder: BuildSuccession, BuildAmendment,
      BuildKeyRotation, BuildKeyPrecommit (guide §11.3)
    - ortholog-sdk/lifecycle: ReEncryptWithGrant (guide §20.4)
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

// GracefulMigrationConfig configures a cooperative exchange migration.
type GracefulMigrationConfig struct {
	// CourtDID is the institutional DID of the migrating court.
	CourtDID string

	// SourceExchangeDID is Exchange A's DID.
	SourceExchangeDID string

	// DestExchangeDID is Exchange B's DID.
	DestExchangeDID string

	// LogDIDs are the three log DIDs being migrated.
	OfficersLogDID string
	CasesLogDID    string
	PartiesLogDID  string

	// NewAuthorityKeys are the key material for Exchange B.
	// Used for key rotation entries.
	NewAuthorityKeys []KeyMaterial
}

// KeyMaterial represents a key for rotation.
type KeyMaterial struct {
	KeyID     string
	PublicKey []byte
	Purpose   string // "signing" | "encryption" | "delegation"
}

// GracefulMigrationPlan contains all entries needed for the migration.
type GracefulMigrationPlan struct {
	// SuccessionEntries announce the exchange change on each log.
	SuccessionEntries []*builder.EntryBuildResult

	// KeyRotationEntries rotate keys to Exchange B's keys.
	KeyRotationEntries []*builder.EntryBuildResult

	// ArtifactReEncryptions lists CIDs that need re-encryption.
	ArtifactReEncryptions []ArtifactReEncryption
}

// ArtifactReEncryption describes one artifact that needs re-encryption
// under Exchange B's keys.
type ArtifactReEncryption struct {
	OriginalCID string
	NewCID      string
	EntityDID   string
}

// PlanGracefulMigration builds the complete migration plan. The caller
// submits entries in order to each log's operator.
func PlanGracefulMigration(cfg GracefulMigrationConfig) (*GracefulMigrationPlan, error) {
	if cfg.CourtDID == "" {
		return nil, fmt.Errorf("migration/graceful: empty court DID")
	}
	if cfg.SourceExchangeDID == "" || cfg.DestExchangeDID == "" {
		return nil, fmt.Errorf("migration/graceful: source and dest exchange DIDs required")
	}

	plan := &GracefulMigrationPlan{}

	// Build succession entries for each log.
	for _, logDID := range []string{cfg.OfficersLogDID, cfg.CasesLogDID, cfg.PartiesLogDID} {
		if logDID == "" {
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
			SignerDID:     cfg.CourtDID,
			DomainPayload: payload,
		})
		if err != nil {
			return nil, fmt.Errorf("migration/graceful: succession for %s: %w", logDID, err)
		}
		plan.SuccessionEntries = append(plan.SuccessionEntries, entry)
	}

	// Build key rotation entries.
	for _, key := range cfg.NewAuthorityKeys {
		payload, _ := json.Marshal(map[string]any{
			"rotation_reason": "exchange_migration",
			"key_id":          key.KeyID,
			"purpose":         key.Purpose,
		})

		entry, err := builder.BuildKeyRotation(builder.KeyRotationParams{
			SignerDID:     cfg.CourtDID,
			NewPublicKey:  key.PublicKey,
			DomainPayload: payload,
		})
		if err != nil {
			return nil, fmt.Errorf("migration/graceful: key rotation for %s: %w", key.KeyID, err)
		}
		plan.KeyRotationEntries = append(plan.KeyRotationEntries, entry)
	}

	return plan, nil
}

// ReEncryptArtifact re-encrypts a single artifact under new keys using
// the SDK's ReEncryptWithGrant (guide §20.4).
func ReEncryptArtifact(params lifecycle.ReEncryptParams) (*lifecycle.ReEncryptResult, error) {
	return lifecycle.ReEncryptWithGrant(params)
}
