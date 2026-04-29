package migration

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/internal/testutil"
)

const (
	courtDID       = "did:web:courts.nashville.gov"
	sourceExchange = "did:web:exchange-a.courts.tn.gov"
	destExchange   = "did:web:exchange-b.courts.tn.gov"
	officersLog    = "did:web:courts.nashville.gov:officers"
	casesLog       = "did:web:courts.nashville.gov:cases"
	partiesLog     = "did:web:courts.nashville.gov:parties"
)

// ═════════════════════════════════════════════════════════════════════
// Graceful migration — succession + key rotation entries
// ═════════════════════════════════════════════════════════════════════

func TestGracefulMigration_ProducesSuccessionEntries(t *testing.T) {
	cfg := GracefulMigrationConfig{
		Destination: "did:web:exchange.test",
		CourtDID:          courtDID,
		SourceExchangeDID: sourceExchange,
		DestExchangeDID:   destExchange,
		OfficersLogDID:    officersLog,
		CasesLogDID:       casesLog,
		PartiesLogDID:     partiesLog,
		EntityPositions: map[string]types.LogPosition{
			officersLog: {LogDID: officersLog, Sequence: 1},
			casesLog:    {LogDID: casesLog, Sequence: 1},
			partiesLog:  {LogDID: partiesLog, Sequence: 1},
		},
	}

	plan, err := PlanGracefulMigration(cfg)
	if err != nil {
		t.Fatalf("PlanGracefulMigration: %v", err)
	}

	// Should produce 3 succession entries (one per log).
	if len(plan.SuccessionEntries) != 3 {
		t.Errorf("SuccessionEntries = %d, want 3", len(plan.SuccessionEntries))
	}

	// Each succession entry should be Path A and target the entity.
	for i, entry := range plan.SuccessionEntries {
		if entry.Header.TargetRoot == nil {
			t.Errorf("succession %d: missing TargetRoot", i)
		}
		if *entry.Header.AuthorityPath != envelope.AuthoritySameSigner {
			t.Errorf("succession %d: should be Path A (SameSigner)", i)
		}
		if entry.Header.SignerDID != courtDID {
			t.Errorf("succession %d: signer = %q, want %q", i, entry.Header.SignerDID, courtDID)
		}
	}
}

func TestGracefulMigration_KeyRotationEntries(t *testing.T) {
	cfg := GracefulMigrationConfig{
		Destination: "did:web:exchange.test",
		CourtDID:          courtDID,
		SourceExchangeDID: sourceExchange,
		DestExchangeDID:   destExchange,
		OfficersLogDID:    officersLog,
		EntityPositions: map[string]types.LogPosition{
			officersLog: {LogDID: officersLog, Sequence: 1},
		},
		NewAuthorityKeys: []KeyMaterial{
			{KeyID: "key-1", PublicKey: []byte("new-pub-key-bytes"), Purpose: "signing",
				EntityPos: types.LogPosition{LogDID: officersLog, Sequence: 5}},
		},
	}

	plan, err := PlanGracefulMigration(cfg)
	if err != nil {
		t.Fatalf("PlanGracefulMigration: %v", err)
	}

	if len(plan.KeyRotationEntries) != 1 {
		t.Fatalf("KeyRotationEntries = %d, want 1", len(plan.KeyRotationEntries))
	}

	entry := plan.KeyRotationEntries[0]
	if entry.Header.TargetRoot == nil {
		t.Fatal("key rotation must have TargetRoot")
	}
	if *entry.Header.AuthorityPath != envelope.AuthoritySameSigner {
		t.Error("key rotation should be Path A")
	}
}

func TestGracefulMigration_EmptyCourtDID_Rejected(t *testing.T) {
	_, err := PlanGracefulMigration(GracefulMigrationConfig{
		Destination: "did:web:exchange.test",
		SourceExchangeDID: sourceExchange,
		DestExchangeDID:   destExchange,
	})
	if err == nil {
		t.Fatal("expected error for empty court DID")
	}
}

func TestGracefulMigration_MissingExchangeDIDs_Rejected(t *testing.T) {
	_, err := PlanGracefulMigration(GracefulMigrationConfig{
		Destination: "did:web:exchange.test",
		CourtDID: courtDID,
	})
	if err == nil {
		t.Fatal("expected error for missing exchange DIDs")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Ungraceful migration — recovery initiation
// ═════════════════════════════════════════════════════════════════════

func TestUngracefulMigration_InitiateRecovery(t *testing.T) {
	cfg := UngracefulMigrationConfig{
		Destination: "did:web:exchange.test",
		CourtDID:          courtDID,
		FailedExchangeDID: sourceExchange,
		NewExchangeDID:    destExchange,
	}

	result, err := InitiateUngracefulMigration(cfg)
	if err != nil {
		t.Fatalf("InitiateUngracefulMigration: %v", err)
	}

	if result == nil {
		t.Fatal("recovery result is nil")
	}
	if result.RequestEntry == nil {
		t.Fatal("RequestEntry is nil")
	}

	// Recovery request is a commentary entry.
	if result.RequestEntry.Header.TargetRoot != nil {
		t.Error("recovery request should have nil TargetRoot (commentary)")
	}
}

func TestUngracefulMigration_EmptyDIDs_Rejected(t *testing.T) {
	_, err := InitiateUngracefulMigration(UngracefulMigrationConfig{})
	if err == nil {
		t.Fatal("expected error for empty DIDs")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Migration record — audit trail commentary
// ═════════════════════════════════════════════════════════════════════

func TestPublishMigrationRecord(t *testing.T) {
	cfg := UngracefulMigrationConfig{
		Destination: "did:web:exchange.test",
		CourtDID:          courtDID,
		FailedExchangeDID: sourceExchange,
		NewExchangeDID:    destExchange,
		RecoveryThreshold: 3,
	}

	entry, err := PublishMigrationRecord(courtDID, cfg)
	if err != nil {
		t.Fatalf("PublishMigrationRecord: %v", err)
	}

	// Commentary entry — zero SMT impact.
	if entry.Header.TargetRoot != nil {
		t.Error("migration record should be commentary (nil TargetRoot)")
	}

	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	if parsed["migration_type"] != "ungraceful" {
		t.Errorf("migration_type = %v, want ungraceful", parsed["migration_type"])
	}
	if parsed["failed_exchange"] != sourceExchange {
		t.Error("failed_exchange mismatch")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Bulk historical — import produces root entities
// ═════════════════════════════════════════════════════════════════════

func TestBulkImport_RootEntities(t *testing.T) {
	// Simulate importing 3 historical cases.
	for i, docket := range []string{"2020-CR-1001", "2021-CV-2002", "2022-CH-3003"} {
		entry, err := builder.BuildRootEntity(builder.RootEntityParams{
			Destination: "did:web:exchange.test",
			SignerDID: courtDID,
			Payload: mustJSON(t, map[string]any{
				"docket_number": docket,
				"import_source": "bulk_historical",
				"original_court": courtDID,
			}),
		})
		if err != nil {
			t.Fatalf("import case %d: %v", i, err)
		}

		if entry.Header.TargetRoot != nil {
			t.Errorf("case %d: imported case should be new root entity", i)
		}

		signed := testutil.SignEntry(t, entry, testutil.GenerateSigningKey(t))
		raw := envelope.Serialize(signed)
		if _, err := envelope.Deserialize(raw); err != nil {
			t.Errorf("case %d: roundtrip failed: %v", i, err)
		}
	}
}

// ═════════════════════════════════════════════════════════════════════
// Succession entry shape
// ═════════════════════════════════════════════════════════════════════

func TestSuccessionEntry_Shape(t *testing.T) {
	entityPos := types.LogPosition{LogDID: officersLog, Sequence: 1}

	entry, err := builder.BuildSuccession(builder.SuccessionParams{
		Destination: "did:web:exchange.test",
		SignerDID:    courtDID,
		TargetRoot:   entityPos,
		NewSignerDID: destExchange,
		Payload: mustJSON(t, map[string]any{
			"migration_type": "graceful",
			"new_exchange":   destExchange,
		}),
	})
	if err != nil {
		t.Fatalf("BuildSuccession: %v", err)
	}

	if !entry.Header.TargetRoot.Equal(entityPos) {
		t.Error("succession TargetRoot mismatch")
	}
	if *entry.Header.AuthorityPath != envelope.AuthoritySameSigner {
		t.Error("succession should be Path A")
	}

	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	if parsed["new_exchange"] != destExchange {
		t.Error("new_exchange mismatch in payload")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Approval cosignature for scope governance
// ═════════════════════════════════════════════════════════════════════

func TestApprovalCosignature_Migration(t *testing.T) {
	proposalPos := types.LogPosition{LogDID: officersLog, Sequence: 500}

	entry, err := lifecycle.BuildApprovalCosignature(
		courtDID,
		"did:web:exchange.test",
		proposalPos,
		1234567890,
	)
	if err != nil {
		t.Fatalf("BuildApprovalCosignature: %v", err)
	}

	if entry.Header.CosignatureOf == nil {
		t.Fatal("CosignatureOf should be set")
	}
	if !entry.Header.CosignatureOf.Equal(proposalPos) {
		t.Error("CosignatureOf should reference proposal")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return b
}
