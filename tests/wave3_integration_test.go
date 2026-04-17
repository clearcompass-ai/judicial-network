package tests

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	davidson "github.com/clearcompass-ai/judicial-network/deployments/davidson_county"
	"github.com/clearcompass-ai/judicial-network/migration"
	"github.com/clearcompass-ai/judicial-network/onboarding"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/topology"
)

// ═════════════════════════════════════════════════════════════════════
// Integration: Graceful migration — full plan generation
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_GracefulMigration_FullPlan(t *testing.T) {
	officersLog := "did:web:courts.test.gov:officers"
	casesLog := "did:web:courts.test.gov:cases"
	partiesLog := "did:web:courts.test.gov:parties"

	cfg := migration.GracefulMigrationConfig{
		CourtDID:          "did:web:courts.test.gov",
		SourceExchangeDID: "did:web:exchange-a.test.gov",
		DestExchangeDID:   "did:web:exchange-b.test.gov",
		OfficersLogDID:    officersLog,
		CasesLogDID:       casesLog,
		PartiesLogDID:     partiesLog,
		EntityPositions: map[string]types.LogPosition{
			officersLog: {LogDID: officersLog, Sequence: 1},
			casesLog:    {LogDID: casesLog, Sequence: 1},
			partiesLog:  {LogDID: partiesLog, Sequence: 1},
		},
		NewAuthorityKeys: []migration.KeyMaterial{
			{KeyID: "sign-1", PublicKey: []byte("test-key"), Purpose: "signing",
				EntityPos: types.LogPosition{LogDID: officersLog, Sequence: 5}},
		},
	}

	plan, err := migration.PlanGracefulMigration(cfg)
	if err != nil {
		t.Fatalf("PlanGracefulMigration: %v", err)
	}

	// 3 succession entries (one per log).
	if len(plan.SuccessionEntries) != 3 {
		t.Errorf("successions = %d, want 3", len(plan.SuccessionEntries))
	}

	// 1 key rotation entry.
	if len(plan.KeyRotationEntries) != 1 {
		t.Errorf("key rotations = %d, want 1", len(plan.KeyRotationEntries))
	}

	// All entries serialize cleanly.
	for _, entry := range plan.SuccessionEntries {
		raw := envelope.Serialize(entry)
		if _, err := envelope.Deserialize(raw); err != nil {
			t.Errorf("succession roundtrip: %v", err)
		}
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Escrow split → reconstruct roundtrip
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_EscrowSplit_Reconstruct(t *testing.T) {
	secret := []byte("signing-key-material-32-bytes!!")
	if len(secret) < 32 {
		padded := make([]byte, 32)
		copy(padded, secret)
		secret = padded
	}

	// Split 3-of-5.
	shares, err := escrow.SplitGF256(secret[:32], 3, 5)
	if err != nil {
		t.Fatalf("SplitGF256: %v", err)
	}

	if len(shares) != 5 {
		t.Fatalf("shares = %d, want 5", len(shares))
	}

	// Reconstruct with exactly threshold (3) shares.
	recovered, err := escrow.ReconstructGF256(shares[:3])
	if err != nil {
		t.Fatalf("ReconstructGF256: %v", err)
	}

	if !bytes.Equal(recovered, secret[:32]) {
		t.Fatal("recovered secret doesn't match original")
	}

	// Different 3 shares also reconstruct correctly.
	recovered2, err := escrow.ReconstructGF256([]escrow.Share{shares[0], shares[2], shares[4]})
	if err != nil {
		t.Fatalf("ReconstructGF256 (alt): %v", err)
	}

	if !bytes.Equal(recovered2, secret[:32]) {
		t.Fatal("alternate share combination doesn't match original")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Davidson County full bootstrap entry generation
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_Davidson_Bootstrap(t *testing.T) {
	// Step 1: Provision the court.
	cfg := onboarding.CourtProvisionConfig{
		Spoke: &topology.SpokeConfig{
			CourtDID:    "did:web:courts.nashville.gov",
			OfficersDID: "did:web:courts.nashville.gov:officers",
			CasesDID:    "did:web:courts.nashville.gov:cases",
			PartiesDID:  "did:web:courts.nashville.gov:parties",
		},
		AuthoritySet: map[string]struct{}{
			"did:web:courts.nashville.gov": {},
		},
		InitialOfficers: []onboarding.InitialOfficer{
			{DelegateDID: "did:web:ex:judge-mcclendon", Role: "judge", Division: "criminal"},
		},
		SchemaURIs: []string{"tn-criminal-case-v1"},
	}

	provision, err := onboarding.ProvisionCourt(cfg, schemas.NewRegistry())
	if err != nil {
		t.Fatalf("ProvisionCourt: %v", err)
	}

	// Step 2: Create all 6 divisions.
	for _, div := range davidson.DefaultDavidsonDivisions() {
		divCfg := davidson.DivisionConfig{
			SignerDID:    "did:web:courts.nashville.gov",
			DivisionName: div,
			DivisionDID:  "did:web:courts.nashville.gov:" + div,
		}
		divProvision, err := davidson.CreateDivision(divCfg)
		if err != nil {
			t.Fatalf("division %s: %v", div, err)
		}
		if divProvision.DivisionEntity == nil {
			t.Errorf("division %s: entity nil", div)
		}
	}

	// Step 3: Generate daily docket.
	docket, err := davidson.GenerateDailyDocket(davidson.DailyDocketConfig{
		SignerDID: "did:web:ex:judge-mcclendon",
	})
	if err != nil {
		t.Fatalf("docket: %v", err)
	}

	// Step 4: Verify total entry count is reasonable.
	totalEntries := len(provision.Officers.AllEntries()) +
		len(provision.Cases.AllEntries()) +
		len(provision.Parties.AllEntries())

	if totalEntries < 5 {
		t.Errorf("total entries = %d, want >= 5 (3 scopes + officers + schemas)", totalEntries)
	}

	// Step 5: All entries serialize cleanly.
	allEntries := append(provision.Officers.AllEntries(), provision.Cases.AllEntries()...)
	allEntries = append(allEntries, provision.Parties.AllEntries()...)
	allEntries = append(allEntries, docket)

	for i, entry := range allEntries {
		raw := envelope.Serialize(entry)
		if _, err := envelope.Deserialize(raw); err != nil {
			t.Errorf("entry %d roundtrip: %v", i, err)
		}
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Re-encryption round-trip across custody transfer
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_CustodyTransfer_ArtifactReEncryption(t *testing.T) {
	// 10 documents under Exchange A's custody.
	documents := [][]byte{
		[]byte("Motion to Dismiss — 2027-CR-4471"),
		[]byte("Plea Agreement — 2027-CR-4471"),
		[]byte("Sentencing Memorandum — 2027-CR-4471"),
		[]byte("Victim Impact Statement — 2027-CR-4471"),
		[]byte("Pre-Sentence Investigation — 2027-CR-4471"),
		[]byte("Exhibit A — surveillance footage metadata"),
		[]byte("Exhibit B — forensic analysis report"),
		[]byte("Exhibit C — witness deposition transcript"),
		[]byte("Sealing order — 2027-CR-4471"),
		[]byte("Expungement petition — 2027-CR-4471"),
	}

	type archivedDoc struct {
		cid storage.CID
		key artifact.ArtifactKey
	}

	// Encrypt all under Exchange A.
	archived := make([]archivedDoc, len(documents))
	for i, doc := range documents {
		ct, key, err := artifact.EncryptArtifact(doc)
		if err != nil {
			t.Fatalf("encrypt doc %d: %v", i, err)
		}
		archived[i] = archivedDoc{cid: storage.Compute(ct), key: key}
	}

	// Re-encrypt all for Exchange B (custody transfer).
	for i, doc := range documents {
		// Re-encrypt: need original ciphertext. Re-create it from the document.
		origCT, origKey, err := artifact.EncryptArtifact(doc)
		if err != nil {
			t.Fatalf("re-create doc %d: %v", i, err)
		}

		newCT, newKey, err := artifact.ReEncryptArtifact(origCT, origKey)
		if err != nil {
			t.Fatalf("re-encrypt doc %d: %v", i, err)
		}

		// Verify content survives.
		recovered, err := artifact.DecryptArtifact(newCT, newKey)
		if err != nil {
			t.Fatalf("decrypt re-encrypted doc %d: %v", i, err)
		}
		if !bytes.Equal(recovered, doc) {
			t.Errorf("doc %d: content mismatch after re-encryption", i)
		}
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Anchor entry for cross-court verification
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_AnchorPublishing(t *testing.T) {
	// Davidson County anchor to TN state log.
	anchor, err := builder.BuildAnchorEntry(builder.AnchorParams{
		SignerDID:    "did:web:operator.courts.tn.gov",
		SourceLogDID: "did:web:courts.nashville.gov:cases",
		TreeHeadRef:  "abcdef0123456789",
		TreeSize:     42871,
	})
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}

	// Anchor is commentary on the state log.
	if anchor.Header.TargetRoot != nil {
		t.Error("anchor should be commentary")
	}

	raw := envelope.Serialize(anchor)
	restored, err := envelope.Deserialize(raw)
	if err != nil {
		t.Fatalf("anchor roundtrip: %v", err)
	}

	var parsed map[string]any
	json.Unmarshal(restored.DomainPayload, &parsed)
	if parsed["tree_size"] != float64(42871) {
		t.Error("tree_size mismatch")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Bulk historical import — N cases
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_BulkHistoricalImport(t *testing.T) {
	courtDID := "did:web:courts.nashville.gov"
	dockets := []string{
		"2020-CR-1001", "2020-CR-1002", "2020-CR-1003",
		"2021-CV-2001", "2021-CV-2002",
		"2022-CH-3001",
	}

	var entries []*envelope.Entry
	for _, docket := range dockets {
		entry, err := builder.BuildRootEntity(builder.RootEntityParams{
			SignerDID: courtDID,
			Payload: mustJSONW3(t, map[string]any{
				"docket_number": docket,
				"import_source": "bulk_historical",
			}),
		})
		if err != nil {
			t.Fatalf("import %s: %v", docket, err)
		}
		entries = append(entries, entry)
	}

	if len(entries) != 6 {
		t.Fatalf("imported = %d, want 6", len(entries))
	}

	// All are root entities (new leaves).
	for i, e := range entries {
		if e.Header.TargetRoot != nil {
			t.Errorf("entry %d: imported case should be new root entity", i)
		}
		raw := envelope.Serialize(e)
		if _, err := envelope.Deserialize(raw); err != nil {
			t.Errorf("entry %d roundtrip: %v", i, err)
		}
	}
}

func mustJSONW3(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return b
}
