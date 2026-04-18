package cases

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

const (
	courtDID    = "did:web:courts.nashville.gov"
	judgeDID    = "did:web:exchange:davidson:role:judge-mcclendon"
	clerkDID    = "did:web:exchange:davidson:role:clerk-williams"
	casesLogDID = "did:web:courts.nashville.gov:cases"
)

// ═════════════════════════════════════════════════════════════════════
// Filing — new case (BuildRootEntity)
// ═════════════════════════════════════════════════════════════════════

func TestFiling_NewCase_RootEntity(t *testing.T) {
	payload := mustJSON(t, map[string]any{
		"docket_number": "2027-CR-4471",
		"case_type":     "criminal",
		"filed_date":    "2027-03-15",
		"status":        "active",
		"charges":       []string{"aggravated_assault"},
	})

	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:exchange.test",
		SignerDID: courtDID,
		Payload:   payload,
	})
	if err != nil {
		t.Fatalf("BuildRootEntity (filing): %v", err)
	}

	// New case: no TargetRoot (creates new SMT leaf).
	if entry.Header.TargetRoot != nil {
		t.Error("new case filing should have nil TargetRoot")
	}

	// AuthorityPath = SameSigner.
	if entry.Header.AuthorityPath == nil || *entry.Header.AuthorityPath != envelope.AuthoritySameSigner {
		t.Error("filing should use AuthoritySameSigner")
	}

	if entry.Header.SignerDID != courtDID {
		t.Errorf("SignerDID = %q, want %q", entry.Header.SignerDID, courtDID)
	}

	// Domain Payload carries case data.
	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	if parsed["docket_number"] != "2027-CR-4471" {
		t.Errorf("docket_number = %v, want 2027-CR-4471", parsed["docket_number"])
	}
}

// ─── Filing with SchemaRef ──────────────────────────────────────────

func TestFiling_WithSchemaRef(t *testing.T) {
	schemaPos := types.LogPosition{LogDID: casesLogDID, Sequence: 3}

	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:exchange.test",
		SignerDID: courtDID,
		Payload:   mustJSON(t, map[string]any{"docket_number": "2027-CV-1001"}),
		SchemaRef: &schemaPos,
	})
	if err != nil {
		t.Fatalf("BuildRootEntity with SchemaRef: %v", err)
	}

	if entry.Header.SchemaRef == nil {
		t.Fatal("SchemaRef should be set")
	}
	if !entry.Header.SchemaRef.Equal(schemaPos) {
		t.Errorf("SchemaRef = %v, want %v", *entry.Header.SchemaRef, schemaPos)
	}
}

// ═════════════════════════════════════════════════════════════════════
// Amendment — same signer updates case (Path A)
// ═════════════════════════════════════════════════════════════════════

func TestAmendment_PathA_SameSigner(t *testing.T) {
	casePos := types.LogPosition{LogDID: casesLogDID, Sequence: 100}

	entry, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: "did:web:exchange.test",
		SignerDID:  courtDID,
		TargetRoot: casePos,
		Payload:    mustJSON(t, map[string]any{"status": "disposed", "disposition": "guilty_plea"}),
	})
	if err != nil {
		t.Fatalf("BuildAmendment: %v", err)
	}

	// Path A: TargetRoot must be set.
	if entry.Header.TargetRoot == nil {
		t.Fatal("amendment must have TargetRoot")
	}
	if !entry.Header.TargetRoot.Equal(casePos) {
		t.Errorf("TargetRoot = %v, want %v", *entry.Header.TargetRoot, casePos)
	}

	// AuthoritySameSigner for Path A.
	if *entry.Header.AuthorityPath != envelope.AuthoritySameSigner {
		t.Error("amendment should use AuthoritySameSigner (Path A)")
	}

	// Signer matches original case creator.
	if entry.Header.SignerDID != courtDID {
		t.Errorf("amendment signer = %q, want %q", entry.Header.SignerDID, courtDID)
	}
}

// ─── Amendment with EvidencePointers ────────────────────────────────

func TestAmendment_WithEvidence(t *testing.T) {
	casePos := types.LogPosition{LogDID: casesLogDID, Sequence: 100}
	evidencePos := types.LogPosition{LogDID: casesLogDID, Sequence: 150}

	entry, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: "did:web:exchange.test",
		SignerDID:        courtDID,
		TargetRoot:       casePos,
		EvidencePointers: []types.LogPosition{evidencePos},
		Payload:          mustJSON(t, map[string]any{"status": "amended"}),
	})
	if err != nil {
		t.Fatalf("amendment with evidence: %v", err)
	}

	if len(entry.Header.EvidencePointers) != 1 {
		t.Fatalf("EvidencePointers = %d, want 1", len(entry.Header.EvidencePointers))
	}
}

// ═════════════════════════════════════════════════════════════════════
// Judicial action via delegation (Path B)
// ═════════════════════════════════════════════════════════════════════

func TestJudicialAction_PathB_Delegated(t *testing.T) {
	casePos := types.LogPosition{LogDID: casesLogDID, Sequence: 100}
	delegPos := types.LogPosition{LogDID: casesLogDID, Sequence: 10}

	entry, err := builder.BuildPathBEntry(builder.PathBParams{
		Destination: "did:web:exchange.test",
		SignerDID:          judgeDID,
		TargetRoot:         casePos,
		DelegationPointers: []types.LogPosition{delegPos},
		Payload: mustJSON(t, map[string]any{
			"action":   "order",
			"order_type": "motion_ruling",
			"ruling":   "denied",
		}),
	})
	if err != nil {
		t.Fatalf("BuildPathBEntry: %v", err)
	}

	// Path B: AuthorityDelegation.
	if entry.Header.AuthorityPath == nil || *entry.Header.AuthorityPath != envelope.AuthorityDelegation {
		t.Error("judicial action should use AuthorityDelegation (Path B)")
	}

	// DelegationPointers must be set and non-empty.
	if len(entry.Header.DelegationPointers) == 0 {
		t.Fatal("Path B must have DelegationPointers")
	}
	if !entry.Header.DelegationPointers[0].Equal(delegPos) {
		t.Errorf("DelegationPointer = %v, want %v", entry.Header.DelegationPointers[0], delegPos)
	}

	// Signer is the judge (delegate), not the court.
	if entry.Header.SignerDID != judgeDID {
		t.Errorf("signer = %q, want %q (judge via delegation)", entry.Header.SignerDID, judgeDID)
	}

	// TargetRoot points to the case entity.
	if !entry.Header.TargetRoot.Equal(casePos) {
		t.Errorf("TargetRoot = %v, want %v", *entry.Header.TargetRoot, casePos)
	}
}

// ─── Path B requires DelegationPointers ─────────────────────────────

func TestPathB_MissingDelegationPointers_Rejected(t *testing.T) {
	_, err := builder.BuildPathBEntry(builder.PathBParams{
		Destination: "did:web:exchange.test",
		SignerDID:  judgeDID,
		TargetRoot: types.LogPosition{LogDID: casesLogDID, Sequence: 100},
		Payload:    []byte("{}"),
		// DelegationPointers intentionally missing.
	})
	if err == nil {
		t.Fatal("expected error for missing DelegationPointers in Path B")
	}
}

// ─── Path B with multi-hop delegation chain ─────────────────────────

func TestPathB_MultiHopChain(t *testing.T) {
	casePos := types.LogPosition{LogDID: casesLogDID, Sequence: 100}
	deleg1 := types.LogPosition{LogDID: casesLogDID, Sequence: 10}
	deleg2 := types.LogPosition{LogDID: casesLogDID, Sequence: 15}

	entry, err := builder.BuildPathBEntry(builder.PathBParams{
		Destination: "did:web:exchange.test",
		SignerDID:          clerkDID,
		TargetRoot:         casePos,
		DelegationPointers: []types.LogPosition{deleg1, deleg2},
		Payload:            mustJSON(t, map[string]any{"action": "accept_filing"}),
	})
	if err != nil {
		t.Fatalf("multi-hop Path B: %v", err)
	}

	if len(entry.Header.DelegationPointers) != 2 {
		t.Errorf("DelegationPointers = %d, want 2", len(entry.Header.DelegationPointers))
	}
}

// ═════════════════════════════════════════════════════════════════════
// Commentary — case notes, recusal (zero SMT impact)
// ═════════════════════════════════════════════════════════════════════

func TestCommentary_CaseNote(t *testing.T) {
	entry, err := builder.BuildCommentary(builder.CommentaryParams{
		Destination: "did:web:exchange.test",
		SignerDID: judgeDID,
		Payload: mustJSON(t, map[string]any{
			"type":          "case_note",
			"docket_number": "2027-CR-4471",
			"note":          "Continued to 2027-04-01 per defense request",
		}),
	})
	if err != nil {
		t.Fatalf("commentary: %v", err)
	}

	if entry.Header.TargetRoot != nil {
		t.Error("commentary must have nil TargetRoot (zero SMT impact)")
	}
	if entry.Header.AuthorityPath != nil {
		t.Error("commentary must have nil AuthorityPath")
	}
	if entry.Header.DelegateDID != nil {
		t.Error("commentary must have nil DelegateDID")
	}
}

// ─── Recusal commentary ─────────────────────────────────────────────

func TestCommentary_Recusal(t *testing.T) {
	entry, err := builder.BuildCommentary(builder.CommentaryParams{
		Destination: "did:web:exchange.test",
		SignerDID: judgeDID,
		Payload: mustJSON(t, map[string]any{
			"type":          "recusal",
			"docket_number": "2027-CR-8891",
			"reason":        "conflict of interest",
		}),
	})
	if err != nil {
		t.Fatalf("recusal: %v", err)
	}

	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	if parsed["type"] != "recusal" {
		t.Errorf("type = %v, want recusal", parsed["type"])
	}

	// Recusal is commentary — delegation stays live.
	if entry.Header.TargetRoot != nil {
		t.Error("recusal should not target any entity")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Succession — exchange migration (Path A)
// ═════════════════════════════════════════════════════════════════════

func TestSuccession_ExchangeMigration(t *testing.T) {
	entityPos := types.LogPosition{LogDID: casesLogDID, Sequence: 1}

	entry, err := builder.BuildSuccession(builder.SuccessionParams{
		Destination: "did:web:exchange.test",
		SignerDID:    courtDID,
		TargetRoot:   entityPos,
		NewSignerDID: "did:web:exchange-b.courts.tn.gov",
		Payload: mustJSON(t, map[string]any{
			"migration_type": "graceful",
			"new_exchange":   "did:web:exchange-b.courts.tn.gov",
		}),
	})
	if err != nil {
		t.Fatalf("BuildSuccession: %v", err)
	}

	if *entry.Header.AuthorityPath != envelope.AuthoritySameSigner {
		t.Error("succession should use Path A (SameSigner)")
	}
	if !entry.Header.TargetRoot.Equal(entityPos) {
		t.Error("succession must target the entity being replaced")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Cosignature — endorsement (zero SMT impact)
// ═════════════════════════════════════════════════════════════════════

func TestCosignature_Endorsement(t *testing.T) {
	endorsedPos := types.LogPosition{LogDID: casesLogDID, Sequence: 200}

	entry, err := builder.BuildCosignature(builder.CosignatureParams{
		Destination: "did:web:exchange.test",
		SignerDID:     judgeDID,
		CosignatureOf: endorsedPos,
		Payload:       mustJSON(t, map[string]any{"endorsement": "approved"}),
	})
	if err != nil {
		t.Fatalf("BuildCosignature: %v", err)
	}

	if entry.Header.CosignatureOf == nil {
		t.Fatal("CosignatureOf must be set")
	}
	if !entry.Header.CosignatureOf.Equal(endorsedPos) {
		t.Errorf("CosignatureOf = %v, want %v", *entry.Header.CosignatureOf, endorsedPos)
	}

	// Cosignature is commentary — zero SMT impact.
	if entry.Header.TargetRoot != nil {
		t.Error("cosignature should have nil TargetRoot")
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
