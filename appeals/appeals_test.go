package appeals

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------
// 1) IssueMandateAffirm — simple config, returns *envelope.Entry
// -------------------------------------------------------------------------

func TestIssueMandateAffirm_Success(t *testing.T) {
	entry, err := IssueMandateAffirm(MandateConfig{
		SignerDID:            "did:web:courts.tn.gov:appellate",
		LowerCourtCasePos:   types.LogPosition{LogDID: "did:web:courts.nashville.gov:cases", Sequence: 100},
		LowerCourtScopePos:  types.LogPosition{LogDID: "did:web:courts.nashville.gov:cases", Sequence: 1},
		AppellateDecisionPos: types.LogPosition{LogDID: "did:web:courts.tn.gov:appellate:cases", Sequence: 500},
		Outcome:              "affirm",
		EventTime:            1700000000,
	})
	if err != nil {
		t.Fatalf("IssueMandateAffirm: %v", err)
	}
	if entry == nil {
		t.Fatal("entry is nil")
	}

	raw := envelope.Serialize(entry)
	restored, err := envelope.Deserialize(raw)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}

	var parsed map[string]any
	json.Unmarshal(restored.DomainPayload, &parsed)
	if len(parsed) == 0 {
		t.Error("mandate payload must not be empty")
	}
}

func TestIssueMandateAffirm_WithRemandInstructions(t *testing.T) {
	entry, err := IssueMandateAffirm(MandateConfig{
		SignerDID:            "did:web:appellate",
		LowerCourtCasePos:   types.LogPosition{LogDID: "did:web:trial:cases", Sequence: 50},
		LowerCourtScopePos:  types.LogPosition{LogDID: "did:web:trial:cases", Sequence: 1},
		AppellateDecisionPos: types.LogPosition{LogDID: "did:web:appellate:cases", Sequence: 200},
		Outcome:              "affirm",
		RemandInstructions:   "none — judgment affirmed in full",
		EventTime:            1700000000,
	})
	if err != nil {
		t.Fatalf("with remand: %v", err)
	}
	if entry == nil {
		t.Fatal("entry nil")
	}
}

// -------------------------------------------------------------------------
// 2) MandateConfig struct fields
// -------------------------------------------------------------------------

func TestMandateConfig_AllFields(t *testing.T) {
	prior := types.LogPosition{LogDID: "did:web:test", Sequence: 99}
	schemaRef := types.LogPosition{LogDID: "did:web:test", Sequence: 3}
	cfg := MandateConfig{
		SignerDID:            "did:web:appellate",
		LowerCourtCasePos:   types.LogPosition{LogDID: "did:web:trial:cases", Sequence: 100},
		LowerCourtScopePos:  types.LogPosition{LogDID: "did:web:trial:cases", Sequence: 1},
		PriorAuthority:      &prior,
		AppellateDecisionPos: types.LogPosition{LogDID: "did:web:appellate:cases", Sequence: 500},
		Outcome:              "reverse",
		RemandInstructions:   "retry with new jury",
		SchemaRef:            &schemaRef,
		EventTime:            1700000000,
	}
	if cfg.SignerDID == "" {
		t.Error("SignerDID required")
	}
	if cfg.Outcome != "reverse" {
		t.Errorf("Outcome = %q", cfg.Outcome)
	}
	if cfg.PriorAuthority == nil {
		t.Error("PriorAuthority should be set")
	}
}

// -------------------------------------------------------------------------
// 3) AppealInitiationConfig struct fields
// -------------------------------------------------------------------------

func TestAppealInitiationConfig_AllFields(t *testing.T) {
	schemaRef := types.LogPosition{LogDID: "did:web:test", Sequence: 5}
	cfg := AppealInitiationConfig{
		SignerDID:         "did:web:exchange:party:jones",
		LowerCourtCasePos: types.LogPosition{LogDID: "did:web:courts.nashville.gov:cases", Sequence: 100},
		LowerCourtDID:     "did:web:courts.nashville.gov",
		AppealNumber:      "2027-AP-001",
		AppealGrounds:     "insufficient_evidence",
		SchemaRef:         &schemaRef,
		EventTime:         1700000000,
	}
	if cfg.SignerDID == "" {
		t.Error("SignerDID required")
	}
	if cfg.LowerCourtDID == "" {
		t.Error("LowerCourtDID required")
	}
	if cfg.AppealNumber != "2027-AP-001" {
		t.Errorf("AppealNumber = %q", cfg.AppealNumber)
	}
	if cfg.AppealGrounds == "" {
		t.Error("AppealGrounds required")
	}
}

// -------------------------------------------------------------------------
// 4) DecisionConfig struct fields
// -------------------------------------------------------------------------

func TestDecisionConfig_AllFields(t *testing.T) {
	cfg := DecisionConfig{
		JudgeDID:           "did:web:exchange:appellate:judge-chen",
		AppealCaseRootPos:  types.LogPosition{LogDID: "did:web:appellate:cases", Sequence: 200},
		CandidatePositions: []types.LogPosition{
			{LogDID: "did:web:appellate:cases", Sequence: 201},
			{LogDID: "did:web:appellate:cases", Sequence: 202},
		},
		Outcome:            "reversed_and_remanded",
		OpinionPlaintext:   []byte("The trial court erred in excluding defense expert testimony"),
		SchemaRef:          types.LogPosition{LogDID: "did:web:appellate:cases", Sequence: 3},
		RemandInstructions: "new trial with corrected evidentiary rulings",
		EventTime:          1700000000,
	}
	if cfg.JudgeDID == "" {
		t.Error("JudgeDID required")
	}
	if cfg.Outcome != "reversed_and_remanded" {
		t.Errorf("Outcome = %q", cfg.Outcome)
	}
	if len(cfg.CandidatePositions) != 2 {
		t.Errorf("CandidatePositions = %d", len(cfg.CandidatePositions))
	}
	if len(cfg.OpinionPlaintext) == 0 {
		t.Error("OpinionPlaintext required")
	}
}

// -------------------------------------------------------------------------
// 5) RecordTransferConfig struct fields
// -------------------------------------------------------------------------

func TestRecordTransferConfig_AllFields(t *testing.T) {
	cfg := RecordTransferConfig{
		SignerDID:          "did:web:courts.nashville.gov",
		LowerCourtCasePos:  types.LogPosition{LogDID: "did:web:trial:cases", Sequence: 100},
		AppellateSchemaRef: types.LogPosition{LogDID: "did:web:appellate:cases", Sequence: 3},
		AppellateOwnerDID:  "did:web:courts.tn.gov:appellate",
		EventTime:          1700000000,
	}
	if cfg.SignerDID == "" {
		t.Error("SignerDID required")
	}
	if cfg.AppellateOwnerDID == "" {
		t.Error("AppellateOwnerDID required")
	}
}

// -------------------------------------------------------------------------
// 6) DecisionResult struct
// -------------------------------------------------------------------------

func TestDecisionResult_Fields(t *testing.T) {
	r := DecisionResult{
		DecisionEntry:   nil,
		OpinionArtifact: nil,
	}
	// Both nil is valid — just verify struct compiles with correct fields.
	if r.DecisionEntry != nil {
		t.Error("nil check")
	}
}

// -------------------------------------------------------------------------
// 7) AppellateDeps struct
// -------------------------------------------------------------------------

func TestAppellateDeps_Fields(t *testing.T) {
	d := AppellateDeps{}
	// All nil is valid — just verify struct compiles with correct fields.
	if d.ContentStore != nil {
		t.Error("nil check")
	}
	if d.KeyStore != nil {
		t.Error("nil check")
	}
	if d.Fetcher != nil {
		t.Error("nil check")
	}
}
