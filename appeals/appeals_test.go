package appeals

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// -------------------------------------------------------------------------
// 1) IssueMandateAffirm: simple config, returns *envelope.Entry
// -------------------------------------------------------------------------

func TestIssueMandateAffirm(t *testing.T) {
	entry, err := IssueMandateAffirm(MandateConfig{
		AppellateCourtDID: "did:web:courts.tn.gov:appellate",
		TrialCourtDID:     "did:web:courts.nashville.gov",
		AppealDocketRef:   "2027-AP-001",
		TrialDocketRef:    "2027-CR-4471",
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
	if parsed["appeal_docket_ref"] != "2027-AP-001" {
		t.Errorf("appeal_docket_ref = %v", parsed["appeal_docket_ref"])
	}
}

// -------------------------------------------------------------------------
// 2) AppealInitiationConfig: struct fields
// -------------------------------------------------------------------------

func TestAppealInitiationConfig_Fields(t *testing.T) {
	cfg := AppealInitiationConfig{
		AppellantDID:   "did:web:ex:party:jones",
		TrialCourtDID:  "did:web:courts.nashville.gov",
		TrialCaseRef:   "2027-CR-4471",
	}
	if cfg.AppellantDID == "" {
		t.Error("AppellantDID required")
	}
	if cfg.TrialCaseRef == "" {
		t.Error("TrialCaseRef required")
	}
}

// -------------------------------------------------------------------------
// 3) DecisionConfig: struct fields
// -------------------------------------------------------------------------

func TestDecisionConfig_Fields(t *testing.T) {
	cfg := DecisionConfig{
		AppealDocketRef: "2027-AP-001",
		Decision:        "reversed_and_remanded",
	}
	if cfg.Decision == "" {
		t.Error("Decision required")
	}
}

// -------------------------------------------------------------------------
// 4) MandateConfig: struct fields
// -------------------------------------------------------------------------

func TestMandateConfig_Fields(t *testing.T) {
	cfg := MandateConfig{
		AppellateCourtDID: "did:web:appellate",
		TrialCourtDID:     "did:web:trial",
		AppealDocketRef:   "2027-AP-001",
		TrialDocketRef:    "2027-CR-4471",
	}
	if cfg.AppellateCourtDID == "" || cfg.TrialCourtDID == "" {
		t.Error("court DIDs required")
	}
}

// -------------------------------------------------------------------------
// 5) RecordTransferConfig: struct fields
// -------------------------------------------------------------------------

func TestRecordTransferConfig_Fields(t *testing.T) {
	cfg := RecordTransferConfig{
		TrialCourtDID:     "did:web:trial",
		AppellateCourtDID: "did:web:appellate",
		TrialDocketRef:    "2027-CR-4471",
	}
	if cfg.TrialDocketRef == "" {
		t.Error("TrialDocketRef required")
	}
}
