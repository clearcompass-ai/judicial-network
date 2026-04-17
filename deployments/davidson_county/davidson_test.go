package davidson_county

import (
	"encoding/json"
	"testing"
	"time"
)

// ═════════════════════════════════════════════════════════════════════
// Division creation
// ═════════════════════════════════════════════════════════════════════

func TestCreateDivision_Criminal(t *testing.T) {
	cfg := DivisionConfig{
		SignerDID:         "did:web:courts.nashville.gov",
		DivisionName:      "criminal",
		DivisionDID:       "did:web:courts.nashville.gov:criminal",
		PresidingJudgeDID: "did:web:ex:judge-mcclendon",
		ClerkDID:          "did:web:ex:clerk-williams",
		ScopeLimit:        []string{"case_filing", "order", "judgment", "sealing_order"},
	}

	provision, err := CreateDivision(cfg)
	if err != nil {
		t.Fatalf("CreateDivision: %v", err)
	}

	if provision.DivisionEntity == nil {
		t.Fatal("DivisionEntity is nil")
	}
	if provision.JudgeDelegation == nil {
		t.Fatal("JudgeDelegation is nil")
	}
	if provision.ClerkDelegation == nil {
		t.Fatal("ClerkDelegation is nil")
	}

	// Division entity signer = court.
	if provision.DivisionEntity.Header.SignerDID != cfg.SignerDID {
		t.Errorf("division signer = %q, want %q", provision.DivisionEntity.Header.SignerDID, cfg.SignerDID)
	}

	// Judge delegation: court → judge.
	if *provision.JudgeDelegation.Header.DelegateDID != cfg.PresidingJudgeDID {
		t.Error("judge delegation delegate mismatch")
	}

	// Clerk delegation: judge → clerk (depth 2).
	if provision.ClerkDelegation.Header.SignerDID != cfg.PresidingJudgeDID {
		t.Error("clerk delegation should be signed by judge")
	}
	if *provision.ClerkDelegation.Header.DelegateDID != cfg.ClerkDID {
		t.Error("clerk delegation delegate mismatch")
	}
}

func TestCreateDivision_JudgeOnly(t *testing.T) {
	cfg := DivisionConfig{
		SignerDID:         "did:web:courts.nashville.gov",
		DivisionName:      "civil",
		DivisionDID:       "did:web:courts.nashville.gov:civil",
		PresidingJudgeDID: "did:web:ex:judge-smith",
	}

	provision, err := CreateDivision(cfg)
	if err != nil {
		t.Fatalf("CreateDivision (judge only): %v", err)
	}

	if provision.JudgeDelegation == nil {
		t.Error("JudgeDelegation should exist")
	}
	if provision.ClerkDelegation != nil {
		t.Error("ClerkDelegation should be nil when no clerk DID provided")
	}
}

func TestCreateDivision_EmptyDIDs_Rejected(t *testing.T) {
	_, err := CreateDivision(DivisionConfig{})
	if err == nil {
		t.Fatal("expected error for empty DIDs")
	}
}

// ═════════════════════════════════════════════════════════════════════
// All 6 divisions
// ═════════════════════════════════════════════════════════════════════

func TestCreateDivision_AllSixDivisions(t *testing.T) {
	divisions := DefaultDavidsonDivisions()
	if len(divisions) != 6 {
		t.Fatalf("DefaultDavidsonDivisions = %d, want 6", len(divisions))
	}

	for _, div := range divisions {
		cfg := DivisionConfig{
			SignerDID:    "did:web:courts.nashville.gov",
			DivisionName: div,
			DivisionDID:  "did:web:courts.nashville.gov:" + div,
		}
		provision, err := CreateDivision(cfg)
		if err != nil {
			t.Errorf("division %s: %v", div, err)
			continue
		}
		if provision.DivisionEntity == nil {
			t.Errorf("division %s: entity nil", div)
		}
	}
}

// ═════════════════════════════════════════════════════════════════════
// Daily docket
// ═════════════════════════════════════════════════════════════════════

func TestGenerateDailyDocket(t *testing.T) {
	cfg := DailyDocketConfig{
		SignerDID: "did:web:ex:judge-mcclendon",
		Date:      time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC),
		Assignments: []DivisionAssignment{
			{
				Division: "criminal",
				Assignments: []JudgeAssignment{
					{JudgeDID: "did:web:ex:judge-mcclendon", JudgeName: "McClendon", Courtrooms: []string{"5A"}},
				},
			},
		},
	}

	entry, err := GenerateDailyDocket(cfg)
	if err != nil {
		t.Fatalf("GenerateDailyDocket: %v", err)
	}

	// Daily docket is commentary — zero SMT impact.
	if entry.Header.TargetRoot != nil {
		t.Error("daily docket should have nil TargetRoot")
	}
	if entry.Header.AuthorityPath != nil {
		t.Error("daily docket should have nil AuthorityPath")
	}

	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	if parsed["assignment_date"] != "2027-03-15" {
		t.Errorf("date = %v, want 2027-03-15", parsed["assignment_date"])
	}
}

func TestGenerateDailyDocket_EmptySigner_Rejected(t *testing.T) {
	_, err := GenerateDailyDocket(DailyDocketConfig{})
	if err == nil {
		t.Fatal("expected error for empty signer")
	}
}

func TestGenerateDailyDocket_DefaultDate(t *testing.T) {
	cfg := DailyDocketConfig{
		SignerDID: "did:web:ex:judge",
	}

	entry, err := GenerateDailyDocket(cfg)
	if err != nil {
		t.Fatalf("GenerateDailyDocket default date: %v", err)
	}

	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	// Should be today's date.
	if parsed["assignment_date"] == nil || parsed["assignment_date"] == "" {
		t.Error("assignment_date should be populated with today's date")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Recusal
// ═════════════════════════════════════════════════════════════════════

func TestPublishRecusal(t *testing.T) {
	entry, err := PublishRecusal(
		"did:web:ex:judge-mcclendon",
		"2027-CR-8891",
		"conflict of interest — concurrent ethics board service",
	)
	if err != nil {
		t.Fatalf("PublishRecusal: %v", err)
	}

	// Recusal is commentary.
	if entry.Header.TargetRoot != nil {
		t.Error("recusal should be commentary (nil TargetRoot)")
	}

	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	if parsed["type"] != "recusal" {
		t.Errorf("type = %v, want recusal", parsed["type"])
	}
	if parsed["docket_number"] != "2027-CR-8891" {
		t.Error("docket_number mismatch")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Revocation
// ═════════════════════════════════════════════════════════════════════

func TestRevokeOfficer(t *testing.T) {
	entry, err := RevokeOfficer(
		"did:web:courts.nashville.gov",
		42,
		"officer_departed",
	)
	if err != nil {
		t.Fatalf("RevokeOfficer: %v", err)
	}

	if entry.Header.TargetRoot == nil {
		t.Fatal("revocation must have TargetRoot")
	}
	if entry.Header.TargetRoot.Sequence != 42 {
		t.Errorf("TargetRoot.Sequence = %d, want 42", entry.Header.TargetRoot.Sequence)
	}
}
