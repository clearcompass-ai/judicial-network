package onboarding

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/topology"
)

func testSpoke() *topology.SpokeConfig {
	return &topology.SpokeConfig{
		CourtDID:    "did:web:courts.test.gov",
		OfficersDID: "did:web:courts.test.gov:officers",
		CasesDID:    "did:web:courts.test.gov:cases",
		PartiesDID:  "did:web:courts.test.gov:parties",
	}
}

func testConfig() CourtProvisionConfig {
	return CourtProvisionConfig{
		Spoke: testSpoke(),
		AuthoritySet: map[string]struct{}{
			"did:web:courts.test.gov": {},
		},
		InitialOfficers: []InitialOfficer{
			{DelegateDID: "did:web:exchange:test:judge-1", Role: "judge", Division: "criminal"},
			{DelegateDID: "did:web:exchange:test:clerk-1", Role: "clerk", Division: "criminal"},
		},
		SchemaURIs: []string{"tn-criminal-case-v1"},
	}
}

// ─── Unit: ProvisionCourt produces 3 non-nil LogProvisions ──────────

func TestProvisionCourt_ThreeLogs(t *testing.T) {
	cfg := testConfig()
	registry := schemas.NewRegistry()

	result, err := ProvisionCourt(cfg, registry)
	if err != nil {
		t.Fatalf("ProvisionCourt: %v", err)
	}

	if result.Officers == nil {
		t.Error("Officers LogProvision is nil")
	}
	if result.Cases == nil {
		t.Error("Cases LogProvision is nil")
	}
	if result.Parties == nil {
		t.Error("Parties LogProvision is nil")
	}
}

// ─── Unit: Each log has a scope entry ───────────────────────────────

func TestProvisionCourt_ScopeEntries(t *testing.T) {
	cfg := testConfig()
	result, err := ProvisionCourt(cfg, schemas.NewRegistry())
	if err != nil {
		t.Fatalf("ProvisionCourt: %v", err)
	}

	if result.Officers.ScopeEntry == nil {
		t.Error("Officers scope entry is nil")
	}
	if result.Cases.ScopeEntry == nil {
		t.Error("Cases scope entry is nil")
	}
	if result.Parties.ScopeEntry == nil {
		t.Error("Parties scope entry is nil")
	}
}

// ─── Unit: Scope payload carries court_did and log_did ──────────────

func TestProvisionCourt_ScopePayload(t *testing.T) {
	cfg := testConfig()
	result, err := ProvisionCourt(cfg, schemas.NewRegistry())
	if err != nil {
		t.Fatalf("ProvisionCourt: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(result.Officers.ScopeEntry.DomainPayload, &payload); err != nil {
		t.Fatalf("unmarshal officers scope: %v", err)
	}
	if payload["court_did"] != "did:web:courts.test.gov" {
		t.Errorf("court_did = %v, want did:web:courts.test.gov", payload["court_did"])
	}
	if payload["log_did"] != "did:web:courts.test.gov:officers" {
		t.Errorf("log_did = %v, want did:web:courts.test.gov:officers", payload["log_did"])
	}
}

// ─── Unit: Officers get delegations, cases get schemas ──────────────

func TestProvisionCourt_PerLogFiltering(t *testing.T) {
	cfg := testConfig()
	result, err := ProvisionCourt(cfg, schemas.NewRegistry())
	if err != nil {
		t.Fatalf("ProvisionCourt: %v", err)
	}

	// Officers log should have delegations (initial officers).
	if len(result.Officers.Delegations) == 0 {
		t.Error("Officers log should have delegations")
	}

	// Cases log should have schema entries.
	if len(result.Cases.SchemaEntries) == 0 {
		t.Error("Cases log should have schema entries")
	}

	// Parties log: delegations mirror officers (all officers, no filter).
	// Schemas are cases-only.
	if len(result.Parties.SchemaEntries) != 0 {
		t.Errorf("Parties log should have 0 schema entries, got %d", len(result.Parties.SchemaEntries))
	}
}

// ─── Unit: AllEntries returns correct order ──────────────────────────

func TestLogProvision_AllEntries_Order(t *testing.T) {
	cfg := testConfig()
	result, err := ProvisionCourt(cfg, schemas.NewRegistry())
	if err != nil {
		t.Fatalf("ProvisionCourt: %v", err)
	}

	entries := result.Officers.AllEntries()
	if len(entries) == 0 {
		t.Fatal("AllEntries returned empty")
	}

	// First entry should be scope entry.
	if entries[0] != result.Officers.ScopeEntry {
		t.Error("first entry should be the scope entry")
	}
}

// ─── Unit: Nil spoke rejected ───────────────────────────────────────

func TestProvisionCourt_NilSpoke_Rejected(t *testing.T) {
	cfg := testConfig()
	cfg.Spoke = nil

	_, err := ProvisionCourt(cfg, schemas.NewRegistry())
	if err == nil {
		t.Fatal("expected error for nil spoke, got nil")
	}
}

// ─── Unit: Empty authority set rejected ─────────────────────────────

func TestProvisionCourt_EmptyAuthoritySet_Rejected(t *testing.T) {
	cfg := testConfig()
	cfg.AuthoritySet = map[string]struct{}{}

	_, err := ProvisionCourt(cfg, schemas.NewRegistry())
	if err == nil {
		t.Fatal("expected error for empty authority set, got nil")
	}
}

// ─── Unit: Court DID must be in authority set ───────────────────────

func TestProvisionCourt_CourtDIDNotInAuthoritySet_Rejected(t *testing.T) {
	cfg := testConfig()
	cfg.AuthoritySet = map[string]struct{}{
		"did:web:other.gov": {},
	}

	_, err := ProvisionCourt(cfg, schemas.NewRegistry())
	if err == nil {
		t.Fatal("expected error when court DID not in authority set")
	}
}

// ─── Unit: Officer targeting specific logs ──────────────────────────

func TestProvisionCourt_OfficerLogTargets(t *testing.T) {
	cfg := testConfig()
	// This officer targets only officers log.
	cfg.InitialOfficers = []InitialOfficer{
		{
			DelegateDID: "did:web:exchange:test:judge-1",
			Role:        "judge",
			Division:    "criminal",
			LogTargets:  []string{"did:web:courts.test.gov:officers"},
		},
	}

	result, err := ProvisionCourt(cfg, schemas.NewRegistry())
	if err != nil {
		t.Fatalf("ProvisionCourt: %v", err)
	}

	// Officers log should have the delegation.
	if len(result.Officers.Delegations) != 1 {
		t.Errorf("Officers delegations = %d, want 1", len(result.Officers.Delegations))
	}

	// Cases and parties should NOT have this delegation.
	if len(result.Cases.Delegations) != 0 {
		t.Errorf("Cases delegations = %d, want 0 (officer targets officers only)", len(result.Cases.Delegations))
	}
	if len(result.Parties.Delegations) != 0 {
		t.Errorf("Parties delegations = %d, want 0", len(result.Parties.Delegations))
	}
}
