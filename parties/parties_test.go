package parties

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// -------------------------------------------------------------------------
// 1) CreateBinding
// -------------------------------------------------------------------------

func TestCreateBinding_Success(t *testing.T) {
	result, err := CreateBinding(BindingConfig{
		SignerDID: "did:web:courts.nashville.gov",
		PartyDID:  "did:web:exchange:party:jones",
		CaseRef:   "2027-CR-4471",
		CaseDID:   "did:web:courts.nashville.gov:cases",
		CaseSeq:   100,
		Role:      "defendant",
		EventTime: 1700000000,
	})
	if err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.Entry == nil {
		t.Fatal("result.Entry is nil")
	}

	raw := envelope.Serialize(result.Entry)
	if _, err := envelope.Deserialize(raw); err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
}

func TestCreateBinding_EmptyConfig(t *testing.T) {
	_, err := CreateBinding(BindingConfig{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestCreateBinding_AllRoles(t *testing.T) {
	for _, role := range []string{"plaintiff", "defendant", "witness", "victim", "guardian_ad_litem"} {
		t.Run(role, func(t *testing.T) {
			result, err := CreateBinding(BindingConfig{
				SignerDID: "did:web:test",
				PartyDID:  "did:web:party:" + role,
				CaseRef:   "2027-CR-001",
				CaseDID:   "did:web:test:cases",
				CaseSeq:   1,
				Role:      role,
				EventTime: 1700000000,
			})
			if err != nil {
				t.Fatalf("%s: %v", role, err)
			}
			if result.Entry == nil {
				t.Errorf("%s: entry nil", role)
			}
		})
	}
}

// -------------------------------------------------------------------------
// 2) VendorDIDStore
// -------------------------------------------------------------------------

func TestNewVendorDIDStore(t *testing.T) {
	store := NewVendorDIDStore()
	if store == nil {
		t.Fatal("store must not be nil")
	}
	if store.MappingCount() != 0 {
		t.Errorf("new store should have 0 mappings, got %d", store.MappingCount())
	}
}

func TestGenerateVendorDID(t *testing.T) {
	store := NewVendorDIDStore()
	vendorDID, err := GenerateVendorDID("exchange-a.courts.tn.gov", "did:web:real:judge", store)
	if err != nil {
		t.Fatalf("GenerateVendorDID: %v", err)
	}
	if vendorDID == "" {
		t.Error("vendor DID must not be empty")
	}
	if store.MappingCount() != 1 {
		t.Errorf("store should have 1 mapping, got %d", store.MappingCount())
	}
}

func TestResolveVendorDID(t *testing.T) {
	store := NewVendorDIDStore()
	vendorDID, _ := GenerateVendorDID("exchange-a.test", "did:web:real:judge", store)

	resolved, err := ResolveVendorDID(vendorDID, store)
	if err != nil {
		t.Fatalf("ResolveVendorDID: %v", err)
	}
	if resolved != "did:web:real:judge" {
		t.Errorf("resolved = %q, want did:web:real:judge", resolved)
	}
}

func TestResolveVendorDID_NotFound(t *testing.T) {
	store := NewVendorDIDStore()
	_, err := ResolveVendorDID("did:web:nonexistent", store)
	if err == nil {
		t.Fatal("expected error for unknown vendor DID")
	}
}

func TestLookupVendorDID(t *testing.T) {
	store := NewVendorDIDStore()
	vendorDID, _ := GenerateVendorDID("exchange-a.test", "did:web:real:clerk", store)

	found, err := LookupVendorDID("did:web:real:clerk", store)
	if err != nil {
		t.Fatalf("LookupVendorDID: %v", err)
	}
	if found != vendorDID {
		t.Errorf("lookup = %q, want %q", found, vendorDID)
	}
}

func TestLookupVendorDID_NotFound(t *testing.T) {
	store := NewVendorDIDStore()
	_, err := LookupVendorDID("did:web:nonexistent", store)
	if err == nil {
		t.Fatal("expected error for unknown real DID")
	}
}

func TestVendorDIDStore_MultipleMappings(t *testing.T) {
	store := NewVendorDIDStore()
	GenerateVendorDID("ex.test", "did:web:judge-a", store)
	GenerateVendorDID("ex.test", "did:web:clerk-b", store)
	GenerateVendorDID("ex.test", "did:web:deputy-c", store)

	if store.MappingCount() != 3 {
		t.Errorf("count = %d, want 3", store.MappingCount())
	}
}

func TestVendorDID_FullRoundtrip(t *testing.T) {
	store := NewVendorDIDStore()
	realDID := "did:web:courts.nashville.gov:role:judge-mcclendon-2026"

	vendorDID, err := GenerateVendorDID("exchange-a.courts.tn.gov", realDID, store)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	resolved, err := ResolveVendorDID(vendorDID, store)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved != realDID {
		t.Errorf("resolved = %q, want %q", resolved, realDID)
	}

	found, err := LookupVendorDID(realDID, store)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if found != vendorDID {
		t.Errorf("lookup = %q, want %q", found, vendorDID)
	}
}

// -------------------------------------------------------------------------
// 3) UpdateBindingConfig fields
// -------------------------------------------------------------------------

func TestUpdateBindingConfig_Fields(t *testing.T) {
	cfg := UpdateBindingConfig{
		SignerDID: "did:web:test",
		NewRole:   "witness",
		NewStatus: "active",
	}
	if cfg.SignerDID == "" {
		t.Error("SignerDID required")
	}
	if cfg.NewRole != "witness" {
		t.Errorf("NewRole = %q", cfg.NewRole)
	}
}

// -------------------------------------------------------------------------
// 4) LinkPartyCaseConfig fields
// -------------------------------------------------------------------------

func TestLinkPartyCaseConfig_Fields(t *testing.T) {
	cfg := LinkPartyCaseConfig{
		SignerDID:     "did:web:test",
		PartyDID:      "did:web:party",
		PartiesLogDID: "did:web:test:parties",
		Role:          "defendant",
	}
	if cfg.SignerDID == "" {
		t.Error("SignerDID required")
	}
	if cfg.Role != "defendant" {
		t.Errorf("Role = %q", cfg.Role)
	}
}
