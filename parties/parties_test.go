/*
FILE PATH: parties/parties_test.go

DESCRIPTION:

	Tests for party-binding writers + roster queries under the
	v1.6 schema (BindingID, PartyClass, PartyName) plus the
	legacy VendorDIDStore tests for vendor-DID rotation (a
	separate concern from party_binding alignment).
*/
package parties

import (
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/judicial-network/internal/testutil"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── 1) CreateBinding ─────────────────────────────────────────────

func TestCreateBinding_Success(t *testing.T) {
	result, err := CreateBinding(BindingConfig{
		Destination: "did:web:exchange.test",
		SignerDID:   "did:web:courts.nashville.gov",
		BindingID:   "d-001",
		PartyClass:  schemas.PartyClassDefendant,
		PartyName:   "John Q. Public",
		CaseRef:     "2027-CR-4471",
		CaseDID:     "did:web:courts.nashville.gov:cases",
		CaseSeq:     100,
		EventTime:   1700000000,
	})
	if err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}
	if result == nil || result.Entry == nil {
		t.Fatal("result/Entry is nil")
	}
	if result.Payload == nil || result.Payload.BindingID != "d-001" {
		t.Errorf("payload drift: %+v", result.Payload)
	}

	signed := testutil.SignEntry(t, result.Entry, testutil.GenerateSigningKey(t))
	raw := envelope.Serialize(signed)
	if _, err := envelope.Deserialize(raw); err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
}

func TestCreateBinding_RejectsEmptyConfig(t *testing.T) {
	_, err := CreateBinding(BindingConfig{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestCreateBinding_RejectsEmptyBindingID(t *testing.T) {
	_, err := CreateBinding(BindingConfig{
		Destination: "did:web:test",
		SignerDID:   "did:web:test",
		PartyClass:  schemas.PartyClassPlaintiff,
		CaseRef:     "2027-CV-1",
	})
	if err == nil {
		t.Fatal("expected error for empty binding_id")
	}
}

func TestCreateBinding_RejectsUnknownPartyClass(t *testing.T) {
	_, err := CreateBinding(BindingConfig{
		Destination: "did:web:test",
		SignerDID:   "did:web:test",
		BindingID:   "x-1",
		PartyClass:  schemas.PartyClass("wizard"),
		CaseRef:     "2027-CV-1",
	})
	if err == nil {
		t.Fatal("expected error for unknown party_class")
	}
}

func TestCreateBinding_AllPartyClasses(t *testing.T) {
	for _, class := range []schemas.PartyClass{
		schemas.PartyClassPlaintiff,
		schemas.PartyClassDefendant,
		schemas.PartyClassRespondent,
		schemas.PartyClassPetitioner,
		schemas.PartyClassState,
	} {
		t.Run(string(class), func(t *testing.T) {
			result, err := CreateBinding(BindingConfig{
				Destination: "did:web:exchange.test",
				SignerDID:   "did:web:test",
				BindingID:   "id-" + string(class),
				PartyClass:  class,
				PartyName:   "Test " + string(class),
				CaseRef:     "2027-CR-001",
				CaseDID:     "did:web:test:cases",
				CaseSeq:     1,
				EventTime:   1700000000,
			})
			if err != nil {
				t.Fatalf("%s: %v", class, err)
			}
			if result.Payload.PartyClass != class {
				t.Errorf("class drift: got %q want %q", result.Payload.PartyClass, class)
			}
		})
	}
}

// TestCreateBinding_SealedHasNoPartyName pins the v1.6 invariant:
// when a binding is sealed, PartyName is empty. The case-local
// BindingID is still the public reference.
func TestCreateBinding_SealedHasNoPartyName(t *testing.T) {
	result, err := CreateBinding(BindingConfig{
		Destination: "did:web:test",
		SignerDID:   "did:web:test",
		BindingID:   "sealed-1",
		PartyClass:  schemas.PartyClassDefendant,
		// PartyName intentionally empty (sealed binding).
		CaseRef:   "2027-CR-1",
		EventTime: 1700000000,
	})
	if err != nil {
		t.Fatalf("CreateBinding (sealed-shaped): %v", err)
	}
	if result.Payload.PartyName != "" {
		t.Errorf("sealed binding should have empty PartyName; got %q",
			result.Payload.PartyName)
	}
	if result.Payload.BindingID != "sealed-1" {
		t.Errorf("BindingID drift: %q", result.Payload.BindingID)
	}
}

// ─── 2) UpdateBinding ─────────────────────────────────────────────

func TestUpdateBindingConfig_RejectsBadStatus(t *testing.T) {
	_, err := UpdateBinding(UpdateBindingConfig{
		SignerDID: "did:web:test",
		NewStatus: "wat",
	})
	if err == nil {
		t.Fatal("expected error for bad status")
	}
}

// ─── 3) VendorDIDStore (vendor-DID rotation; separate concern) ────

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

// ─── 4) LinkPartyCaseConfig fields ─────────────────────────────────

func TestLinkPartyCaseConfig_Fields(t *testing.T) {
	cfg := LinkPartyCaseConfig{
		SignerDID:     "did:web:test",
		BindingID:     "p-001",
		PartiesLogDID: "did:web:test:parties",
		PartyClass:    schemas.PartyClassDefendant,
	}
	if cfg.BindingID != "p-001" {
		t.Errorf("BindingID = %q", cfg.BindingID)
	}
	if cfg.PartyClass != schemas.PartyClassDefendant {
		t.Errorf("PartyClass = %q", cfg.PartyClass)
	}
}
