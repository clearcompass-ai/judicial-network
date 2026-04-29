package schemas

import (
	"encoding/json"
	"testing"
)

// ─── Unit: Registry contains all 12 schemas ─────────────────────────

func TestRegistry_ContainsAll12Schemas(t *testing.T) {
	r := NewRegistry()

	expected := []string{
		SchemaCriminalCaseV1,
		SchemaCivilCaseV1,
		SchemaFamilyCaseV1,
		SchemaJuvenileCaseV1,
		SchemaEvidenceArtifactV1,
		SchemaDisclosureOrderV1,
		SchemaCourtOfficerV1,
		SchemaPartyBindingV1,
		SchemaPartyBindingSealedV1,
		SchemaSealingOrderV1,
		SchemaShardGenesisV1,
		SchemaKeyAttestationV1, // Wave 1 file 9/11
	}

	for _, uri := range expected {
		if !r.Has(uri) {
			t.Errorf("registry missing schema: %s", uri)
		}
	}

	uris := r.URIs()
	if len(uris) != len(expected) {
		t.Errorf("registry has %d schemas, want %d", len(uris), len(expected))
	}
}

// ─── Unit: Lookup returns correct registration ──────────────────────

func TestRegistry_Lookup(t *testing.T) {
	r := NewRegistry()

	reg, err := r.Lookup(SchemaCriminalCaseV1)
	if err != nil {
		t.Fatalf("Lookup(%s): %v", SchemaCriminalCaseV1, err)
	}
	if reg.URI != SchemaCriminalCaseV1 {
		t.Errorf("URI = %q, want %q", reg.URI, SchemaCriminalCaseV1)
	}
	if reg.IdentifierScope != IdentifierScopeRealDID {
		t.Errorf("IdentifierScope = %q, want real_did", reg.IdentifierScope)
	}
}

// ─── Unit: Lookup unknown schema returns error ──────────────────────

func TestRegistry_LookupUnknown(t *testing.T) {
	r := NewRegistry()

	_, err := r.Lookup("nonexistent-schema-v99")
	if err == nil {
		t.Fatal("expected error for unknown schema, got nil")
	}
}

// ─── Unit: DefaultParams produces valid JSON for every schema ───────

func TestRegistry_DefaultParams_ValidJSON(t *testing.T) {
	r := NewRegistry()

	for _, uri := range r.URIs() {
		reg, _ := r.Lookup(uri)
		params := reg.DefaultParams()
		if len(params) == 0 {
			t.Errorf("%s: DefaultParams returned empty", uri)
			continue
		}
		var parsed map[string]any
		if err := json.Unmarshal(params, &parsed); err != nil {
			t.Errorf("%s: DefaultParams is not valid JSON: %v", uri, err)
		}
	}
}

// ─── Unit: Criminal case serialize/deserialize roundtrip ────────────

func TestCriminalCase_SerializeRoundtrip(t *testing.T) {
	original := &CriminalCasePayload{
		DocketNumber: "2027-CR-4471",
		CaseType:     "criminal",
		FiledDate:    "2027-03-15",
		Status:       "active",
		Charges:      []string{"aggravated_assault", "weapons_possession"},
	}

	data, err := SerializeCriminalCasePayload(original)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	restored, err := DeserializeCriminalCasePayload(data)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}

	if restored.DocketNumber != original.DocketNumber {
		t.Errorf("DocketNumber = %q, want %q", restored.DocketNumber, original.DocketNumber)
	}
	if len(restored.Charges) != 2 {
		t.Errorf("Charges count = %d, want 2", len(restored.Charges))
	}
}

// ─── Unit: Evidence artifact schema has sealed grant mode ───────────

func TestEvidenceArtifact_SealedGrantMode(t *testing.T) {
	params := DefaultEvidenceArtifactParams()
	var parsed map[string]any
	if err := json.Unmarshal(params, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if parsed["grant_authorization_mode"] != "sealed" {
		t.Errorf("grant_authorization_mode = %v, want sealed", parsed["grant_authorization_mode"])
	}
	if parsed["artifact_encryption"] != "umbral_pre" {
		t.Errorf("artifact_encryption = %v, want umbral_pre", parsed["artifact_encryption"])
	}
	if parsed["grant_entry_required"] != true {
		t.Error("grant_entry_required should be true for evidence")
	}
}

// ─── Unit: Juvenile case has auto-seal at disposition ────────────────

func TestJuvenileCase_AutoSealAtDisposition(t *testing.T) {
	params := DefaultJuvenileCaseParams()
	var parsed map[string]any
	if err := json.Unmarshal(params, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if parsed["identifier_scope"] != "vendor_specific" {
		t.Errorf("identifier_scope = %v, want vendor_specific", parsed["identifier_scope"])
	}
	if parsed["auto_seal_at_disposition"] != true {
		t.Error("auto_seal_at_disposition should be true for juvenile cases")
	}

	behaviors, ok := parsed["enforcement_behaviors"].(map[string]any)
	if !ok {
		t.Fatal("enforcement_behaviors missing or wrong type")
	}
	sealing, ok := behaviors["sealing_order"].(map[string]any)
	if !ok {
		t.Fatal("sealing_order behavior missing")
	}
	if sealing["activation_delay"] != float64(0) {
		t.Errorf("juvenile sealing activation_delay = %v, want 0 (immediate)", sealing["activation_delay"])
	}
}

// ─── Unit: Family case uses vendor_specific identifiers ─────────────

func TestFamilyCase_VendorSpecific(t *testing.T) {
	r := NewRegistry()
	reg, _ := r.Lookup(SchemaFamilyCaseV1)
	if reg.IdentifierScope != IdentifierScopeVendorSpecific {
		t.Errorf("family case IdentifierScope = %q, want vendor_specific", reg.IdentifierScope)
	}
}

// ─── Unit: Sealing order default params ─────────────────────────────

func TestSealingOrder_DefaultParams(t *testing.T) {
	params := DefaultSealingOrderParams()
	var parsed map[string]any
	if err := json.Unmarshal(params, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Criminal sealing: 72h = 259200 seconds.
	if parsed["activation_delay"] != float64(259200) {
		t.Errorf("activation_delay = %v, want 259200", parsed["activation_delay"])
	}
}

// ─── Unit: Disclosure order extraction helpers ──────────────────────

func TestDisclosureOrder_ExtractRecipients(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"order_type":            "disclosure",
		"scope":                 "per_artifact",
		"authorized_recipients": []string{"did:web:da:davidson", "did:web:defense:smith"},
		"authorized_artifact_cids": []string{"sha256:abc123"},
	})

	recipients, err := ExtractDisclosureRecipients(payload)
	if err != nil {
		t.Fatalf("ExtractDisclosureRecipients: %v", err)
	}
	if len(recipients) != 2 {
		t.Fatalf("recipients count = %d, want 2", len(recipients))
	}

	if !DisclosureOrderAppliesToArtifact(payload, "sha256:abc123") {
		t.Error("should apply to sha256:abc123")
	}
	if DisclosureOrderAppliesToArtifact(payload, "sha256:other") {
		t.Error("should NOT apply to sha256:other")
	}
}

// ─── Unit: Registry via SerializePayload/DeserializePayload ─────────

func TestRegistry_SerializeDeserialize_Via_Registry(t *testing.T) {
	r := NewRegistry()

	original := &CivilCasePayload{
		DocketNumber: "2027-CV-1234",
		CaseType:     "civil",
		Status:       "active",
		Plaintiff:    "Smith Corp",
		ClaimAmount:  "$250,000",
	}

	data, err := r.SerializePayload(SchemaCivilCaseV1, original)
	if err != nil {
		t.Fatalf("SerializePayload: %v", err)
	}

	restored, err := r.DeserializePayload(SchemaCivilCaseV1, data)
	if err != nil {
		t.Fatalf("DeserializePayload: %v", err)
	}

	civil := restored.(*CivilCasePayload)
	if civil.DocketNumber != "2027-CV-1234" {
		t.Errorf("DocketNumber = %q, want 2027-CV-1234", civil.DocketNumber)
	}
	if civil.ClaimAmount != "$250,000" {
		t.Errorf("ClaimAmount = %q, want $250,000", civil.ClaimAmount)
	}
}
