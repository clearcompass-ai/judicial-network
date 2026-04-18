package enforcement

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

const (
	judgeDID   = "did:web:exchange:davidson:role:judge-mcclendon"
	courtDID   = "did:web:courts.nashville.gov"
	casesLogDID = "did:web:courts.nashville.gov:cases"
)

func scopePos() types.LogPosition {
	return types.LogPosition{LogDID: casesLogDID, Sequence: 1}
}

func casePos() types.LogPosition {
	return types.LogPosition{LogDID: casesLogDID, Sequence: 100}
}

// ─── Unit: Sealing order is Path C enforcement ──────────────────────

func TestSealingOrder_PathC_Enforcement(t *testing.T) {
	payload := mustJSON(t, map[string]any{
		"order_type":         "sealing_order",
		"authority":          "TCA 40-32-101",
		"case_ref":           "2027-CR-4471",
		"affected_artifacts": []string{"sha256:abc123", "sha256:def456"},
	})

	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:    judgeDID,
		TargetRoot:   casePos(),
		ScopePointer: scopePos(),
		Payload:      payload,
	})
	if err != nil {
		t.Fatalf("BuildEnforcement (sealing): %v", err)
	}

	// Path C: AuthorityPath must be ScopeAuthority.
	if entry.Header.AuthorityPath == nil || *entry.Header.AuthorityPath != envelope.AuthorityScopeAuthority {
		t.Error("sealing order should use AuthorityScopeAuthority (Path C)")
	}

	// Must have TargetRoot (the case entity being sealed).
	if entry.Header.TargetRoot == nil {
		t.Fatal("sealing order must have TargetRoot")
	}
	if !entry.Header.TargetRoot.Equal(casePos()) {
		t.Errorf("TargetRoot = %v, want %v", *entry.Header.TargetRoot, casePos())
	}

	// Must have ScopePointer (the scope entity granting authority).
	if entry.Header.ScopePointer == nil {
		t.Fatal("sealing order must have ScopePointer")
	}
	if !entry.Header.ScopePointer.Equal(scopePos()) {
		t.Errorf("ScopePointer = %v, want %v", *entry.Header.ScopePointer, scopePos())
	}

	// Signer should be the judge (scope authority member).
	if entry.Header.SignerDID != judgeDID {
		t.Errorf("SignerDID = %q, want %q", entry.Header.SignerDID, judgeDID)
	}

	// Domain Payload should carry order details.
	var parsed map[string]any
	if err := json.Unmarshal(entry.DomainPayload, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["order_type"] != "sealing_order" {
		t.Errorf("order_type = %v, want sealing_order", parsed["order_type"])
	}
}

// ─── Unit: Unsealing order is also Path C ───────────────────────────

func TestUnsealingOrder_PathC_Enforcement(t *testing.T) {
	payload := mustJSON(t, map[string]any{
		"order_type": "unsealing_order",
		"authority":  "Court order — public interest override",
		"case_ref":   "2027-CR-4471",
		"reason":     "Media request pursuant to First Amendment",
	})

	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:    judgeDID,
		TargetRoot:   casePos(),
		ScopePointer: scopePos(),
		Payload:      payload,
	})
	if err != nil {
		t.Fatalf("BuildEnforcement (unsealing): %v", err)
	}

	if *entry.Header.AuthorityPath != envelope.AuthorityScopeAuthority {
		t.Error("unsealing should be Path C")
	}

	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	if parsed["order_type"] != "unsealing_order" {
		t.Errorf("order_type = %v, want unsealing_order", parsed["order_type"])
	}
}

// ─── Unit: Sealing with EvidencePointers ────────────────────────────

func TestSealingOrder_WithEvidencePointers(t *testing.T) {
	evidencePos := types.LogPosition{LogDID: casesLogDID, Sequence: 50}

	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:        judgeDID,
		TargetRoot:       casePos(),
		ScopePointer:     scopePos(),
		EvidencePointers: []types.LogPosition{evidencePos},
		Payload:          mustJSON(t, map[string]any{"order_type": "sealing_order"}),
	})
	if err != nil {
		t.Fatalf("BuildEnforcement with evidence: %v", err)
	}

	if len(entry.Header.EvidencePointers) != 1 {
		t.Fatalf("EvidencePointers count = %d, want 1", len(entry.Header.EvidencePointers))
	}
	if !entry.Header.EvidencePointers[0].Equal(evidencePos) {
		t.Errorf("EvidencePointer = %v, want %v", entry.Header.EvidencePointers[0], evidencePos)
	}
}

// ─── Unit: Sealing with PriorAuthority (OCC) ────────────────────────

func TestSealingOrder_WithPriorAuthority(t *testing.T) {
	priorPos := types.LogPosition{LogDID: casesLogDID, Sequence: 80}

	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:      judgeDID,
		TargetRoot:     casePos(),
		ScopePointer:   scopePos(),
		PriorAuthority: &priorPos,
		Payload:        mustJSON(t, map[string]any{"order_type": "sealing_order"}),
	})
	if err != nil {
		t.Fatalf("BuildEnforcement with prior: %v", err)
	}

	if entry.Header.PriorAuthority == nil {
		t.Fatal("PriorAuthority should be set")
	}
	if !entry.Header.PriorAuthority.Equal(priorPos) {
		t.Errorf("PriorAuthority = %v, want %v", *entry.Header.PriorAuthority, priorPos)
	}
}

// ─── Unit: Enforcement requires TargetRoot ──────────────────────────

func TestEnforcement_MissingTargetRoot_Rejected(t *testing.T) {
	_, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:    judgeDID,
		ScopePointer: scopePos(),
		Payload:      []byte("{}"),
	})
	if err == nil {
		t.Fatal("expected error for missing TargetRoot")
	}
}

// ─── Unit: Enforcement requires ScopePointer ────────────────────────

func TestEnforcement_MissingScopePointer_Rejected(t *testing.T) {
	_, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:  judgeDID,
		TargetRoot: casePos(),
		Payload:    []byte("{}"),
	})
	if err == nil {
		t.Fatal("expected error for missing ScopePointer")
	}
}

// ─── Unit: Expungement entry shape ──────────────────────────────────

func TestExpungementOrder_EntryShape(t *testing.T) {
	payload := mustJSON(t, map[string]any{
		"order_type":         "expungement",
		"authority":          "TCA 40-32-101(g)",
		"case_ref":           "2020-CR-1234",
		"affected_artifacts": []string{"sha256:sealed1", "sha256:sealed2"},
		"key_destruction":    true,
		"cas_deletion":       true,
	})

	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:    judgeDID,
		TargetRoot:   casePos(),
		ScopePointer: scopePos(),
		Payload:      payload,
	})
	if err != nil {
		t.Fatalf("BuildEnforcement (expungement): %v", err)
	}

	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	if parsed["key_destruction"] != true {
		t.Error("expungement must flag key_destruction=true")
	}
	if parsed["cas_deletion"] != true {
		t.Error("expungement must flag cas_deletion=true")
	}
}

// ─── Unit: Juvenile auto-seal activation_delay=0 ────────────────────

func TestJuvenileAutoSeal_ImmediateActivation(t *testing.T) {
	payload := mustJSON(t, map[string]any{
		"order_type":       "sealing_order",
		"authority":        "TCA 37-1-153",
		"activation_delay": 0,
		"auto_seal":        true,
		"case_ref":         "2027-JV-0042",
	})

	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:    judgeDID,
		TargetRoot:   casePos(),
		ScopePointer: scopePos(),
		Payload:      payload,
	})
	if err != nil {
		t.Fatalf("juvenile auto-seal: %v", err)
	}

	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	if parsed["activation_delay"] != float64(0) {
		t.Errorf("activation_delay = %v, want 0 (immediate)", parsed["activation_delay"])
	}
	if parsed["auto_seal"] != true {
		t.Error("auto_seal should be true for juvenile")
	}
}

// ─── Unit: Serialize roundtrip preserves enforcement fields ─────────

func TestEnforcement_SerializeRoundtrip(t *testing.T) {
	original, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:    judgeDID,
		TargetRoot:   casePos(),
		ScopePointer: scopePos(),
		Payload:      mustJSON(t, map[string]any{"order_type": "sealing_order"}),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	raw := envelope.Serialize(original)
	restored, err := envelope.Deserialize(raw)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}

	if *restored.Header.AuthorityPath != *original.Header.AuthorityPath {
		t.Error("AuthorityPath mismatch after roundtrip")
	}
	if !restored.Header.TargetRoot.Equal(*original.Header.TargetRoot) {
		t.Error("TargetRoot mismatch after roundtrip")
	}
	if !restored.Header.ScopePointer.Equal(*original.Header.ScopePointer) {
		t.Error("ScopePointer mismatch after roundtrip")
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
