package tests

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/onboarding"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/topology"
)

// ═════════════════════════════════════════════════════════════════════
// Integration: Full court provisioning → entry verification
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_ProvisionCourt_FullLifecycle(t *testing.T) {
	cfg := onboarding.CourtProvisionConfig{
		Spoke: &topology.SpokeConfig{
			CourtDID:    "did:web:courts.integration-test.gov",
			OfficersDID: "did:web:courts.integration-test.gov:officers",
			CasesDID:    "did:web:courts.integration-test.gov:cases",
			PartiesDID:  "did:web:courts.integration-test.gov:parties",
		},
		AuthoritySet: map[string]struct{}{
			"did:web:courts.integration-test.gov": {},
		},
		InitialOfficers: []onboarding.InitialOfficer{
			{DelegateDID: "did:web:ex:judge-1", Role: "judge", Division: "criminal"},
			{DelegateDID: "did:web:ex:clerk-1", Role: "clerk", Division: "criminal"},
			{DelegateDID: "did:web:ex:judge-2", Role: "judge", Division: "civil"},
		},
		SchemaURIs: []string{"tn-criminal-case-v1", "tn-civil-case-v1"},
	}

	result, err := onboarding.ProvisionCourt(cfg, schemas.NewRegistry())
	if err != nil {
		t.Fatalf("ProvisionCourt: %v", err)
	}

	// Verify all three logs provisioned.
	for name, lp := range map[string]interface{}{
		"officers": result.Officers,
		"cases":    result.Cases,
		"parties":  result.Parties,
	} {
		if lp == nil {
			t.Fatalf("%s LogProvision is nil", name)
		}
	}

	// Officers log: scope + 3 delegations.
	allOfficers := result.Officers.AllEntries()
	if len(allOfficers) < 4 {
		t.Errorf("Officers entries = %d, want >= 4 (scope + 3 delegations)", len(allOfficers))
	}

	// Cases log: scope + 2 schemas + delegations.
	if len(result.Cases.SchemaEntries) != 2 {
		t.Errorf("Cases schema entries = %d, want 2", len(result.Cases.SchemaEntries))
	}

	// Every entry should serialize and deserialize cleanly.
	for _, entry := range allOfficers {
		raw := envelope.Serialize(entry)
		_, err := envelope.Deserialize(raw)
		if err != nil {
			t.Errorf("entry serialize/deserialize failed: %v", err)
		}
	}

	// Scope entry signer should be the court DID.
	if result.Officers.ScopeEntry.Header.SignerDID != cfg.Spoke.CourtDID {
		t.Errorf("scope signer = %q, want %q",
			result.Officers.ScopeEntry.Header.SignerDID, cfg.Spoke.CourtDID)
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Full 3-depth delegation chain
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_DelegationChain_3Depths(t *testing.T) {
	courtDID := "did:web:courts.chain-test.gov"
	judgeDID := "did:web:ex:judge-chain"
	clerkDID := "did:web:ex:clerk-chain"
	deputyDID := "did:web:ex:deputy-chain"

	// Depth 1: court → judge.
	d1, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   courtDID,
		DelegateDID: judgeDID,
		Payload:     mustJSONInteg(t, map[string]any{"role": "judge", "division": "criminal"}),
	})
	if err != nil {
		t.Fatalf("depth 1: %v", err)
	}

	// Depth 2: judge → clerk.
	d2, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   judgeDID,
		DelegateDID: clerkDID,
		Payload:     mustJSONInteg(t, map[string]any{"role": "clerk"}),
	})
	if err != nil {
		t.Fatalf("depth 2: %v", err)
	}

	// Depth 3: clerk → deputy.
	d3, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   clerkDID,
		DelegateDID: deputyDID,
		Payload:     mustJSONInteg(t, map[string]any{"role": "deputy"}),
	})
	if err != nil {
		t.Fatalf("depth 3: %v", err)
	}

	// Verify chain connectivity: d1.Signer → d1.Delegate == d2.Signer → d2.Delegate == d3.Signer.
	if *d1.Header.DelegateDID != d2.Header.SignerDID {
		t.Error("chain broken between depth 1 and 2")
	}
	if *d2.Header.DelegateDID != d3.Header.SignerDID {
		t.Error("chain broken between depth 2 and 3")
	}

	// Every entry serializes cleanly.
	for i, entry := range []*envelope.Entry{d1, d2, d3} {
		raw := envelope.Serialize(entry)
		restored, err := envelope.Deserialize(raw)
		if err != nil {
			t.Fatalf("depth %d roundtrip: %v", i+1, err)
		}
		if restored.Header.SignerDID != entry.Header.SignerDID {
			t.Errorf("depth %d signer mismatch after roundtrip", i+1)
		}
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Revocation entry targets a delegation
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_Revocation_TargetsDelegation(t *testing.T) {
	courtDID := "did:web:courts.revoke-test.gov"
	judgeDID := "did:web:ex:judge-revoke"

	// Create delegation.
	delegation, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   courtDID,
		DelegateDID: judgeDID,
		Payload:     mustJSONInteg(t, map[string]any{"role": "judge"}),
	})
	if err != nil {
		t.Fatalf("delegation: %v", err)
	}

	// Simulate: delegation lands at position 5 on officers log.
	delegPos := types.LogPosition{
		LogDID:   "did:web:courts.revoke-test.gov:officers",
		Sequence: 5,
	}

	// Revoke it.
	revocation, err := builder.BuildRevocation(builder.RevocationParams{
		Destination: "did:web:exchange.test",
		SignerDID:  courtDID,
		TargetRoot: delegPos,
		Payload:    mustJSONInteg(t, map[string]any{"reason": "officer_departed"}),
	})
	if err != nil {
		t.Fatalf("revocation: %v", err)
	}

	// Verify revocation targets the delegation.
	if !revocation.Header.TargetRoot.Equal(delegPos) {
		t.Error("revocation doesn't target the delegation position")
	}

	// Both must have the same signer (same-signer revocation = Path A).
	if revocation.Header.SignerDID != delegation.Header.SignerDID {
		t.Error("revocation signer should match delegation signer (Path A)")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Artifact encrypt → CID → decrypt → verify
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_ArtifactLifecycle(t *testing.T) {
	// Simulate a court filing document.
	document := []byte(`{"docket_number":"2027-CR-4471","type":"motion_to_dismiss",` +
		`"filed_by":"did:web:defense:smith","content":"The defendant moves to dismiss..."}`)

	// Step 1: Encrypt.
	ciphertext, key, err := artifact.EncryptArtifact(document)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Step 2: Compute CID (what the operator/artifact store indexes by).
	cid := storage.Compute(ciphertext)
	if cid.IsZero() {
		t.Fatal("CID is zero")
	}

	// Step 3: CID verifies the ciphertext.
	if !cid.Verify(ciphertext) {
		t.Fatal("CID doesn't verify its own ciphertext")
	}

	// Step 4: Decrypt.
	recovered, err := artifact.DecryptArtifact(ciphertext, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	// Step 5: Content matches original.
	if !bytes.Equal(recovered, document) {
		t.Fatal("decrypted content doesn't match original document")
	}

	// Step 6: Tampered ciphertext fails CID verification.
	tampered := append([]byte{}, ciphertext...)
	tampered[len(tampered)/2] ^= 0xFF
	if cid.Verify(tampered) {
		t.Fatal("CID verified tampered ciphertext — integrity failure")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Schema entry construction through registry
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_SchemaEntry_Construction(t *testing.T) {
	registry := schemas.NewRegistry()

	// Get default params for criminal case schema.
	reg, err := registry.Lookup(schemas.SchemaCriminalCaseV1)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	params := reg.DefaultParams()
	if len(params) == 0 {
		t.Fatal("default params empty")
	}

	// Build a schema entry using the SDK.
	entry, err := builder.BuildSchemaEntry(builder.SchemaEntryParams{
		Destination: "did:web:exchange.test",
		SignerDID: "did:web:courts.schema-test.gov",
		Payload:   params,
	})
	if err != nil {
		t.Fatalf("BuildSchemaEntry: %v", err)
	}

	// Verify it's a root entity (creates a new leaf).
	if entry.Header.TargetRoot != nil {
		t.Error("schema entry should have nil TargetRoot (new leaf)")
	}

	// Payload should parse as valid JSON with expected fields.
	var parsed map[string]any
	if err := json.Unmarshal(entry.DomainPayload, &parsed); err != nil {
		t.Fatalf("schema payload not valid JSON: %v", err)
	}
	if parsed["artifact_encryption"] != "aes_gcm" {
		t.Errorf("artifact_encryption = %v, want aes_gcm", parsed["artifact_encryption"])
	}
}

func mustJSONInteg(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return b
}
