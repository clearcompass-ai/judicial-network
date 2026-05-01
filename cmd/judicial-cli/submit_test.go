/*
FILE PATH: cmd/judicial-cli/submit_test.go

DESCRIPTION:
    Pins the buildAndSign pipeline: a spec on disk → canonical wire
    bytes that round-trip through envelope.Deserialize and verify
    against the keys we wrote. The pipeline is the load-bearing path
    for every walkthrough scenario; drift here would silently break
    them.
*/
package main

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sdkenv "github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdksigs "github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// helper: keygen into a tempdir and return the file path.
func issueKey(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name+".key.json")
	if err := runKeygen([]string{"--out", p}); err != nil {
		t.Fatalf("keygen %s: %v", name, err)
	}
	return p
}

// helper: write a spec to disk, return path.
func writeSpec(t *testing.T, dir, name string, s SubmitSpec) string {
	t.Helper()
	p := filepath.Join(dir, name+".spec.json")
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	return p
}

func TestBuildAndSign_HappyPath_SingleSigner(t *testing.T) {
	dir := t.TempDir()
	clerk := issueKey(t, dir, "clerk")
	clerkDID, _, _, err := LoadKey(clerk)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	spec := SubmitSpec{
		Schema:           "civil_case",
		Destination:      "did:web:state:tn:davidson",
		PrimarySignerKey: clerk,
		EventTimeMicros:  1_705_276_800_000_000,
		Payload: json.RawMessage(`{
            "docket_number": "2024-CV-001",
            "case_type": "contract",
            "filed_date": "2024-01-15",
            "status": "active"
        }`),
	}
	specPath := writeSpec(t, dir, "civil", spec)
	loaded, err := loadSubmitSpec(specPath)
	if err != nil {
		t.Fatalf("loadSubmitSpec: %v", err)
	}

	wire, hash, err := buildAndSign(loaded)
	if err != nil {
		t.Fatalf("buildAndSign: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("empty wire bytes")
	}
	if got := sha256.Sum256(wire); got != hash {
		t.Errorf("returned hash != sha256(wire)")
	}

	// Roundtrip through envelope.Deserialize and verify.
	got, err := sdkenv.Deserialize(wire)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.Header.SignerDID != clerkDID {
		t.Errorf("SignerDID drift: want %s, got %s", clerkDID, got.Header.SignerDID)
	}
	if got.Header.Destination != spec.Destination {
		t.Errorf("Destination drift: want %s, got %s", spec.Destination, got.Header.Destination)
	}
	if len(got.Signatures) != 1 {
		t.Fatalf("signatures: want 1, got %d", len(got.Signatures))
	}
	if got.Signatures[0].SignerDID != clerkDID {
		t.Errorf("Signatures[0] drift: %s != %s", got.Signatures[0].SignerDID, clerkDID)
	}
	if got.Signatures[0].AlgoID != sdkenv.SigAlgoECDSA {
		t.Errorf("AlgoID: want SigAlgoECDSA, got 0x%04x", got.Signatures[0].AlgoID)
	}

	// Cryptographic sanity: VerifyEntry must accept the signature
	// against the public key we stored in the key file.
	digest := sha256.Sum256(sdkenv.SigningPayload(got))
	_, _, priv, err := LoadKey(clerk)
	if err != nil {
		t.Fatalf("LoadKey for verify: %v", err)
	}
	if err := sdksigs.VerifyEntry(digest, got.Signatures[0].Bytes, &priv.PublicKey); err != nil {
		t.Errorf("VerifyEntry: %v", err)
	}
}

func TestBuildAndSign_WithCosignerAndEvidence(t *testing.T) {
	dir := t.TempDir()
	primary := issueKey(t, dir, "clerk")
	cosigner := issueKey(t, dir, "cooper")
	primaryDID, _, _, _ := LoadKey(primary)
	cosignerDID, _, _, _ := LoadKey(cosigner)

	spec := SubmitSpec{
		Destination:      "did:web:state:tn:davidson",
		PrimarySignerKey: primary,
		CosignerKeys:     []string{cosigner},
		EventTimeMicros:  1_705_276_800_000_000,
		EvidencePointers: []EvidencePointer{
			{LogDID: "did:web:state:tn:coa", Sequence: 7},
		},
		Payload: json.RawMessage(`{"binding_id":"bind-001","party_class":"plaintiff","case_ref":"2024-CV-001"}`),
	}
	specPath := writeSpec(t, dir, "party", spec)
	loaded, err := loadSubmitSpec(specPath)
	if err != nil {
		t.Fatalf("loadSubmitSpec: %v", err)
	}
	wire, _, err := buildAndSign(loaded)
	if err != nil {
		t.Fatalf("buildAndSign: %v", err)
	}
	got, err := sdkenv.Deserialize(wire)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if len(got.Signatures) != 2 {
		t.Fatalf("signatures: want 2 (primary + 1 cosigner), got %d", len(got.Signatures))
	}
	if got.Signatures[0].SignerDID != primaryDID {
		t.Errorf("Signatures[0]: %s != primary %s", got.Signatures[0].SignerDID, primaryDID)
	}
	if got.Signatures[1].SignerDID != cosignerDID {
		t.Errorf("Signatures[1]: %s != cosigner %s", got.Signatures[1].SignerDID, cosignerDID)
	}
	if len(got.Header.EvidencePointers) != 1 {
		t.Fatalf("EvidencePointers: want 1, got %d", len(got.Header.EvidencePointers))
	}
	if got.Header.EvidencePointers[0].LogDID != "did:web:state:tn:coa" ||
		got.Header.EvidencePointers[0].Sequence != 7 {
		t.Errorf("EvidencePointers drift: %+v", got.Header.EvidencePointers[0])
	}
}

func TestLoadSubmitSpec_RejectsOverCappedEvidence(t *testing.T) {
	dir := t.TempDir()
	primary := issueKey(t, dir, "clerk")
	pointers := make([]EvidencePointer, 11)
	for i := range pointers {
		pointers[i] = EvidencePointer{LogDID: "did:web:x", Sequence: uint64(i + 1)}
	}
	spec := SubmitSpec{
		Destination:      "did:web:state:tn:davidson",
		PrimarySignerKey: primary,
		EvidencePointers: pointers,
		Payload:          json.RawMessage(`{}`),
	}
	specPath := writeSpec(t, dir, "bad", spec)
	if _, err := loadSubmitSpec(specPath); err == nil {
		t.Fatal("11 evidence pointers MUST reject (operator cap is 10)")
	}
}

func TestLoadSubmitSpec_MissingFields(t *testing.T) {
	dir := t.TempDir()
	cases := []SubmitSpec{
		{PrimarySignerKey: "x", Payload: json.RawMessage(`{}`)},        // no destination
		{Destination: "did:web:x", Payload: json.RawMessage(`{}`)},     // no signer key
		{Destination: "did:web:x", PrimarySignerKey: "x"},              // no payload
	}
	for i, s := range cases {
		path := writeSpec(t, dir, "bad", s)
		if _, err := loadSubmitSpec(path); err == nil {
			t.Errorf("case %d: MUST reject", i)
		}
	}
}
