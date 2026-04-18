package tests

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═════════════════════════════════════════════════════════════════════
// Integration: Complete case lifecycle — file → amend → seal → unseal
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_CaseLifecycle_FileAmendSealUnseal(t *testing.T) {
	courtDID := "did:web:courts.lifecycle-test.gov"
	judgeDID := "did:web:ex:judge-lifecycle"
	casesLog := "did:web:courts.lifecycle-test.gov:cases"
	scopePos := types.LogPosition{LogDID: casesLog, Sequence: 1}

	// Step 1: File case (root entity).
	caseEntry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:exchange.test",
		SignerDID: courtDID,
		Payload: mustJSONW2(t, map[string]any{
			"docket_number": "2027-CR-9999",
			"case_type":     "criminal",
			"status":        "active",
		}),
	})
	if err != nil {
		t.Fatalf("file case: %v", err)
	}

	// Simulate: case lands at position 100.
	casePos := types.LogPosition{LogDID: casesLog, Sequence: 100}

	// Step 2: Amend case (update status).
	amendEntry, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: "did:web:exchange.test",
		SignerDID:  courtDID,
		TargetRoot: casePos,
		Payload: mustJSONW2(t, map[string]any{
			"status":      "arraigned",
			"arraignment": "2027-04-01",
		}),
	})
	if err != nil {
		t.Fatalf("amend case: %v", err)
	}

	// Step 3: Seal case (enforcement — Path C).
	sealEntry, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:    judgeDID,
		TargetRoot:   casePos,
		ScopePointer: scopePos,
		Payload:      mustJSONW2(t, map[string]any{"order_type": "sealing_order", "authority": "TCA 40-32-101"}),
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Step 4: Unseal case (enforcement — Path C, overrides prior).
	unsealEntry, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:    judgeDID,
		TargetRoot:   casePos,
		ScopePointer: scopePos,
		PriorAuthority: &types.LogPosition{LogDID: casesLog, Sequence: 102}, // seal entry position
		Payload:      mustJSONW2(t, map[string]any{"order_type": "unsealing_order", "reason": "public interest"}),
	})
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}

	// Verify chain: all entries target the same case, serialize cleanly.
	entries := []*envelope.Entry{caseEntry, amendEntry, sealEntry, unsealEntry}
	names := []string{"filing", "amendment", "seal", "unseal"}

	for i, e := range entries {
		raw := envelope.Serialize(e)
		restored, err := envelope.Deserialize(raw)
		if err != nil {
			t.Fatalf("%s roundtrip: %v", names[i], err)
		}
		_ = restored
	}

	// Filing has no target (new leaf). Others target the case.
	if caseEntry.Header.TargetRoot != nil {
		t.Error("filing should have nil TargetRoot")
	}
	for i, e := range entries[1:] {
		if e.Header.TargetRoot == nil || !e.Header.TargetRoot.Equal(casePos) {
			t.Errorf("%s should target casePos", names[i+1])
		}
	}

	// Seal and unseal use Path C.
	for _, e := range []*envelope.Entry{sealEntry, unsealEntry} {
		if *e.Header.AuthorityPath != envelope.AuthorityScopeAuthority {
			t.Error("seal/unseal should be Path C")
		}
	}

	// Unseal has PriorAuthority pointing to seal.
	if unsealEntry.Header.PriorAuthority == nil {
		t.Error("unseal should have PriorAuthority pointing to seal entry")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Expungement — encrypt → seal → expunge (key destroyed)
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_Expungement_KeyDestruction(t *testing.T) {
	// Step 1: Encrypt a document.
	document := []byte("Sealed juvenile record — TCA 37-1-153 applies")
	ciphertext, artKey, err := artifact.EncryptArtifact(document)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	cid := storage.Compute(ciphertext)

	// Step 2: Verify we CAN decrypt.
	recovered, err := artifact.DecryptArtifact(ciphertext, artKey)
	if err != nil {
		t.Fatalf("pre-expungement decrypt: %v", err)
	}
	if !bytes.Equal(recovered, document) {
		t.Fatal("pre-expungement content mismatch")
	}

	// Step 3: Simulate expungement — zero the key.
	artifact.ZeroKey(&artKey)

	// Step 4: Verify we CANNOT decrypt with zeroed key.
	_, err = artifact.DecryptArtifact(ciphertext, artKey)
	if err == nil {
		t.Fatal("expected decryption to fail after key destruction")
	}

	// Step 5: CID still identifies the ciphertext (metadata survives).
	if !cid.Verify(ciphertext) {
		t.Error("CID should still verify ciphertext after key destruction")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Juvenile auto-seal — entry with activation_delay=0
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_JuvenileAutoSeal(t *testing.T) {
	judgeDID := "did:web:ex:judge-juvenile"
	casesLog := "did:web:courts.test.gov:cases"
	casePos := types.LogPosition{LogDID: casesLog, Sequence: 200}
	scopePos := types.LogPosition{LogDID: casesLog, Sequence: 1}

	// File juvenile case.
	_, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:exchange.test",
		SignerDID: "did:web:courts.test.gov",
		Payload: mustJSONW2(t, map[string]any{
			"docket_number":           "2027-JV-0042",
			"case_type":              "juvenile",
			"auto_seal_at_disposition": true,
		}),
	})
	if err != nil {
		t.Fatalf("juvenile filing: %v", err)
	}

	// Auto-seal at disposition — activation_delay=0.
	sealEntry, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:    judgeDID,
		TargetRoot:   casePos,
		ScopePointer: scopePos,
		Payload: mustJSONW2(t, map[string]any{
			"order_type":       "sealing_order",
			"authority":        "TCA 37-1-153",
			"activation_delay": 0,
			"auto_seal":        true,
		}),
	})
	if err != nil {
		t.Fatalf("auto-seal: %v", err)
	}

	var parsed map[string]any
	json.Unmarshal(sealEntry.DomainPayload, &parsed)
	if parsed["activation_delay"] != float64(0) {
		t.Errorf("activation_delay = %v, want 0", parsed["activation_delay"])
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Path B judicial action through full delegation chain
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_PathB_FullDelegationChain(t *testing.T) {
	courtDID := "did:web:courts.pathb-test.gov"
	judgeDID := "did:web:ex:judge-pathb"
	clerkDID := "did:web:ex:clerk-pathb"
	casesLog := "did:web:courts.pathb-test.gov:cases"

	// Build delegation chain: court → judge (depth 1).
	d1, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   courtDID,
		DelegateDID: judgeDID,
		Payload:     mustJSONW2(t, map[string]any{"role": "judge"}),
	})
	if err != nil {
		t.Fatalf("d1: %v", err)
	}

	// Judge → clerk (depth 2).
	d2, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   judgeDID,
		DelegateDID: clerkDID,
		Payload:     mustJSONW2(t, map[string]any{"role": "clerk"}),
	})
	if err != nil {
		t.Fatalf("d2: %v", err)
	}

	// Simulate positions.
	d1Pos := types.LogPosition{LogDID: casesLog, Sequence: 5}
	d2Pos := types.LogPosition{LogDID: casesLog, Sequence: 8}
	casePos := types.LogPosition{LogDID: casesLog, Sequence: 100}

	// Clerk acts on case via 2-hop delegation (Path B).
	action, err := builder.BuildPathBEntry(builder.PathBParams{
		Destination: "did:web:exchange.test",
		SignerDID:          clerkDID,
		TargetRoot:         casePos,
		DelegationPointers: []types.LogPosition{d1Pos, d2Pos},
		Payload:            mustJSONW2(t, map[string]any{"action": "accept_filing", "filed_doc": "motion.pdf"}),
	})
	if err != nil {
		t.Fatalf("Path B action: %v", err)
	}

	// Verify chain: d1.Delegate == d2.Signer, d2.Delegate == action.Signer.
	if *d1.Header.DelegateDID != d2.Header.SignerDID {
		t.Error("chain broken: d1.Delegate != d2.Signer")
	}
	if *d2.Header.DelegateDID != action.Header.SignerDID {
		t.Error("chain broken: d2.Delegate != action.Signer")
	}

	// Action uses Path B.
	if *action.Header.AuthorityPath != envelope.AuthorityDelegation {
		t.Error("action should use AuthorityDelegation (Path B)")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Scope governance — propose → approve (cosignature)
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_ScopeGovernance_ProposeAndApprove(t *testing.T) {
	// Propose adding a new member.
	proposal, err := lifecycle.ProposeAmendment(lifecycle.AmendmentProposalParams{
		ProposerDID:  "did:web:courts.nashville.gov",
		ProposalType: lifecycle.ProposalAddAuthority,
		TargetDID:    "did:web:courts.knoxville.gov",
		Description:  "Add Knox County",
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}

	if proposal.Entry == nil {
		t.Fatal("proposal entry nil")
	}

	// Proposal serializes cleanly.
	raw := envelope.Serialize(proposal.Entry)
	restored, err := envelope.Deserialize(raw)
	if err != nil {
		t.Fatalf("proposal roundtrip: %v", err)
	}

	// Approval cosignature (references the proposal).
	// Simulate: proposal lands at position 500.
	proposalPos := types.LogPosition{LogDID: "did:web:courts.tn.gov:governance", Sequence: 500}

	approval, err := lifecycle.BuildApprovalCosignature(
		"did:web:courts.memphis.gov",
		proposalPos,
		1234567890,
	)
	if err != nil {
		t.Fatalf("BuildApprovalCosignature: %v", err)
	}

	// Approval is a cosignature entry.
	if approval.Header.CosignatureOf == nil {
		t.Fatal("approval should have CosignatureOf set")
	}
	if !approval.Header.CosignatureOf.Equal(proposalPos) {
		t.Error("approval should reference the proposal position")
	}

	_ = restored // verify compilation uses restored
}

// ═════════════════════════════════════════════════════════════════════
// Integration: Re-encryption preserves content across custody transfer
// ═════════════════════════════════════════════════════════════════════

func TestIntegration_ReEncryption_CustodyTransfer(t *testing.T) {
	// Original document under Exchange A's custody.
	document := []byte("Sealed evidence — chain of custody test document for custody transfer verification")

	ct1, key1, err := artifact.EncryptArtifact(document)
	if err != nil {
		t.Fatalf("initial encrypt: %v", err)
	}
	cid1 := storage.Compute(ct1)

	// Custody transfer: re-encrypt under Exchange B's keys.
	ct2, key2, err := artifact.ReEncryptArtifact(ct1, key1)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}
	cid2 := storage.Compute(ct2)

	// CIDs differ (different ciphertext).
	if cid1.Equal(cid2) {
		t.Error("re-encrypted CID should differ from original")
	}

	// Keys differ.
	if key1.Key == key2.Key {
		t.Error("re-encrypted key should differ")
	}

	// Content is identical after decryption.
	recovered, err := artifact.DecryptArtifact(ct2, key2)
	if err != nil {
		t.Fatalf("decrypt re-encrypted: %v", err)
	}
	if !bytes.Equal(recovered, document) {
		t.Fatal("re-encrypted content doesn't match original")
	}

	// Old key cannot decrypt new ciphertext (custody transfer complete).
	_, err = artifact.DecryptArtifact(ct2, key1)
	if err == nil {
		t.Error("old key should not decrypt re-encrypted ciphertext")
	}
}

func mustJSONW2(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return b
}
