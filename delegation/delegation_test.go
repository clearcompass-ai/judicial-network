package delegation

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/internal/testutil"
)

// ─── Helpers ────────────────────────────────────────────────────────

const (
	courtDID   = "did:web:courts.nashville.gov"
	judgeDID   = "did:web:exchange:davidson:role:judge-mcclendon"
	clerkDID   = "did:web:exchange:davidson:role:clerk-williams"
	deputyDID  = "did:web:exchange:davidson:role:deputy-chen"
	outsideDID = "did:web:exchange:shelby:role:judge-smith"
)

func mustDeserialize(t *testing.T, entry *envelope.Entry) *envelope.Entry {
	t.Helper()
	signed := testutil.SignEntry(t, entry, testutil.GenerateSigningKey(t))
	raw := envelope.Serialize(signed)
	parsed, err := envelope.Deserialize(raw)
	if err != nil {
		t.Fatalf("roundtrip deserialize failed: %v", err)
	}
	return parsed
}

// ─── Unit: Depth 1 — Court → Judge ─────────────────────────────────

func TestBuildJudgeDelegation_Depth1(t *testing.T) {
	scopePayload, _ := json.Marshal(map[string]any{
		"role":        "presiding_judge",
		"division":    "criminal",
		"scope_limit": []string{"case_filing", "order", "judgment"},
	})

	entry, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   courtDID,
		DelegateDID: judgeDID,
		Payload:     scopePayload,
	})
	if err != nil {
		t.Fatalf("BuildDelegation failed: %v", err)
	}

	// Verify header fields.
	if entry.Header.SignerDID != courtDID {
		t.Errorf("SignerDID = %q, want %q", entry.Header.SignerDID, courtDID)
	}
	if entry.Header.DelegateDID == nil || *entry.Header.DelegateDID != judgeDID {
		t.Errorf("DelegateDID = %v, want %q", entry.Header.DelegateDID, judgeDID)
	}
	if entry.Header.AuthorityPath == nil || *entry.Header.AuthorityPath != envelope.AuthoritySameSigner {
		t.Error("AuthorityPath should be SameSigner for delegation")
	}
	if entry.Header.TargetRoot != nil {
		t.Error("TargetRoot should be nil for new delegation (creates new leaf)")
	}

	// Verify Domain Payload roundtrips.
	rt := mustDeserialize(t, entry)
	var payload map[string]any
	if err := json.Unmarshal(rt.DomainPayload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["role"] != "presiding_judge" {
		t.Errorf("role = %v, want presiding_judge", payload["role"])
	}
}

// ─── Unit: Depth 2 — Judge → Clerk ─────────────────────────────────

func TestBuildClerkDelegation_Depth2(t *testing.T) {
	entry, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   judgeDID,
		DelegateDID: clerkDID,
		Payload: mustJSON(t, map[string]any{
			"role":        "clerk",
			"division":    "criminal",
			"scope_limit": []string{"scheduling", "docket_management"},
		}),
	})
	if err != nil {
		t.Fatalf("BuildDelegation depth 2 failed: %v", err)
	}

	if entry.Header.SignerDID != judgeDID {
		t.Errorf("SignerDID = %q, want %q (judge as delegator)", entry.Header.SignerDID, judgeDID)
	}
	if *entry.Header.DelegateDID != clerkDID {
		t.Errorf("DelegateDID = %q, want %q", *entry.Header.DelegateDID, clerkDID)
	}
}

// ─── Unit: Depth 3 — Clerk → Deputy ────────────────────────────────

func TestBuildDeputyDelegation_Depth3(t *testing.T) {
	entry, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   clerkDID,
		DelegateDID: deputyDID,
		Payload: mustJSON(t, map[string]any{
			"role":        "deputy_clerk",
			"scope_limit": []string{"filing_acceptance"},
		}),
	})
	if err != nil {
		t.Fatalf("BuildDelegation depth 3 failed: %v", err)
	}

	if entry.Header.SignerDID != clerkDID {
		t.Errorf("SignerDID = %q, want %q", entry.Header.SignerDID, clerkDID)
	}
	if *entry.Header.DelegateDID != deputyDID {
		t.Errorf("DelegateDID = %q, want %q", *entry.Header.DelegateDID, deputyDID)
	}
}

// ─── Unit: Revocation produces correct entry ────────────────────────

func TestBuildRevocation(t *testing.T) {
	targetPos := types.LogPosition{LogDID: "did:web:courts.nashville.gov:officers", Sequence: 42}

	entry, err := builder.BuildRevocation(builder.RevocationParams{
		Destination: "did:web:exchange.test",
		SignerDID:  courtDID,
		TargetRoot: targetPos,
		Payload:    mustJSON(t, map[string]any{"reason": "officer_departed"}),
	})
	if err != nil {
		t.Fatalf("BuildRevocation failed: %v", err)
	}

	if entry.Header.SignerDID != courtDID {
		t.Errorf("SignerDID = %q, want %q", entry.Header.SignerDID, courtDID)
	}
	if entry.Header.TargetRoot == nil {
		t.Fatal("TargetRoot should be set for revocation")
	}
	if !entry.Header.TargetRoot.Equal(targetPos) {
		t.Errorf("TargetRoot = %v, want %v", *entry.Header.TargetRoot, targetPos)
	}
	if entry.Header.AuthorityPath == nil || *entry.Header.AuthorityPath != envelope.AuthoritySameSigner {
		t.Error("Revocation should use AuthoritySameSigner (Path A)")
	}
	// Revocation must NOT have DelegateDID.
	if entry.Header.DelegateDID != nil {
		t.Error("Revocation should not have DelegateDID")
	}
}

// ─── Unit: Empty DelegateDID rejected ───────────────────────────────

func TestBuildDelegation_EmptyDelegate_Rejected(t *testing.T) {
	_, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   courtDID,
		DelegateDID: "",
		Payload:     []byte("{}"),
	})
	if err == nil {
		t.Fatal("expected error for empty DelegateDID, got nil")
	}
}

// ─── Unit: Empty SignerDID rejected ─────────────────────────────────

func TestBuildDelegation_EmptySigner_Rejected(t *testing.T) {
	_, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   "",
		DelegateDID: judgeDID,
		Payload:     []byte("{}"),
	})
	if err == nil {
		t.Fatal("expected error for empty SignerDID, got nil")
	}
}

// ─── Unit: Serialize/Deserialize roundtrip ──────────────────────────

func TestDelegationEntry_SerializeRoundtrip(t *testing.T) {
	original, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   courtDID,
		DelegateDID: judgeDID,
		Payload:     mustJSON(t, map[string]any{"role": "judge", "division": "criminal"}),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	signed := testutil.SignEntry(t, original, testutil.GenerateSigningKey(t))
	raw := envelope.Serialize(signed)
	if len(raw) == 0 {
		t.Fatal("Serialize produced empty bytes")
	}

	restored, err := envelope.Deserialize(raw)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}

	if restored.Header.SignerDID != original.Header.SignerDID {
		t.Error("SignerDID mismatch after roundtrip")
	}
	if *restored.Header.DelegateDID != *original.Header.DelegateDID {
		t.Error("DelegateDID mismatch after roundtrip")
	}
	if string(restored.DomainPayload) != string(original.DomainPayload) {
		t.Error("DomainPayload mismatch after roundtrip")
	}
}

// ─── Unit: Commentary (daily docket) has zero SMT footprint ─────────

func TestBuildCommentary_ZeroSMTImpact(t *testing.T) {
	entry, err := builder.BuildCommentary(builder.CommentaryParams{
		Destination: "did:web:exchange.test",
		SignerDID: courtDID,
		Payload:   mustJSON(t, map[string]any{"type": "daily_docket", "date": "2027-03-15"}),
	})
	if err != nil {
		t.Fatalf("BuildCommentary: %v", err)
	}

	// Commentary: no TargetRoot, no AuthorityPath, no DelegateDID.
	if entry.Header.TargetRoot != nil {
		t.Error("Commentary should have nil TargetRoot")
	}
	if entry.Header.AuthorityPath != nil {
		t.Error("Commentary should have nil AuthorityPath")
	}
	if entry.Header.DelegateDID != nil {
		t.Error("Commentary should have nil DelegateDID")
	}
}

// ─── Unit: Multiple delegations from same signer ────────────────────

func TestMultipleDelegations_SameSigner(t *testing.T) {
	// Court delegates to two different judges — both should succeed.
	entry1, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   courtDID,
		DelegateDID: judgeDID,
		Payload:     mustJSON(t, map[string]any{"division": "criminal"}),
	})
	if err != nil {
		t.Fatalf("first delegation: %v", err)
	}

	entry2, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   courtDID,
		DelegateDID: outsideDID,
		Payload:     mustJSON(t, map[string]any{"division": "civil"}),
	})
	if err != nil {
		t.Fatalf("second delegation: %v", err)
	}

	// Both should have the same signer but different delegates.
	if entry1.Header.SignerDID != entry2.Header.SignerDID {
		t.Error("both delegations should have the same signer")
	}
	if *entry1.Header.DelegateDID == *entry2.Header.DelegateDID {
		t.Error("delegations should have different delegates")
	}
}

// ─── Helpers ────────────────────────────────────────────────────────

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return b
}
