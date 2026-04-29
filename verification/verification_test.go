package verification

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/internal/testutil"
)

const (
	courtDID    = "did:web:courts.nashville.gov"
	judgeDID    = "did:web:exchange:davidson:role:judge-mcclendon"
	casesLogDID = "did:web:courts.nashville.gov:cases"
)

// ═════════════════════════════════════════════════════════════════════
// Verification helpers — entry shape assertions
// ═════════════════════════════════════════════════════════════════════

// ─── Case status entry: amendment changes status ────────────────────

func TestCaseStatusAmendment_CarriesStatus(t *testing.T) {
	casePos := types.LogPosition{LogDID: casesLogDID, Sequence: 100}

	entry, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: "did:web:exchange.test",
		SignerDID:  courtDID,
		TargetRoot: casePos,
		Payload: mustJSON(t, map[string]any{
			"status":      "disposed",
			"disposition": "guilty_plea",
			"disposed_at": "2027-06-15",
		}),
	})
	if err != nil {
		t.Fatalf("status amendment: %v", err)
	}

	// Verify the payload carries the status change.
	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	if parsed["status"] != "disposed" {
		t.Errorf("status = %v, want disposed", parsed["status"])
	}
	if parsed["disposition"] != "guilty_plea" {
		t.Errorf("disposition = %v, want guilty_plea", parsed["disposition"])
	}
}

// ─── Evidence chain: multiple amendments form a chain ───────────────

func TestEvidenceChain_MultipleAmendments(t *testing.T) {
	casePos := types.LogPosition{LogDID: casesLogDID, Sequence: 100}

	// First amendment: initial filing.
	a1, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: "did:web:exchange.test",
		SignerDID:  courtDID,
		TargetRoot: casePos,
		Payload:    mustJSON(t, map[string]any{"event": "initial_filing", "seq": 1}),
	})
	if err != nil {
		t.Fatalf("a1: %v", err)
	}

	// Second amendment: evidence submitted.
	a2, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: "did:web:exchange.test",
		SignerDID:  courtDID,
		TargetRoot: casePos,
		Payload:    mustJSON(t, map[string]any{"event": "evidence_submitted", "seq": 2}),
	})
	if err != nil {
		t.Fatalf("a2: %v", err)
	}

	// Third amendment: hearing held.
	a3, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: "did:web:exchange.test",
		SignerDID:  courtDID,
		TargetRoot: casePos,
		Payload:    mustJSON(t, map[string]any{"event": "hearing_held", "seq": 3}),
	})
	if err != nil {
		t.Fatalf("a3: %v", err)
	}

	// All three target the same case entity.
	for i, entry := range []*envelope.Entry{a1, a2, a3} {
		if !entry.Header.TargetRoot.Equal(casePos) {
			t.Errorf("amendment %d: wrong TargetRoot", i+1)
		}
	}

	// Each serializes cleanly after the exchange signs them.
	for i, entry := range []*envelope.Entry{a1, a2, a3} {
		signed := testutil.SignEntry(t, entry, testutil.GenerateSigningKey(t))
		raw := envelope.Serialize(signed)
		_, err := envelope.Deserialize(raw)
		if err != nil {
			t.Errorf("amendment %d: roundtrip failed: %v", i+1, err)
		}
	}
}

// ─── Delegation chain verification: Path B entry shape ──────────────

func TestDelegationChainVerification_PathBShape(t *testing.T) {
	casePos := types.LogPosition{LogDID: casesLogDID, Sequence: 100}
	deleg1 := types.LogPosition{LogDID: casesLogDID, Sequence: 5}
	deleg2 := types.LogPosition{LogDID: casesLogDID, Sequence: 8}

	// Judge acts via 2-hop delegation chain.
	entry, err := builder.BuildPathBEntry(builder.PathBParams{
		Destination: "did:web:exchange.test",
		SignerDID:          judgeDID,
		TargetRoot:         casePos,
		DelegationPointers: []types.LogPosition{deleg1, deleg2},
		Payload:            mustJSON(t, map[string]any{"action": "order", "type": "judgment"}),
	})
	if err != nil {
		t.Fatalf("Path B: %v", err)
	}

	// Verify the chain can be extracted from the header for verification.
	if len(entry.Header.DelegationPointers) != 2 {
		t.Fatalf("DelegationPointers = %d, want 2", len(entry.Header.DelegationPointers))
	}

	// Verifier would walk: deleg1 → deleg2 → judge. Confirm positions.
	if !entry.Header.DelegationPointers[0].Equal(deleg1) {
		t.Error("first delegation pointer mismatch")
	}
	if !entry.Header.DelegationPointers[1].Equal(deleg2) {
		t.Error("second delegation pointer mismatch")
	}
}

// ─── Sealing check: enforcement entry detectable by header ──────────

func TestSealingCheck_EnforcementDetectable(t *testing.T) {
	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:    judgeDID,
		TargetRoot:   types.LogPosition{LogDID: casesLogDID, Sequence: 100},
		ScopePointer: types.LogPosition{LogDID: casesLogDID, Sequence: 1},
		Payload:      mustJSON(t, map[string]any{"order_type": "sealing_order"}),
	})
	if err != nil {
		t.Fatalf("enforcement: %v", err)
	}

	// A sealing check scans for enforcement entries targeting a case.
	// The entry is identifiable by: AuthorityPath=ScopeAuthority + TargetRoot set.
	isEnforcement := entry.Header.AuthorityPath != nil &&
		*entry.Header.AuthorityPath == envelope.AuthorityScopeAuthority &&
		entry.Header.TargetRoot != nil

	if !isEnforcement {
		t.Error("enforcement entry not identifiable by header shape")
	}

	// Domain payload carries the order type for filtering.
	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	if parsed["order_type"] != "sealing_order" {
		t.Error("sealing_order not in payload")
	}
}

// ─── Appellate history: amendment with cross-log reference ──────────

func TestAppellateHistory_CrossLogReference(t *testing.T) {
	casePos := types.LogPosition{LogDID: casesLogDID, Sequence: 100}
	appellateRef := types.LogPosition{
		LogDID:   "did:web:courts.tn.gov:appellate:cases",
		Sequence: 500,
	}

	entry, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: "did:web:exchange.test",
		SignerDID:        courtDID,
		TargetRoot:       casePos,
		EvidencePointers: []types.LogPosition{appellateRef},
		Payload: mustJSON(t, map[string]any{
			"status":        "remanded",
			"appellate_ref": appellateRef.String(),
			"appellate_decision": "reversed_and_remanded",
		}),
	})
	if err != nil {
		t.Fatalf("appellate amendment: %v", err)
	}

	// Evidence pointers carry the cross-log reference.
	if len(entry.Header.EvidencePointers) != 1 {
		t.Fatal("should have 1 evidence pointer (appellate reference)")
	}
	if entry.Header.EvidencePointers[0].LogDID != "did:web:courts.tn.gov:appellate:cases" {
		t.Error("evidence pointer should reference appellate log")
	}
}

// ─── Background check: multiple entries from different logs ─────────

func TestBackgroundCheck_MultiLogEntries(t *testing.T) {
	// Simulate entries from two different county logs.
	davidson, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:exchange.test",
		SignerDID: "did:web:courts.nashville.gov",
		Payload:   mustJSON(t, map[string]any{"docket": "2027-CR-4471", "county": "davidson"}),
	})
	if err != nil {
		t.Fatalf("davidson: %v", err)
	}

	shelby, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:exchange.test",
		SignerDID: "did:web:courts.memphis.gov",
		Payload:   mustJSON(t, map[string]any{"docket": "2027-CR-9901", "county": "shelby"}),
	})
	if err != nil {
		t.Fatalf("shelby: %v", err)
	}

	// Both are valid entries from different courts.
	if davidson.Header.SignerDID == shelby.Header.SignerDID {
		t.Error("entries should have different signers (different courts)")
	}

	// Both serialize cleanly after the exchange signs them.
	for name, entry := range map[string]*envelope.Entry{"davidson": davidson, "shelby": shelby} {
		signed := testutil.SignEntry(t, entry, testutil.GenerateSigningKey(t))
		raw := envelope.Serialize(signed)
		if _, err := envelope.Deserialize(raw); err != nil {
			t.Errorf("%s roundtrip: %v", name, err)
		}
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
