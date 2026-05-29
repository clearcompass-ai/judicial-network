// Tests for judicial-warrant-v1.
//
// Pins the daily criminal-court contract:
//   1. Registration in the JN domain Registry.
//   2. Arrest warrant on felony complaint (use case A) —
//      issuance + ProbableCauseRef round-trip.
//   3. Search warrant for digital evidence (use case B) —
//      TargetSpecifications + WarrantTypeSearch round-trip.
//   4. Bench warrant for failure to appear (use case C) —
//      no ProbableCauseRef required; WarrantTypeBench round-trips.
//   5. Two-phase issuance→return chain via PriorWarrantPos.
//   6. Every WarrantType constant round-trips.
//   7. WarrantReturn nested struct round-trips with Executed flag.
package schemas

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

func TestWarrant_RegisteredInJNRegistry(t *testing.T) {
	r := NewRegistry()
	if !r.Has(SchemaWarrantV1) {
		t.Fatalf("Registry missing %q", SchemaWarrantV1)
	}
}

// TestWarrant_ArrestOnFelonyComplaint pins use case A: arrest
// warrant on a felony complaint. ProbableCauseRef points at the
// underlying complaint entry; TargetBinding identifies the
// defendant.
func TestWarrant_ArrestOnFelonyComplaint(t *testing.T) {
	caseRoot := caseAt(100)
	complaint := caseAt(110)

	warrant := &WarrantPayload{
		CaseRootPos:      caseRoot,
		WarrantType:      WarrantTypeArrest,
		TargetBinding:    "binding-defendant-001",
		ProbableCauseRef: complaint,
		SourceAuthority:  "TCA 40-6-205",
		Issuance: WarrantIssuance{
			IssuedAt:        time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC),
			IssuingJudgeDID: "did:web:judge.criminal.tn.example",
		},
	}
	body, err := SerializeWarrantPayload(warrant)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	got, err := DeserializeWarrantPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.WarrantType != WarrantTypeArrest {
		t.Errorf("WarrantType drift: %q", got.WarrantType)
	}
	if got.TargetBinding != "binding-defendant-001" {
		t.Errorf("TargetBinding drift: %q", got.TargetBinding)
	}
	if got.ProbableCauseRef != complaint {
		t.Errorf("ProbableCauseRef drift: %+v", got.ProbableCauseRef)
	}
	if got.Return != nil {
		t.Error("Return populated on initial issuance; should be nil")
	}
}

// TestWarrant_SearchWithTargetSpecifications pins use case B:
// search warrant for digital evidence. TargetSpecifications
// names the locations (constitutional particularity), no
// TargetBinding (the warrant authorizes search of THINGS, not
// arrest of a PERSON).
func TestWarrant_SearchWithTargetSpecifications(t *testing.T) {
	warrant := &WarrantPayload{
		CaseRootPos:      caseAt(200),
		WarrantType:      WarrantTypeSearch,
		TargetSpecifications: []string{
			"residence at 1234 Main St, Nashville TN 37203",
			"any Apple iPhone associated with phone number 615-555-0100",
			"iCloud account anonymized@icloud.example",
			"Google account anonymized@gmail.example",
		},
		ProbableCauseRef: caseAt(210), // the affidavit entry
		SourceAuthority:  "TRCrP 41 / TCA 40-6-105",
		Issuance: WarrantIssuance{
			IssuedAt:        time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC),
			IssuingJudgeDID: "did:web:judge.criminal.tn.example",
			ExpiresAt:       time.Date(2026, 6, 11, 9, 0, 0, 0, time.UTC), // TRCrP 41: 10 days
		},
	}
	body, _ := SerializeWarrantPayload(warrant)
	got, err := DeserializeWarrantPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.WarrantType != WarrantTypeSearch {
		t.Errorf("WarrantType drift: %q", got.WarrantType)
	}
	if len(got.TargetSpecifications) != 4 {
		t.Errorf("TargetSpecifications dropped: got %d", len(got.TargetSpecifications))
	}
	if got.TargetBinding != "" {
		t.Errorf("search warrant should not have TargetBinding; got %q", got.TargetBinding)
	}
	if !got.Issuance.ExpiresAt.Equal(time.Date(2026, 6, 11, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("ExpiresAt drift: %v", got.Issuance.ExpiresAt)
	}
}

// TestWarrant_BenchWarrant_FailureToAppear pins use case C:
// bench warrant for FTA. No ProbableCauseRef (the FTA is the
// cause); TargetBinding identifies the defendant.
func TestWarrant_BenchWarrant_FailureToAppear(t *testing.T) {
	warrant := &WarrantPayload{
		CaseRootPos:     caseAt(300),
		WarrantType:     WarrantTypeBench,
		TargetBinding:   "binding-defendant-fta-001",
		SourceAuthority: "TCA 40-11-138 (failure to appear)",
		Issuance: WarrantIssuance{
			IssuedAt:        time.Date(2026, 5, 29, 14, 0, 0, 0, time.UTC),
			IssuingJudgeDID: "did:web:judge.criminal.tn.example",
			// No expiration on bench warrants.
		},
	}
	body, _ := SerializeWarrantPayload(warrant)
	got, err := DeserializeWarrantPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.WarrantType != WarrantTypeBench {
		t.Errorf("WarrantType drift: %q", got.WarrantType)
	}
	if !got.ProbableCauseRef.IsNull() {
		t.Errorf("bench warrant should have null ProbableCauseRef; got %+v", got.ProbableCauseRef)
	}
	if !got.Issuance.ExpiresAt.IsZero() {
		t.Errorf("bench warrant ExpiresAt should be zero (no expiration); got %v", got.Issuance.ExpiresAt)
	}
}

// TestWarrant_TwoPhaseReturnChain pins the issuance→return
// chain: an amended entry with PriorWarrantPos pointing at the
// original + a populated Return struct closes the warrant's
// active state.
func TestWarrant_TwoPhaseReturnChain(t *testing.T) {
	originalIssuance := caseAt(105)

	returned := &WarrantPayload{
		CaseRootPos:     caseAt(100),
		WarrantType:     WarrantTypeArrest,
		TargetBinding:   "binding-defendant-001",
		SourceAuthority: "TCA 40-6-205",
		Issuance: WarrantIssuance{
			IssuedAt:        time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC),
			IssuingJudgeDID: "did:web:judge.criminal.tn.example",
		},
		Return: &WarrantReturn{
			ReturnedAt:          time.Date(2026, 6, 1, 16, 30, 0, 0, time.UTC),
			ExecutingOfficerDID: "did:web:deputy.smith.davidson.example",
			Executed:            true,
			Notes:               "Subject arrested without incident at 1234 Main St per warrant. Transported to county jail.",
		},
		PriorWarrantPos: originalIssuance,
	}
	body, _ := SerializeWarrantPayload(returned)
	got, err := DeserializeWarrantPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.PriorWarrantPos != originalIssuance {
		t.Errorf("PriorWarrantPos drift: %+v", got.PriorWarrantPos)
	}
	if got.Return == nil {
		t.Fatal("Return should be non-nil on returned warrant")
	}
	if !got.Return.Executed {
		t.Error("Return.Executed should be true")
	}
	if got.Return.ExecutingOfficerDID != "did:web:deputy.smith.davidson.example" {
		t.Errorf("ExecutingOfficerDID drift")
	}
}

// TestWarrant_UnexecutedReturn pins the negative case: a
// warrant returned WITHOUT execution (subject not found,
// premises vacated). Executed=false; Notes captures the
// officer's explanation.
func TestWarrant_UnexecutedReturn(t *testing.T) {
	returned := &WarrantPayload{
		CaseRootPos:     caseAt(100),
		WarrantType:     WarrantTypeSearch,
		TargetSpecifications: []string{"residence at 5678 Oak St"},
		SourceAuthority: "TRCrP 41",
		Issuance: WarrantIssuance{
			IssuedAt:        time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC),
			IssuingJudgeDID: "did:web:judge.criminal.tn.example",
			ExpiresAt:       time.Date(2026, 6, 8, 10, 0, 0, 0, time.UTC),
		},
		Return: &WarrantReturn{
			ReturnedAt:          time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC),
			ExecutingOfficerDID: "did:web:detective.jones.davidson.example",
			Executed:            false,
			Notes:               "Premises vacated; tenant moved out per landlord. No items seized.",
		},
		PriorWarrantPos: caseAt(105),
	}
	body, _ := SerializeWarrantPayload(returned)
	got, err := DeserializeWarrantPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.Return.Executed {
		t.Error("Executed should be false on unexecuted return")
	}
}

// TestWarrant_AllWarrantTypes pins that every WarrantType
// constant round-trips correctly.
func TestWarrant_AllWarrantTypes(t *testing.T) {
	for _, wt := range []string{
		WarrantTypeArrest,
		WarrantTypeSearch,
		WarrantTypeBench,
		WarrantTypeCapias,
		WarrantTypeMaterialWitness,
	} {
		t.Run(wt, func(t *testing.T) {
			warrant := &WarrantPayload{
				CaseRootPos: caseAt(100),
				WarrantType: wt,
				SourceAuthority: "test",
				Issuance: WarrantIssuance{
					IssuedAt:        time.Now().UTC(),
					IssuingJudgeDID: "did:web:judge.test",
				},
			}
			body, _ := SerializeWarrantPayload(warrant)
			got, err := DeserializeWarrantPayload(body)
			if err != nil {
				t.Fatalf("deserialize: %v", err)
			}
			if got.WarrantType != wt {
				t.Errorf("WarrantType = %q, want %q", got.WarrantType, wt)
			}
		})
	}
}

func TestWarrant_AdmissionThroughSDKRegistry(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	warrant := &WarrantPayload{
		CaseRootPos:     caseAt(100),
		WarrantType:     WarrantTypeArrest,
		TargetBinding:   "binding-defendant-001",
		SourceAuthority: "TCA 40-6-205",
		Issuance: WarrantIssuance{
			IssuedAt:        time.Now().UTC(),
			IssuingJudgeDID: "did:web:judge.test",
		},
	}
	body, _ := SerializeWarrantPayload(warrant)
	if err := r.ValidateAdmission(sdk, SchemaWarrantV1, &envelope.Entry{DomainPayload: body}); err != nil {
		t.Errorf("admission rejected well-formed payload: %v", err)
	}
}
