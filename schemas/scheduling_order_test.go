// Tests for judicial-scheduling-order-v1.
//
// Pins the daily-court contract:
//   1. Round-trip serialize/deserialize preserves every field.
//   2. The schema registers cleanly in the JN domain Registry.
//   3. The schema flows through the SDK admission Registry with
//      a non-nil Binding (D9 enrichment).
//   4. Standard-milestone "every case has a trial date" scenario
//      from dictionary §6 works end-to-end.
//   5. The amended-order chain (PriorOrderPos) round-trips.
//   6. Specialty-court milestone sets (drug court treatment-
//      review hearings) round-trip — the schema does not
//      reject deployment-specific milestone names.
package schemas

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
)

// caseAt is a test fixture: a LogPosition for a case root entry.
func caseAt(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: "did:web:test-court.example", Sequence: seq}
}

// TestSchedulingOrder_RegisteredInJNRegistry pins that the
// schema is reachable from the default Registry — i.e., the
// registerAll() call wires it in. Without this, downstream
// production code that constructs a Registry would silently
// not know about the schema.
func TestSchedulingOrder_RegisteredInJNRegistry(t *testing.T) {
	r := NewRegistry()
	if !r.Has(SchemaSchedulingOrderV1) {
		t.Fatalf("Registry missing schema %q", SchemaSchedulingOrderV1)
	}
}

// TestSchedulingOrder_RoundTrip pins serialize→deserialize
// preserves every payload field across a realistic 4-milestone
// civil-case calendar (the daily case-management conference
// scenario from the schema docstring).
func TestSchedulingOrder_RoundTrip(t *testing.T) {
	caseRoot := caseAt(100)
	original := &SchedulingOrderPayload{
		CaseRootPos: caseRoot,
		Milestones: []SchedulingOrderMilestone{
			{Name: "discovery_close", DueAt: time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC)},
			{Name: "motion_cutoff", DueAt: time.Date(2027, 8, 15, 0, 0, 0, 0, time.UTC)},
			{Name: "pretrial_conference", DueAt: time.Date(2027, 9, 15, 0, 0, 0, 0, time.UTC), Notes: "settlement conference"},
			{Name: "trial_date", DueAt: time.Date(2027, 10, 15, 0, 0, 0, 0, time.UTC)},
		},
		IssuedAt:        time.Date(2026, 5, 29, 14, 0, 0, 0, time.UTC),
		IssuingJudgeDID: "did:web:judge.smith.tn.example",
	}

	body, err := SerializeSchedulingOrderPayload(original)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	got, err := DeserializeSchedulingOrderPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}

	if got.CaseRootPos != original.CaseRootPos {
		t.Errorf("CaseRootPos drift: got %+v, want %+v", got.CaseRootPos, original.CaseRootPos)
	}
	if got.IssuingJudgeDID != original.IssuingJudgeDID {
		t.Errorf("IssuingJudgeDID drift: got %q, want %q", got.IssuingJudgeDID, original.IssuingJudgeDID)
	}
	if !got.IssuedAt.Equal(original.IssuedAt) {
		t.Errorf("IssuedAt drift: got %v, want %v", got.IssuedAt, original.IssuedAt)
	}
	if len(got.Milestones) != len(original.Milestones) {
		t.Fatalf("Milestones len = %d, want %d", len(got.Milestones), len(original.Milestones))
	}
	for i := range original.Milestones {
		if got.Milestones[i].Name != original.Milestones[i].Name {
			t.Errorf("Milestones[%d].Name = %q, want %q", i, got.Milestones[i].Name, original.Milestones[i].Name)
		}
		if !got.Milestones[i].DueAt.Equal(original.Milestones[i].DueAt) {
			t.Errorf("Milestones[%d].DueAt drift", i)
		}
		if got.Milestones[i].Notes != original.Milestones[i].Notes {
			t.Errorf("Milestones[%d].Notes = %q, want %q", i, got.Milestones[i].Notes, original.Milestones[i].Notes)
		}
	}
}

// TestSchedulingOrder_AmendedChain_RoundTrip pins the continuance-
// granted scenario from the schema docstring: after a motion_
// continuance is granted, an amended scheduling_order with
// PriorOrderPos + AmendmentReason supersedes the original.
func TestSchedulingOrder_AmendedChain_RoundTrip(t *testing.T) {
	caseRoot := caseAt(100)
	originalOrder := caseAt(105) // the prior scheduling_order

	amended := &SchedulingOrderPayload{
		CaseRootPos: caseRoot,
		Milestones: []SchedulingOrderMilestone{
			{Name: "trial_date", DueAt: time.Date(2027, 12, 1, 0, 0, 0, 0, time.UTC)},
		},
		IssuedAt:        time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC),
		IssuingJudgeDID: "did:web:judge.smith.tn.example",
		PriorOrderPos:   originalOrder,
		AmendmentReason: "counsel of record granted continuance per motion_continuance",
	}
	body, err := SerializeSchedulingOrderPayload(amended)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	got, err := DeserializeSchedulingOrderPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.PriorOrderPos != originalOrder {
		t.Errorf("PriorOrderPos = %+v, want %+v", got.PriorOrderPos, originalOrder)
	}
	if got.AmendmentReason != amended.AmendmentReason {
		t.Errorf("AmendmentReason drift: got %q", got.AmendmentReason)
	}
}

// TestSchedulingOrder_SpecialtyCourt_RoundTrip pins specialty-
// court use case C: drug-court treatment-review hearings live
// in the same Milestones array as trial dates. The schema does
// not reject deployment-specific milestone names.
func TestSchedulingOrder_SpecialtyCourt_RoundTrip(t *testing.T) {
	order := &SchedulingOrderPayload{
		CaseRootPos: caseAt(50),
		Milestones: []SchedulingOrderMilestone{
			{Name: "treatment_review_hearing", DueAt: time.Date(2026, 7, 15, 9, 0, 0, 0, time.UTC), Notes: "30-day check-in"},
			{Name: "compliance_conference", DueAt: time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)},
			{Name: "graduation_hearing", DueAt: time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC), Notes: "anticipated"},
		},
		IssuedAt:        time.Date(2026, 6, 15, 14, 0, 0, 0, time.UTC),
		IssuingJudgeDID: "did:web:judge.specialty.tn.example",
	}
	body, err := SerializeSchedulingOrderPayload(order)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	got, err := DeserializeSchedulingOrderPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(got.Milestones) != 3 || got.Milestones[0].Name != "treatment_review_hearing" {
		t.Errorf("specialty milestones drift: %+v", got.Milestones)
	}
}

// TestSchedulingOrder_MalformedJSON_Rejected pins fail-closed
// on garbage input — same posture as every other JN schema.
func TestSchedulingOrder_MalformedJSON_Rejected(t *testing.T) {
	if _, err := DeserializeSchedulingOrderPayload([]byte("{not valid json")); err == nil {
		t.Fatal("malformed JSON must be rejected")
	}
}

// TestSchedulingOrder_AdmissionThroughSDKRegistry pins the
// SDK admission contract: the schema's enriched Binding's
// Validator accepts a well-formed payload through the SDK's
// ValidateEntry pipeline.
func TestSchedulingOrder_AdmissionThroughSDKRegistry(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	good := &SchedulingOrderPayload{
		CaseRootPos: caseAt(100),
		Milestones: []SchedulingOrderMilestone{
			{Name: "trial_date", DueAt: time.Date(2027, 10, 15, 0, 0, 0, 0, time.UTC)},
		},
		IssuedAt:        time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC),
		IssuingJudgeDID: "did:web:judge.smith.tn.example",
	}
	body, err := SerializeSchedulingOrderPayload(good)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := r.ValidateAdmission(sdk, SchemaSchedulingOrderV1, &envelope.Entry{DomainPayload: body}); err != nil {
		t.Errorf("admission rejected well-formed payload: %v", err)
	}
}
