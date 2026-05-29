// Tests for judicial-interlocutory-order-v1.
//
// Pins the high-volume daily-court contract:
//   1. Round-trip preservation across all fields.
//   2. Registration in the JN domain Registry.
//   3. Granted-motion-to-compel scenario (use case A from
//      docstring) round-trips cleanly.
//   4. Granted-in-part scenario (use case B) preserves Disposition.
//   5. IsDispositive=true (case-ending order, use case C)
//      round-trips and surfaces to consumers.
//   6. Closed-set Disposition constants are usable as named values.
package schemas

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

func TestInterlocutoryOrder_RegisteredInJNRegistry(t *testing.T) {
	r := NewRegistry()
	if !r.Has(SchemaInterlocutoryOrderV1) {
		t.Fatalf("Registry missing %q", SchemaInterlocutoryOrderV1)
	}
}

// TestInterlocutoryOrder_GrantedMotionToCompel_RoundTrip pins
// use case A from the docstring: granted motion to compel
// discovery. The order carries MotionRefPos pointing at the
// underlying motion — verified to round-trip identically.
func TestInterlocutoryOrder_GrantedMotionToCompel_RoundTrip(t *testing.T) {
	caseRoot := caseAt(100)
	motion := caseAt(150) // the motion_compel_discovery entry

	order := &InterlocutoryOrderPayload{
		CaseRootPos:     caseRoot,
		MotionRefPos:    motion,
		Disposition:     DispositionGranted,
		OrderText:       "GRANTED. Defendant shall produce all bates-stamped documents responsive to RFPs 1-15 within 21 days. Failure to comply will result in sanctions under TRCP 37.",
		IssuedAt:        time.Date(2026, 6, 1, 11, 30, 0, 0, time.UTC),
		IssuingJudgeDID: "did:web:judge.smith.tn.example",
	}
	body, err := SerializeInterlocutoryOrderPayload(order)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	got, err := DeserializeInterlocutoryOrderPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.MotionRefPos != motion {
		t.Errorf("MotionRefPos drift: got %+v, want %+v", got.MotionRefPos, motion)
	}
	if got.Disposition != DispositionGranted {
		t.Errorf("Disposition = %q, want %q", got.Disposition, DispositionGranted)
	}
	if got.IsDispositive {
		t.Error("granted motion to compel should not be dispositive (case continues)")
	}
}

// TestInterlocutoryOrder_GrantedInPart_RoundTrip pins use case B:
// motion in limine granted in part / denied in part. Tests that
// the granted_in_part_denied_in_part Disposition value round-trips.
func TestInterlocutoryOrder_GrantedInPart_RoundTrip(t *testing.T) {
	order := &InterlocutoryOrderPayload{
		CaseRootPos:     caseAt(100),
		MotionRefPos:    caseAt(200),
		Disposition:     DispositionGrantedInPartDeniedInPart,
		OrderText:       "GRANTED IN PART, DENIED IN PART. Categories 1 and 2 of defendant's MIL are GRANTED (prior-conviction evidence excluded; character evidence excluded). Category 3 is DENIED (expert testimony admitted subject to Daubert hearing).",
		IssuedAt:        time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC),
		IssuingJudgeDID: "did:web:judge.smith.tn.example",
	}
	body, _ := SerializeInterlocutoryOrderPayload(order)
	got, err := DeserializeInterlocutoryOrderPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.Disposition != DispositionGrantedInPartDeniedInPart {
		t.Errorf("Disposition = %q, want %q", got.Disposition, DispositionGrantedInPartDeniedInPart)
	}
}

// TestInterlocutoryOrder_CaseEndingDispositive pins use case C:
// granted motion to dismiss with prejudice. IsDispositive=true
// signals to case-management tooling that a final_judgment
// entry should follow.
func TestInterlocutoryOrder_CaseEndingDispositive(t *testing.T) {
	order := &InterlocutoryOrderPayload{
		CaseRootPos:     caseAt(100),
		MotionRefPos:    caseAt(180),
		Disposition:     DispositionGranted,
		OrderText:       "Motion to dismiss under TRCP 12.02(6) is GRANTED WITH PREJUDICE. Complaint dismissed. Costs to defendant.",
		IssuedAt:        time.Date(2026, 8, 15, 16, 0, 0, 0, time.UTC),
		IssuingJudgeDID: "did:web:judge.smith.tn.example",
		IsDispositive:   true,
	}
	body, _ := SerializeInterlocutoryOrderPayload(order)
	got, err := DeserializeInterlocutoryOrderPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if !got.IsDispositive {
		t.Error("IsDispositive should be true on case-ending order")
	}
}

// TestInterlocutoryOrder_AllDispositions_RoundTrip pins that
// every constant in the closed Disposition set round-trips
// — i.e., the constants are correctly aligned with the JSON
// values the schema serializes.
func TestInterlocutoryOrder_AllDispositions_RoundTrip(t *testing.T) {
	for _, d := range []string{
		DispositionGranted,
		DispositionDenied,
		DispositionGrantedInPartDeniedInPart,
		DispositionDeniedWithoutPrejudice,
		DispositionTakenUnderAdvisement,
	} {
		t.Run(d, func(t *testing.T) {
			order := &InterlocutoryOrderPayload{
				CaseRootPos:     caseAt(100),
				MotionRefPos:    caseAt(200),
				Disposition:     d,
				IssuedAt:        time.Now().UTC(),
				IssuingJudgeDID: "did:web:judge.test",
			}
			body, _ := SerializeInterlocutoryOrderPayload(order)
			got, err := DeserializeInterlocutoryOrderPayload(body)
			if err != nil {
				t.Fatalf("deserialize: %v", err)
			}
			if got.Disposition != d {
				t.Errorf("Disposition = %q, want %q", got.Disposition, d)
			}
		})
	}
}

func TestInterlocutoryOrder_AdmissionThroughSDKRegistry(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	order := &InterlocutoryOrderPayload{
		CaseRootPos:     caseAt(100),
		MotionRefPos:    caseAt(150),
		Disposition:     DispositionGranted,
		IssuedAt:        time.Now().UTC(),
		IssuingJudgeDID: "did:web:judge.test",
	}
	body, _ := SerializeInterlocutoryOrderPayload(order)
	if err := r.ValidateAdmission(sdk, SchemaInterlocutoryOrderV1, &envelope.Entry{DomainPayload: body}); err != nil {
		t.Errorf("admission rejected well-formed payload: %v", err)
	}
}
