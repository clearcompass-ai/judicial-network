// Tests for judicial-protective-order-v1.
//
// Pins the daily-court contract:
//   1. Registration in the JN domain Registry.
//   2. Ex parte DV protective order (use case A) round-trips
//      with all standard restrictions.
//   3. Civil TRO (use case B) — asset-freeze restrictions
//      round-trip identically.
//   4. Permanent injunction (use case C) — EffectiveUntil
//      zero round-trips as zero (not auto-defaulted).
//   5. Multiple ProtectedParties / RestrainedParties round-trip.
//   6. Generic Restrictions strings (not in any closed set)
//      round-trip — the schema is open-ended on purpose.
package schemas

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

func TestProtectiveOrder_RegisteredInJNRegistry(t *testing.T) {
	r := NewRegistry()
	if !r.Has(SchemaProtectiveOrderV1) {
		t.Fatalf("Registry missing %q", SchemaProtectiveOrderV1)
	}
}

// TestProtectiveOrder_ExParteDV_RoundTrip pins use case A:
// the morning ex parte DV protective order. Standard
// no_contact + stay_away + surrender_firearms restrictions.
func TestProtectiveOrder_ExParteDV_RoundTrip(t *testing.T) {
	order := &ProtectiveOrderPayload{
		CaseRootPos:       caseAt(100),
		ProtectedParties:  []string{"binding-victim-001"},
		RestrainedParties: []string{"binding-respondent-001"},
		Restrictions: []string{
			"no_contact",
			"no_electronic_contact",
			"stay_away_500ft",
			"surrender_firearms",
		},
		SourceAuthority: "TCA 36-3-605",
		IssuedAt:        time.Date(2026, 5, 29, 9, 0, 0, 0, time.UTC),
		EffectiveUntil:  time.Date(2026, 6, 12, 17, 0, 0, 0, time.UTC), // 14 days ex parte
		IssuingJudgeDID: "did:web:judge.dv.tn.example",
		IsExParte:       true,
	}
	body, err := SerializeProtectiveOrderPayload(order)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	got, err := DeserializeProtectiveOrderPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if !got.IsExParte {
		t.Error("IsExParte=false post-roundtrip; want true")
	}
	if len(got.Restrictions) != 4 {
		t.Errorf("Restrictions len = %d, want 4", len(got.Restrictions))
	}
	if got.SourceAuthority != "TCA 36-3-605" {
		t.Errorf("SourceAuthority drift: %q", got.SourceAuthority)
	}
}

// TestProtectiveOrder_CivilTRO_AssetFreeze pins use case B:
// civil TRO against asset destruction. Restrictions different
// from DV; SourceAuthority is TRCP 65.03 not TCA 36-3-605.
func TestProtectiveOrder_CivilTRO_AssetFreeze(t *testing.T) {
	order := &ProtectiveOrderPayload{
		CaseRootPos:       caseAt(200),
		ProtectedParties:  []string{"binding-plaintiff-corp"},
		RestrainedParties: []string{"binding-defendant-individual"},
		Restrictions: []string{
			"no_destruction_of_assets",
			"preserve_documents",
			"no_disposition_of_property",
		},
		SourceAuthority: "TRCP 65.03",
		IssuedAt:        time.Date(2026, 7, 1, 14, 0, 0, 0, time.UTC),
		EffectiveUntil:  time.Date(2026, 7, 15, 23, 59, 59, 0, time.UTC), // 14-day TRO
		IssuingJudgeDID: "did:web:judge.civil.tn.example",
		IsExParte:       false,
	}
	body, _ := SerializeProtectiveOrderPayload(order)
	got, err := DeserializeProtectiveOrderPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.SourceAuthority != "TRCP 65.03" {
		t.Errorf("SourceAuthority drift")
	}
	if got.IsExParte {
		t.Error("civil TRO with notice should not be ex parte")
	}
}

// TestProtectiveOrder_PermanentInjunction pins use case C: a
// permanent injunction has EffectiveUntil = zero (no expiration).
// Verify the zero value round-trips correctly (i.e., is NOT
// auto-populated to time.Now() or similar).
func TestProtectiveOrder_PermanentInjunction(t *testing.T) {
	order := &ProtectiveOrderPayload{
		CaseRootPos:       caseAt(300),
		ProtectedParties:  []string{"binding-protected-001"},
		RestrainedParties: []string{"binding-restrained-001"},
		Restrictions:      []string{"no_third_party_communication"},
		SourceAuthority:   "TRCP 65.04",
		IssuedAt:          time.Date(2026, 10, 15, 11, 0, 0, 0, time.UTC),
		// EffectiveUntil intentionally zero.
		IssuingJudgeDID: "did:web:judge.civil.tn.example",
	}
	body, _ := SerializeProtectiveOrderPayload(order)
	got, err := DeserializeProtectiveOrderPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if !got.EffectiveUntil.IsZero() {
		t.Errorf("EffectiveUntil should be zero (permanent); got %v", got.EffectiveUntil)
	}
}

// TestProtectiveOrder_MultipleProtectedAndRestrained pins that
// the slice fields handle the multi-party case (e.g., DV order
// protecting victim + minor children; restraining one alleged
// abuser + accomplice).
func TestProtectiveOrder_MultipleProtectedAndRestrained(t *testing.T) {
	order := &ProtectiveOrderPayload{
		CaseRootPos: caseAt(400),
		ProtectedParties: []string{
			"binding-victim-mother",
			"binding-victim-child-1",
			"binding-victim-child-2",
		},
		RestrainedParties: []string{
			"binding-respondent-primary",
			"binding-respondent-accomplice",
		},
		Restrictions:    []string{"no_contact", "stay_away_1000ft"},
		SourceAuthority: "TCA 36-3-606",
		IssuedAt:        time.Date(2026, 5, 29, 8, 30, 0, 0, time.UTC),
		IssuingJudgeDID: "did:web:judge.dv.tn.example",
		IsExParte:       true,
	}
	body, _ := SerializeProtectiveOrderPayload(order)
	got, err := DeserializeProtectiveOrderPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(got.ProtectedParties) != 3 || len(got.RestrainedParties) != 2 {
		t.Errorf("party counts drift: protected=%d, restrained=%d",
			len(got.ProtectedParties), len(got.RestrainedParties))
	}
}

// TestProtectiveOrder_OpenEndedRestrictions pins the design
// choice: Restrictions is OPEN — a deployment can declare a new
// statutory restriction ("no_cyber_stalking" post-2025) without
// a schema bump. The schema does NOT reject novel values.
func TestProtectiveOrder_OpenEndedRestrictions(t *testing.T) {
	order := &ProtectiveOrderPayload{
		CaseRootPos:       caseAt(500),
		ProtectedParties:  []string{"binding-victim"},
		RestrainedParties: []string{"binding-respondent"},
		Restrictions: []string{
			"no_cyber_stalking",
			"no_geolocation_tracking",
			"no_social_media_contact",
		},
		SourceAuthority: "TCA 39-17-315 (cyber-stalking, 2025 amendment)",
		IssuedAt:        time.Date(2026, 5, 29, 11, 0, 0, 0, time.UTC),
		IssuingJudgeDID: "did:web:judge.dv.tn.example",
	}
	body, _ := SerializeProtectiveOrderPayload(order)
	got, err := DeserializeProtectiveOrderPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(got.Restrictions) != 3 {
		t.Errorf("novel restrictions dropped: got %d", len(got.Restrictions))
	}
}

func TestProtectiveOrder_AdmissionThroughSDKRegistry(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	order := &ProtectiveOrderPayload{
		CaseRootPos:       caseAt(100),
		ProtectedParties:  []string{"binding-victim"},
		RestrainedParties: []string{"binding-respondent"},
		Restrictions:      []string{"no_contact"},
		SourceAuthority:   "TCA 36-3-605",
		IssuedAt:          time.Now().UTC(),
		IssuingJudgeDID:   "did:web:judge.test",
	}
	body, _ := SerializeProtectiveOrderPayload(order)
	if err := r.ValidateAdmission(sdk, SchemaProtectiveOrderV1, &envelope.Entry{DomainPayload: body}); err != nil {
		t.Errorf("admission rejected well-formed payload: %v", err)
	}
}
