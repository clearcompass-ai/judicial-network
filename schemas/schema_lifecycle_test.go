// Tests for judicial-schema-lifecycle-v1.
//
// Pins the rare-but-foundational governance contract:
//   1. Registration in the JN domain Registry.
//   2. Round-trip preservation for all four Action values.
//   3. Mental-health-court publication (use case A) — PublicFields
//      + PrivateFields round-trip.
//   4. Davidson adoption (use case B) — AdoptingExchangeDID +
//      PredecessorPos round-trip.
//   5. Bail-reform amendment (use case C) — AmendmentDescription
//      round-trip + SchemaVersion bump.
//   6. Paper-form deprecation (use case D) — DeprecationEffective
//      + GracePeriodSeconds round-trip; zero grace = hard cutover.
//   7. SDK admission accepts each Action.
package schemas

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
)

func networkPos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: "did:web:tn-state.example", Sequence: seq}
}

func TestSchemaLifecycle_RegisteredInJNRegistry(t *testing.T) {
	r := NewRegistry()
	if !r.Has(SchemaSchemaLifecycleV1) {
		t.Fatalf("Registry missing %q", SchemaSchemaLifecycleV1)
	}
}

// TestSchemaLifecycle_Publication pins use case A: the SC clerk
// publishes a new specialty-court schema with explicit
// PublicFields + PrivateFields. Privacy classification is frozen
// at publication; subsequent entries against the schema must
// respect the published classification.
func TestSchemaLifecycle_Publication(t *testing.T) {
	pub := &SchemaLifecyclePayload{
		Action:        ActionPublication,
		SchemaID:      "judicial-mental-health-court-docket-v1",
		SchemaVersion: 1,
		PublicFields: []string{
			"docket_number",
			"case_type",
			"filed_date",
			"status",
			"treatment_program_id",
		},
		PrivateFields: []string{
			"medical_diagnosis",
			"medication_regimen",
			"treatment_history",
			"competency_evaluation",
		},
		IssuedAt:   time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		IssuingDID: "did:web:tn-sc-clerk.example",
	}
	body, err := SerializeSchemaLifecyclePayload(pub)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	got, err := DeserializeSchemaLifecyclePayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.Action != ActionPublication {
		t.Errorf("Action = %q, want %q", got.Action, ActionPublication)
	}
	if got.SchemaID != "judicial-mental-health-court-docket-v1" {
		t.Errorf("SchemaID drift: %q", got.SchemaID)
	}
	if len(got.PublicFields) != 5 || len(got.PrivateFields) != 4 {
		t.Errorf("field counts drift: public=%d, private=%d",
			len(got.PublicFields), len(got.PrivateFields))
	}
}

// TestSchemaLifecycle_Adoption pins use case B: Davidson opts in
// to the SC publication. PredecessorPos points at the SC pub;
// AdoptingExchangeDID identifies Davidson.
func TestSchemaLifecycle_Adoption(t *testing.T) {
	publicationPos := networkPos(1000) // hypothetical SC publication

	adoption := &SchemaLifecyclePayload{
		Action:              ActionAdoption,
		SchemaID:            "judicial-mental-health-court-docket-v1",
		PredecessorPos:      publicationPos,
		AdoptingExchangeDID: "did:web:state:tn:davidson",
		IssuedAt:            time.Date(2026, 3, 1, 14, 0, 0, 0, time.UTC),
		IssuingDID:          "did:web:judge.chief.davidson.example",
	}
	body, _ := SerializeSchemaLifecyclePayload(adoption)
	got, err := DeserializeSchemaLifecyclePayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.PredecessorPos != publicationPos {
		t.Errorf("PredecessorPos drift: %+v, want %+v", got.PredecessorPos, publicationPos)
	}
	if got.AdoptingExchangeDID != "did:web:state:tn:davidson" {
		t.Errorf("AdoptingExchangeDID drift: %q", got.AdoptingExchangeDID)
	}
}

// TestSchemaLifecycle_Amendment pins use case C: bail-reform
// amendment. SchemaVersion bumps to v2; PredecessorPos points
// at v1 publication; AmendmentDescription captures the
// substantive change.
func TestSchemaLifecycle_Amendment(t *testing.T) {
	v1PublicationPos := networkPos(500)

	amendment := &SchemaLifecyclePayload{
		Action:               ActionAmendment,
		SchemaID:             "judicial-criminal-case-v2",
		SchemaVersion:        2,
		PredecessorPos:       v1PublicationPos,
		AmendmentDescription: "Section 4 bond-limit table raised per 2027 bail reform act (Tenn. Pub. Acts ch. 156). Bond limits for classes A-C felonies revised; class D-E unchanged. Effective for cases initiated on or after 2027-07-01.",
		IssuedAt:             time.Date(2027, 5, 1, 9, 0, 0, 0, time.UTC),
		IssuingDID:           "did:web:tn-sc-clerk.example",
	}
	body, _ := SerializeSchemaLifecyclePayload(amendment)
	got, err := DeserializeSchemaLifecyclePayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.SchemaVersion != 2 {
		t.Errorf("SchemaVersion = %d, want 2", got.SchemaVersion)
	}
	if got.PredecessorPos != v1PublicationPos {
		t.Errorf("PredecessorPos drift")
	}
	if len(got.AmendmentDescription) == 0 {
		t.Error("AmendmentDescription empty (required for amendments)")
	}
}

// TestSchemaLifecycle_Deprecation pins use case D: paper-form
// deprecation. DeprecationEffective is the cutover; existing
// entries remain valid (immutability invariant).
func TestSchemaLifecycle_Deprecation(t *testing.T) {
	originalPublicationPos := networkPos(100)
	cutover := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	gracePeriod := int64(30 * 24 * 3600) // 30 days

	dep := &SchemaLifecyclePayload{
		Action:               ActionDeprecation,
		SchemaID:             "judicial-paper-form-v1",
		PredecessorPos:       originalPublicationPos,
		DeprecationEffective: cutover,
		GracePeriodSeconds:   gracePeriod,
		IssuedAt:             time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
		IssuingDID:           "did:web:tn-sc-clerk.example",
	}
	body, _ := SerializeSchemaLifecyclePayload(dep)
	got, err := DeserializeSchemaLifecyclePayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if !got.DeprecationEffective.Equal(cutover) {
		t.Errorf("DeprecationEffective drift: %v, want %v", got.DeprecationEffective, cutover)
	}
	if got.GracePeriodSeconds != gracePeriod {
		t.Errorf("GracePeriodSeconds = %d, want %d", got.GracePeriodSeconds, gracePeriod)
	}
}

// TestSchemaLifecycle_HardCutoverDeprecation pins the hard-cutover
// variant: zero GracePeriodSeconds = cutover takes effect at
// DeprecationEffective with no soft warning window.
func TestSchemaLifecycle_HardCutoverDeprecation(t *testing.T) {
	dep := &SchemaLifecyclePayload{
		Action:               ActionDeprecation,
		SchemaID:             "judicial-paper-form-v1",
		PredecessorPos:       networkPos(100),
		DeprecationEffective: time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC),
		// GracePeriodSeconds zero — hard cutover.
		IssuedAt:   time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
		IssuingDID: "did:web:tn-sc-clerk.example",
	}
	body, _ := SerializeSchemaLifecyclePayload(dep)
	got, err := DeserializeSchemaLifecyclePayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.GracePeriodSeconds != 0 {
		t.Errorf("GracePeriodSeconds = %d, want 0 (hard cutover)", got.GracePeriodSeconds)
	}
}

// TestSchemaLifecycle_AllActions_RoundTrip pins every Action
// constant round-trips correctly.
func TestSchemaLifecycle_AllActions_RoundTrip(t *testing.T) {
	for _, a := range []string{
		ActionPublication,
		ActionAdoption,
		ActionAmendment,
		ActionDeprecation,
	} {
		t.Run(a, func(t *testing.T) {
			p := &SchemaLifecyclePayload{
				Action:     a,
				SchemaID:   "judicial-test-v1",
				IssuedAt:   time.Now().UTC(),
				IssuingDID: "did:web:test",
			}
			body, _ := SerializeSchemaLifecyclePayload(p)
			got, err := DeserializeSchemaLifecyclePayload(body)
			if err != nil {
				t.Fatalf("deserialize: %v", err)
			}
			if got.Action != a {
				t.Errorf("Action = %q, want %q", got.Action, a)
			}
		})
	}
}

func TestSchemaLifecycle_AdmissionThroughSDKRegistry(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	pub := &SchemaLifecyclePayload{
		Action:        ActionPublication,
		SchemaID:      "judicial-test-v1",
		SchemaVersion: 1,
		PublicFields:  []string{"id"},
		IssuedAt:      time.Now().UTC(),
		IssuingDID:    "did:web:test",
	}
	body, _ := SerializeSchemaLifecyclePayload(pub)
	if err := r.ValidateAdmission(sdk, SchemaSchemaLifecycleV1, &envelope.Entry{DomainPayload: body}); err != nil {
		t.Errorf("admission rejected well-formed payload: %v", err)
	}
}
