/*
FILE PATH: schemas/counsel_appearance_test.go

DESCRIPTION:

	Tests for the tn-counsel-appearance-v1 schema. Two layers:

	  1. Unit-level invariants
	     - Validate accepts the canonical happy-path payload.
	     - Validate rejects every malformed shape.
	     - Serialize/Deserialize round-trip.
	     - Status default to "active" on empty.

	  2. Functional emulation
	     - "Defense counsel files appearance for one defendant."
	     - "Defense counsel represents two co-defendants."
	     - "Civil attorney represents the plaintiff."
	     - "Counsel withdraws by amending status to withdrawn."

	The functional tests exercise the schema as it would be
	used in a real submission flow — building the payload,
	validating it, and round-tripping JSON.
*/
package schemas

import (
	"errors"
	"strings"
	"testing"
)

// ─── happy-path constructor used across tests ─────────────────────

func happyAppearance() *CounselAppearancePayload {
	return &CounselAppearancePayload{
		AppearanceID: "ap-001",
		AttorneyDID:  "did:key:zQ3shATTORNEY",
		Represents:   []string{"d-001"},
		CaseRef:      "DAV-2026-CV-0001",
		Status:       "active",
	}
}

// ─── unit tests: Validate happy + every rejection path ───────────

func TestCAValidate_HappyPath(t *testing.T) {
	if err := happyAppearance().Validate(); err != nil {
		t.Errorf("happy path must validate: %v", err)
	}
}

func TestCAValidate_NilReceiver(t *testing.T) {
	var p *CounselAppearancePayload
	if err := p.Validate(); !errors.Is(err, ErrCounselAppearanceInvalid) {
		t.Errorf("nil receiver: want ErrCounselAppearanceInvalid, got %v", err)
	}
}

func TestCAValidate_MissingAppearanceID(t *testing.T) {
	p := happyAppearance()
	p.AppearanceID = ""
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "appearance_id required") {
		t.Errorf("missing appearance_id should be rejected, got %v", err)
	}
}

func TestCAValidate_MissingAttorneyDID(t *testing.T) {
	p := happyAppearance()
	p.AttorneyDID = ""
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "attorney_did required") {
		t.Errorf("missing attorney_did should be rejected, got %v", err)
	}
}

func TestCAValidate_EmptyRepresents(t *testing.T) {
	p := happyAppearance()
	p.Represents = nil
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "represents must list") {
		t.Errorf("empty represents should be rejected, got %v", err)
	}
}

func TestCAValidate_EmptyBindingIDInRepresents(t *testing.T) {
	p := happyAppearance()
	p.Represents = []string{"d-001", ""}
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "represents[1]") {
		t.Errorf("empty binding_id in represents should be rejected, got %v",
			err)
	}
}

func TestCAValidate_MissingCaseRef(t *testing.T) {
	p := happyAppearance()
	p.CaseRef = ""
	if err := p.Validate(); err == nil ||
		!strings.Contains(err.Error(), "case_ref required") {
		t.Errorf("missing case_ref should be rejected, got %v", err)
	}
}

func TestCAValidate_StatusEnum(t *testing.T) {
	for _, ok := range []string{"", "active", "withdrawn"} {
		p := happyAppearance()
		p.Status = ok
		if err := p.Validate(); err != nil {
			t.Errorf("status %q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"pending", "ACTIVE", "withdrawn_partial", "x"} {
		p := happyAppearance()
		p.Status = bad
		if err := p.Validate(); err == nil ||
			!strings.Contains(err.Error(), "status") {
			t.Errorf("invalid status %q should be rejected, got %v", bad, err)
		}
	}
}

// ─── serialize round-trip ────────────────────────────────────────

func TestCASerialize_DefaultsStatusActive(t *testing.T) {
	p := happyAppearance()
	p.Status = ""
	data, err := SerializeCounselAppearancePayload(p)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	got, err := DeserializeCounselAppearancePayload(data)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.Status != "active" {
		t.Errorf("Status default drift: want active, got %q", got.Status)
	}
}

func TestCASerializeDeserialize_RoundTrip(t *testing.T) {
	p := happyAppearance()
	data, err := SerializeCounselAppearancePayload(p)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	got, err := DeserializeCounselAppearancePayload(data)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if got.AppearanceID != p.AppearanceID ||
		got.AttorneyDID != p.AttorneyDID ||
		got.CaseRef != p.CaseRef ||
		len(got.Represents) != len(p.Represents) {
		t.Errorf("round-trip drift: got %+v want %+v", got, p)
	}
}

func TestCASerialize_NilPayload(t *testing.T) {
	if _, err := SerializeCounselAppearancePayload(nil); err == nil {
		t.Error("nil payload must reject on Serialize")
	}
}

func TestCASerialize_RejectsInvalidPayload(t *testing.T) {
	// Non-nil but Validate-failing payload exercises the error
	// path inside Serialize (after the nil check, before
	// Marshal). 100% coverage on Serialize.
	p := happyAppearance()
	p.AppearanceID = ""
	if _, err := SerializeCounselAppearancePayload(p); err == nil {
		t.Error("invalid payload must reject on Serialize")
	}
}

func TestCADeserialize_BadJSON(t *testing.T) {
	if _, err := DeserializeCounselAppearancePayload([]byte("not json")); err == nil {
		t.Error("malformed JSON must reject on Deserialize")
	}
}

func TestCADeserialize_FailsValidate(t *testing.T) {
	// Valid JSON, missing required fields → fails Validate.
	bad := []byte(`{"appearance_id":"","attorney_did":"x"}`)
	if _, err := DeserializeCounselAppearancePayload(bad); err == nil {
		t.Error("payload missing required fields must reject on Deserialize")
	}
}

// ─── default params ───────────────────────────────────────────────

func TestCADefaultCounselAppearanceParams_Parses(t *testing.T) {
	b := DefaultCounselAppearanceParams()
	if len(b) == 0 {
		t.Error("DefaultCounselAppearanceParams returned empty bytes")
	}
}

// ─── registry round-trip ─────────────────────────────────────────

func TestCARegistry_LookupCounselAppearance(t *testing.T) {
	r := NewRegistry()
	reg, err := r.Lookup(SchemaCounselAppearanceV1)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if reg.URI != SchemaCounselAppearanceV1 {
		t.Errorf("URI drift: got %q want %q",
			reg.URI, SchemaCounselAppearanceV1)
	}
	if reg.IdentifierScope != IdentifierScopeRealDID {
		t.Errorf("IdentifierScope drift: got %q", reg.IdentifierScope)
	}
}

func TestCARegistry_SerializeDeserialize_ViaInterface(t *testing.T) {
	r := NewRegistry()
	reg, err := r.Lookup(SchemaCounselAppearanceV1)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	p := happyAppearance()
	data, err := reg.Serialize(p)
	if err != nil {
		t.Fatalf("Serialize via registry: %v", err)
	}
	got, err := reg.Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize via registry: %v", err)
	}
	gp, ok := got.(*CounselAppearancePayload)
	if !ok {
		t.Fatalf("Deserialize returned %T, want *CounselAppearancePayload", got)
	}
	if gp.AppearanceID != p.AppearanceID {
		t.Errorf("registry round-trip drift: %+v", gp)
	}
}

func TestCARegistry_Serialize_WrongType(t *testing.T) {
	r := NewRegistry()
	reg, err := r.Lookup(SchemaCounselAppearanceV1)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if _, err := reg.Serialize("not a payload struct"); err == nil {
		t.Error("Serialize must reject wrong payload type")
	}
}

// Functional-emulation tests live in
// counsel_appearance_functional_test.go to keep this file under
// the 300-line cap.
