/*
FILE PATH: schemas/capacity_test.go

DESCRIPTION:
    Tests pinning the FiledByCapacity contract: closed-set roles,
    structural validation, JSON round-trip, and ExtractFiledByCapacity
    behavior across present / absent / malformed payloads.
*/
package schemas

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// ─── helpers ────────────────────────────────────────────────────────

func validCapacity() *FiledByCapacity {
	return &FiledByCapacity{
		Actor: ActorFiler,
		Role:  FilerRoleDefenseCounsel,
		DID:   "did:key:zQ3shATTORNEY",
		Credentials: map[string]string{
			"bpr_number":   "TN-12345",
			"jurisdiction": "TN",
			"firm":         "Smith & Jones LLP",
		},
		SwornAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// ─── FilerRole closed set ───────────────────────────────────────────

func TestFilerRole_IsValid(t *testing.T) {
	for _, r := range []FilerRole{
		FilerRoleProsecutor, FilerRoleDefenseCounsel,
		FilerRoleCivilAttorney, FilerRoleFiduciary,
		FilerRoleGuardianAdLitem,
	} {
		if !r.IsValid() {
			t.Errorf("%q must be valid", r)
		}
	}
	for _, r := range []FilerRole{"", "wizard", "lawyer", "judge"} {
		if r.IsValid() {
			t.Errorf("%q must NOT be valid", r)
		}
	}
}

// ─── Validate ───────────────────────────────────────────────────────

func TestFiledByCapacity_Validate_HappyPath(t *testing.T) {
	if err := validCapacity().Validate(); err != nil {
		t.Errorf("happy path: %v", err)
	}
}

func TestFiledByCapacity_Validate_NilCapacity(t *testing.T) {
	var c *FiledByCapacity
	err := c.Validate()
	if err == nil || !errors.Is(err, ErrCapacityInvalid) {
		t.Errorf("nil capacity: %v", err)
	}
}

func TestFiledByCapacity_Validate_RejectsActorSigner(t *testing.T) {
	c := validCapacity()
	c.Actor = ActorSigner
	err := c.Validate()
	if !errors.Is(err, ErrCapacityWrongActor) {
		t.Errorf("expected ErrCapacityWrongActor, got: %v", err)
	}
}

func TestFiledByCapacity_Validate_RejectsActorParty(t *testing.T) {
	c := validCapacity()
	c.Actor = ActorParty
	err := c.Validate()
	if !errors.Is(err, ErrCapacityWrongActor) {
		t.Errorf("expected ErrCapacityWrongActor, got: %v", err)
	}
}

func TestFiledByCapacity_Validate_RejectsActorUnspecified(t *testing.T) {
	c := validCapacity()
	c.Actor = ActorUnspecified
	err := c.Validate()
	if !errors.Is(err, ErrCapacityWrongActor) {
		t.Errorf("expected ErrCapacityWrongActor, got: %v", err)
	}
}

func TestFiledByCapacity_Validate_RejectsUnknownRole(t *testing.T) {
	c := validCapacity()
	c.Role = "wizard"
	err := c.Validate()
	if !errors.Is(err, ErrCapacityUnknownRole) {
		t.Errorf("expected ErrCapacityUnknownRole, got: %v", err)
	}
}

func TestFiledByCapacity_Validate_RejectsEmptyRole(t *testing.T) {
	c := validCapacity()
	c.Role = ""
	err := c.Validate()
	if !errors.Is(err, ErrCapacityUnknownRole) {
		t.Errorf("expected ErrCapacityUnknownRole, got: %v", err)
	}
}

func TestFiledByCapacity_Validate_RejectsEmptyDID(t *testing.T) {
	c := validCapacity()
	c.DID = ""
	err := c.Validate()
	if !errors.Is(err, ErrCapacityInvalid) {
		t.Errorf("expected ErrCapacityInvalid, got: %v", err)
	}
	if !strings.Contains(err.Error(), "did required") {
		t.Errorf("err should mention did: %v", err)
	}
}

func TestFiledByCapacity_Validate_RejectsEmptySwornAt(t *testing.T) {
	c := validCapacity()
	c.SwornAt = ""
	err := c.Validate()
	if !errors.Is(err, ErrCapacityInvalid) || !strings.Contains(err.Error(), "sworn_at") {
		t.Errorf("expected sworn_at error, got: %v", err)
	}
}

func TestFiledByCapacity_Validate_RejectsMalformedSwornAt(t *testing.T) {
	c := validCapacity()
	c.SwornAt = "yesterday"
	err := c.Validate()
	if !errors.Is(err, ErrCapacityInvalid) || !strings.Contains(err.Error(), "sworn_at") {
		t.Errorf("expected sworn_at error, got: %v", err)
	}
}

// ─── HasCredential ──────────────────────────────────────────────────

func TestFiledByCapacity_HasCredential(t *testing.T) {
	c := validCapacity()
	if !c.HasCredential("bpr_number") {
		t.Error("bpr_number should be present")
	}
	if c.HasCredential("ssn") {
		t.Error("ssn must not be present")
	}

	// Empty value reads as missing.
	c.Credentials["empty"] = ""
	if c.HasCredential("empty") {
		t.Error("empty value should read as missing")
	}

	// nil capacity / nil map.
	var nilCap *FiledByCapacity
	if nilCap.HasCredential("anything") {
		t.Error("nil capacity should HasCredential=false")
	}
	c2 := &FiledByCapacity{}
	if c2.HasCredential("x") {
		t.Error("nil credentials map should HasCredential=false")
	}
}

// ─── Marshal / Round-trip ──────────────────────────────────────────

func TestMarshalFiledByCapacity_RoundTrip(t *testing.T) {
	original := validCapacity()
	data, err := MarshalFiledByCapacity(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got FiledByCapacity
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.DID != original.DID {
		t.Errorf("did drift: %q", got.DID)
	}
	if got.Role != original.Role {
		t.Errorf("role drift: %q", got.Role)
	}
	if got.Actor != original.Actor {
		t.Errorf("actor drift: %s", got.Actor)
	}
	if got.Credentials["bpr_number"] != "TN-12345" {
		t.Errorf("creds drift: %v", got.Credentials)
	}
}

func TestMarshalFiledByCapacity_RejectsInvalid(t *testing.T) {
	c := validCapacity()
	c.Role = "wizard"
	_, err := MarshalFiledByCapacity(c)
	if !errors.Is(err, ErrCapacityUnknownRole) {
		t.Errorf("expected validate failure, got: %v", err)
	}
}

// ─── ExtractFiledByCapacity ────────────────────────────────────────

func TestExtractFiledByCapacity_PayloadHasCapacity(t *testing.T) {
	cap := validCapacity()
	wrapper := map[string]any{
		"event_type":        "motion_continuance",
		"filed_by_capacity": cap,
	}
	payload, _ := json.Marshal(wrapper)

	got, present, err := ExtractFiledByCapacity(payload)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if !present {
		t.Fatal("present should be true")
	}
	if got.DID != cap.DID {
		t.Errorf("did drift: %q", got.DID)
	}
	if got.Role != cap.Role {
		t.Errorf("role drift: %q", got.Role)
	}
}

func TestExtractFiledByCapacity_PayloadHasNoCapacity(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"event_type": "verdict",
		"some_field": "some_value",
	})
	got, present, err := ExtractFiledByCapacity(payload)
	if err != nil {
		t.Errorf("expected nil err, got: %v", err)
	}
	if present {
		t.Error("present should be false (no capacity in payload)")
	}
	if got != nil {
		t.Errorf("got should be nil, got: %+v", got)
	}
}

func TestExtractFiledByCapacity_EmptyPayload(t *testing.T) {
	got, present, err := ExtractFiledByCapacity(nil)
	if err != nil || present || got != nil {
		t.Errorf("nil payload: got=%v present=%v err=%v", got, present, err)
	}
	got, present, err = ExtractFiledByCapacity([]byte{})
	if err != nil || present || got != nil {
		t.Errorf("empty payload: got=%v present=%v err=%v", got, present, err)
	}
}

func TestExtractFiledByCapacity_NotJSONPayload(t *testing.T) {
	// Non-JSON payload should fail-soft to (nil, false, nil) — many
	// log entries carry opaque bytes; the verifier doesn't care.
	got, present, err := ExtractFiledByCapacity([]byte("not json"))
	if err != nil || present || got != nil {
		t.Errorf("not-json payload: got=%v present=%v err=%v", got, present, err)
	}
}

func TestExtractFiledByCapacity_MalformedCapacityBlock(t *testing.T) {
	// Payload has filed_by_capacity but it's not a parseable
	// FiledByCapacity (e.g., a string instead of an object). This
	// IS an error — the writer attempted a capacity claim but the
	// shape is wrong.
	payload := []byte(`{"filed_by_capacity": "not-an-object"}`)
	got, present, err := ExtractFiledByCapacity(payload)
	if err == nil {
		t.Fatalf("expected error, got: present=%v got=%v", present, got)
	}
	if !errors.Is(err, ErrCapacityInvalid) {
		t.Errorf("expected ErrCapacityInvalid, got: %v", err)
	}
}

// ─── round-trip via Extract ────────────────────────────────────────

func TestExtractFiledByCapacity_RoundTripWithMarshal(t *testing.T) {
	cap := validCapacity()
	capBytes, _ := MarshalFiledByCapacity(cap)
	wrapper := json.RawMessage(`{"event_type":"motion_continuance","filed_by_capacity":` +
		string(capBytes) + `}`)

	got, present, err := ExtractFiledByCapacity(wrapper)
	if err != nil || !present {
		t.Fatalf("extract: %v present=%v", err, present)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("extracted capacity should validate: %v", err)
	}
}
