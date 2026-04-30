/*
FILE PATH: schemas/signed_by_capacity_test.go

DESCRIPTION:
    Tests pinning the SignedByCapacity contract: structural
    validation, JSON round-trip, ExtractSignedByCapacities behavior
    across present / absent / malformed payloads, and per-DID lookup.

    These tests are the writer-side mirror of capacity_test.go and
    cement the v1.6 symmetric-payload guarantee: every cosigner
    other than the primary signer is self-described in the payload.
*/
package schemas

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ─── helpers ────────────────────────────────────────────────────────

func validSignedByCapacity() *SignedByCapacity {
	return &SignedByCapacity{
		DID:      "did:web:courts.nashville.gov:role:clerk-smith",
		Role:     "court_clerk",
		Exchange: "did:web:courts.nashville.gov",
		DelegationRef: &LogPositionRef{
			LogDID:   "did:web:courts.nashville.gov:delegations",
			Sequence: 42,
		},
	}
}

// ─── Validate ───────────────────────────────────────────────────────

func TestSignedByCapacity_Validate_HappyPath(t *testing.T) {
	if err := validSignedByCapacity().Validate(); err != nil {
		t.Errorf("happy path: %v", err)
	}
}

func TestSignedByCapacity_Validate_HappyPath_NoDelegationRef(t *testing.T) {
	c := validSignedByCapacity()
	c.DelegationRef = nil
	if err := c.Validate(); err != nil {
		t.Errorf("delegation_ref is optional at this layer: %v", err)
	}
}

func TestSignedByCapacity_Validate_NilCapacity(t *testing.T) {
	var c *SignedByCapacity
	err := c.Validate()
	if err == nil || !errors.Is(err, ErrSignedByCapacityInvalid) {
		t.Errorf("nil capacity: %v", err)
	}
}

func TestSignedByCapacity_Validate_RejectsEmptyDID(t *testing.T) {
	c := validSignedByCapacity()
	c.DID = ""
	err := c.Validate()
	if !errors.Is(err, ErrSignedByCapacityInvalid) ||
		!strings.Contains(err.Error(), "did") {
		t.Errorf("expected did-required error, got: %v", err)
	}
}

func TestSignedByCapacity_Validate_RejectsEmptyRole(t *testing.T) {
	c := validSignedByCapacity()
	c.Role = ""
	err := c.Validate()
	if !errors.Is(err, ErrSignedByCapacityInvalid) ||
		!strings.Contains(err.Error(), "role") {
		t.Errorf("expected role-required error, got: %v", err)
	}
}

func TestSignedByCapacity_Validate_RejectsEmptyExchange(t *testing.T) {
	c := validSignedByCapacity()
	c.Exchange = ""
	err := c.Validate()
	if !errors.Is(err, ErrSignedByCapacityInvalid) ||
		!strings.Contains(err.Error(), "exchange") {
		t.Errorf("expected exchange-required error, got: %v", err)
	}
}

// ─── Marshal / Round-trip ──────────────────────────────────────────

func TestMarshalSignedByCapacities_RoundTrip(t *testing.T) {
	original := []SignedByCapacity{
		*validSignedByCapacity(),
		{
			DID:      "did:web:courts.nashville.gov:role:reporter-jones",
			Role:     "court_reporter",
			Exchange: "did:web:courts.nashville.gov",
		},
	}

	data, err := MarshalSignedByCapacities(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got []SignedByCapacity
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].DID != original[0].DID {
		t.Errorf("did drift: %q", got[0].DID)
	}
	if got[0].DelegationRef == nil ||
		got[0].DelegationRef.Sequence != 42 {
		t.Errorf("delegation_ref drift: %+v", got[0].DelegationRef)
	}
	if got[1].DelegationRef != nil {
		t.Errorf("entry 2 should have nil delegation_ref, got: %+v",
			got[1].DelegationRef)
	}
}

func TestMarshalSignedByCapacities_RejectsInvalid(t *testing.T) {
	caps := []SignedByCapacity{
		*validSignedByCapacity(),
		{DID: "did:web:bad", Role: "", Exchange: "did:web:x"}, // empty role
	}
	_, err := MarshalSignedByCapacities(caps)
	if err == nil || !errors.Is(err, ErrSignedByCapacityInvalid) {
		t.Errorf("expected validation failure on entry[1]: %v", err)
	}
	if !strings.Contains(err.Error(), "[1]") {
		t.Errorf("error should identify the bad index: %v", err)
	}
}

func TestMarshalSignedByCapacities_EmptySlice(t *testing.T) {
	data, err := MarshalSignedByCapacities(nil)
	if err != nil {
		t.Errorf("nil slice should marshal cleanly: %v", err)
	}
	if string(data) != "null" && string(data) != "[]" {
		t.Errorf("expected null/empty, got: %s", string(data))
	}
}

// ─── ExtractSignedByCapacities ─────────────────────────────────────

func TestExtractSignedByCapacities_PayloadHasCapacities(t *testing.T) {
	caps := []SignedByCapacity{*validSignedByCapacity()}
	wrapper := map[string]any{
		"event_type":           "motion_continuance",
		"signed_by_capacities": caps,
	}
	payload, _ := json.Marshal(wrapper)

	got, present, err := ExtractSignedByCapacities(payload)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if !present {
		t.Fatal("present should be true")
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].DID != caps[0].DID {
		t.Errorf("did drift: %q", got[0].DID)
	}
}

func TestExtractSignedByCapacities_PayloadHasNoCapacities(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"event_type": "verdict",
		"some_field": "some_value",
	})
	got, present, err := ExtractSignedByCapacities(payload)
	if err != nil {
		t.Errorf("expected nil err, got: %v", err)
	}
	if present {
		t.Error("present should be false (no signed_by_capacities)")
	}
	if got != nil {
		t.Errorf("got should be nil, got: %+v", got)
	}
}

func TestExtractSignedByCapacities_EmptyPayload(t *testing.T) {
	got, present, err := ExtractSignedByCapacities(nil)
	if err != nil || present || got != nil {
		t.Errorf("nil payload: got=%v present=%v err=%v",
			got, present, err)
	}
	got, present, err = ExtractSignedByCapacities([]byte{})
	if err != nil || present || got != nil {
		t.Errorf("empty payload: got=%v present=%v err=%v",
			got, present, err)
	}
}

func TestExtractSignedByCapacities_NotJSONPayload(t *testing.T) {
	got, present, err := ExtractSignedByCapacities([]byte("not json"))
	if err != nil || present || got != nil {
		t.Errorf("not-json payload: got=%v present=%v err=%v",
			got, present, err)
	}
}

func TestExtractSignedByCapacities_MalformedArray(t *testing.T) {
	// Payload has signed_by_capacities but it's a string, not an array.
	payload := []byte(`{"signed_by_capacities":"not-an-array"}`)
	got, present, err := ExtractSignedByCapacities(payload)
	if err == nil {
		t.Fatalf("expected error, got: present=%v got=%v",
			present, got)
	}
	if !errors.Is(err, ErrSignedByCapacityInvalid) {
		t.Errorf("expected ErrSignedByCapacityInvalid, got: %v", err)
	}
}

// ─── FindSignedByCapacity ──────────────────────────────────────────

func TestFindSignedByCapacity_Found(t *testing.T) {
	caps := []SignedByCapacity{
		{DID: "did:web:a", Role: "judge", Exchange: "did:web:ex"},
		{DID: "did:web:b", Role: "court_clerk", Exchange: "did:web:ex"},
		{DID: "did:web:c", Role: "court_reporter", Exchange: "did:web:ex"},
	}
	got := FindSignedByCapacity(caps, "did:web:b")
	if got == nil {
		t.Fatal("expected to find did:web:b")
	}
	if got.Role != "court_clerk" {
		t.Errorf("role drift: %q", got.Role)
	}
}

func TestFindSignedByCapacity_NotFound(t *testing.T) {
	caps := []SignedByCapacity{
		{DID: "did:web:a", Role: "judge", Exchange: "did:web:ex"},
	}
	if got := FindSignedByCapacity(caps, "did:web:missing"); got != nil {
		t.Errorf("expected nil, got: %+v", got)
	}
}

func TestFindSignedByCapacity_EmptySlice(t *testing.T) {
	if got := FindSignedByCapacity(nil, "did:web:any"); got != nil {
		t.Errorf("nil slice should return nil, got: %+v", got)
	}
	if got := FindSignedByCapacity([]SignedByCapacity{}, "did:web:any"); got != nil {
		t.Errorf("empty slice should return nil, got: %+v", got)
	}
}

// ─── round-trip via Extract ────────────────────────────────────────

func TestExtractSignedByCapacities_RoundTripWithMarshal(t *testing.T) {
	caps := []SignedByCapacity{*validSignedByCapacity()}
	capBytes, _ := MarshalSignedByCapacities(caps)
	wrapper := json.RawMessage(`{"event_type":"motion_continuance",` +
		`"signed_by_capacities":` + string(capBytes) + `}`)

	got, present, err := ExtractSignedByCapacities(wrapper)
	if err != nil || !present {
		t.Fatalf("extract: %v present=%v", err, present)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if err := got[0].Validate(); err != nil {
		t.Errorf("extracted capacity should validate: %v", err)
	}
}
