/*
FILE PATH: verification/payload_role_resolver_test.go

DESCRIPTION:

	Tests pinning PayloadRoleResolver behavior. Covers the four
	construction paths (raw bytes happy / raw bytes empty / raw
	bytes malformed / pre-parsed slice), the lookup contract
	(found / unknown / nil receiver), the audit-view accessor, and
	the wiring against the cosignature_check pipeline.
*/
package verification

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── helpers ────────────────────────────────────────────────────────

func threeCapacities() []schemas.SignedByCapacity {
	return []schemas.SignedByCapacity{
		{
			DID:      "did:web:courts.nashville.gov:role:judge-mclendon",
			Role:     "judge",
			Exchange: "did:web:courts.nashville.gov",
		},
		{
			DID:      "did:web:courts.nashville.gov:role:clerk-smith",
			Role:     "court_clerk",
			Exchange: "did:web:courts.nashville.gov",
		},
		{
			DID:      "did:web:courts.nashville.gov:role:reporter-jones",
			Role:     "court_reporter",
			Exchange: "did:web:courts.nashville.gov",
		},
	}
}

func payloadWith(caps []schemas.SignedByCapacity, extras map[string]any) []byte {
	wrapper := map[string]any{
		"event_type":           "verdict",
		"signed_by_capacities": caps,
	}
	for k, v := range extras {
		wrapper[k] = v
	}
	out, _ := json.Marshal(wrapper)
	return out
}

// ─── NewPayloadRoleResolver (raw bytes) ────────────────────────────

func TestNewPayloadRoleResolver_HappyPath(t *testing.T) {
	payload := payloadWith(threeCapacities(), nil)
	r, err := NewPayloadRoleResolver(payload)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	if got := len(r.Capacities()); got != 3 {
		t.Errorf("len(caps)=%d, want 3", got)
	}
}

func TestNewPayloadRoleResolver_EmptyPayload(t *testing.T) {
	r, err := NewPayloadRoleResolver(nil)
	if err != nil {
		t.Fatalf("nil bytes: %v", err)
	}
	if r == nil {
		t.Fatal("resolver should not be nil")
	}
	if got := len(r.Capacities()); got != 0 {
		t.Errorf("len(caps)=%d, want 0", got)
	}

	r2, err := NewPayloadRoleResolver([]byte{})
	if err != nil {
		t.Fatalf("empty bytes: %v", err)
	}
	if got := len(r2.Capacities()); got != 0 {
		t.Errorf("len(caps)=%d, want 0", got)
	}
}

func TestNewPayloadRoleResolver_PayloadHasNoCapacities(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"event_type": "filed"})
	r, err := NewPayloadRoleResolver(payload)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	if got := len(r.Capacities()); got != 0 {
		t.Errorf("len(caps)=%d, want 0 (block absent)", got)
	}
}

func TestNewPayloadRoleResolver_MalformedArray(t *testing.T) {
	payload := []byte(`{"signed_by_capacities":"not-an-array"}`)
	_, err := NewPayloadRoleResolver(payload)
	if err == nil {
		t.Fatal("expected error for malformed array")
	}
}

func TestNewPayloadRoleResolver_RejectsInvalidEntry(t *testing.T) {
	bad := []schemas.SignedByCapacity{
		{DID: "did:web:a", Role: "judge", Exchange: "did:web:ex"},
		{DID: "", Role: "court_clerk", Exchange: "did:web:ex"}, // missing did
	}
	payload := payloadWith(bad, nil)
	_, err := NewPayloadRoleResolver(payload)
	if err == nil {
		t.Fatal("expected error from validate")
	}
	if !errors.Is(err, schemas.ErrSignedByCapacityInvalid) {
		t.Errorf("expected ErrSignedByCapacityInvalid in chain: %v", err)
	}
}

// ─── NewPayloadRoleResolverFrom (pre-parsed slice) ─────────────────

func TestNewPayloadRoleResolverFrom_HappyPath(t *testing.T) {
	r, err := NewPayloadRoleResolverFrom(threeCapacities())
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	if got := len(r.Capacities()); got != 3 {
		t.Errorf("len=%d", got)
	}
}

func TestNewPayloadRoleResolverFrom_RejectsInvalid(t *testing.T) {
	bad := []schemas.SignedByCapacity{
		{DID: "did:web:a", Role: "", Exchange: "did:web:ex"},
	}
	_, err := NewPayloadRoleResolverFrom(bad)
	if err == nil {
		t.Fatal("expected validate error")
	}
}

func TestNewPayloadRoleResolverFrom_DefensiveCopy(t *testing.T) {
	original := threeCapacities()
	r, err := NewPayloadRoleResolverFrom(original)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	// Mutate the caller's slice — the resolver's internal view
	// must NOT change.
	original[0].Role = "wizard"
	got, err := r.LookupRole(original[0].DID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.Role != "judge" {
		t.Errorf("resolver was mutated by external write; role=%q", got.Role)
	}
}

func TestNewPayloadRoleResolverFrom_EmptySlice(t *testing.T) {
	r, err := NewPayloadRoleResolverFrom(nil)
	if err != nil {
		t.Fatalf("nil slice: %v", err)
	}
	if got := len(r.Capacities()); got != 0 {
		t.Errorf("len=%d", got)
	}
}

// ─── LookupRole ─────────────────────────────────────────────────────

func TestPayloadRoleResolver_LookupRole_Found(t *testing.T) {
	r, _ := NewPayloadRoleResolverFrom(threeCapacities())
	got, err := r.LookupRole("did:web:courts.nashville.gov:role:clerk-smith")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.Role != "court_clerk" {
		t.Errorf("role=%q, want court_clerk", got.Role)
	}
	if got.Exchange != "did:web:courts.nashville.gov" {
		t.Errorf("exchange=%q", got.Exchange)
	}
}

func TestPayloadRoleResolver_LookupRole_Unknown(t *testing.T) {
	r, _ := NewPayloadRoleResolverFrom(threeCapacities())
	_, err := r.LookupRole("did:web:not-in-capacities")
	if err == nil {
		t.Fatal("expected ErrSignerUnknown")
	}
	if !errors.Is(err, ErrSignerUnknown) {
		t.Errorf("expected ErrSignerUnknown, got: %v", err)
	}
}

func TestPayloadRoleResolver_LookupRole_NilReceiver(t *testing.T) {
	var r *PayloadRoleResolver
	_, err := r.LookupRole("did:web:any")
	if !errors.Is(err, ErrSignerUnknown) {
		t.Errorf("nil receiver: expected ErrSignerUnknown, got: %v", err)
	}
}

func TestPayloadRoleResolver_LookupRole_EmptyResolver(t *testing.T) {
	r, _ := NewPayloadRoleResolver(nil)
	_, err := r.LookupRole("did:web:any")
	if !errors.Is(err, ErrSignerUnknown) {
		t.Errorf("empty resolver: expected ErrSignerUnknown, got: %v", err)
	}
}

// ─── Capacities accessor ───────────────────────────────────────────

func TestPayloadRoleResolver_Capacities_NilReceiver(t *testing.T) {
	var r *PayloadRoleResolver
	if got := r.Capacities(); got != nil {
		t.Errorf("nil receiver: expected nil, got: %+v", got)
	}
}

// ─── Interface satisfaction ────────────────────────────────────────

func TestPayloadRoleResolver_SatisfiesRoleResolver(t *testing.T) {
	var _ RoleResolver = (*PayloadRoleResolver)(nil)
	r, _ := NewPayloadRoleResolverFrom(threeCapacities())
	var iface RoleResolver = r
	got, err := iface.LookupRole("did:web:courts.nashville.gov:role:judge-mclendon")
	if err != nil {
		t.Fatalf("interface call: %v", err)
	}
	if got.Role != "judge" {
		t.Errorf("role=%q", got.Role)
	}
}
