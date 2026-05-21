package verification

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
)

func TestWitnessSetRegistry_GetSnapshotLen(t *testing.T) {
	w := newVGWitnesses(t, 3, 2)
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": w.set}, w.nid)

	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1", r.Len())
	}
	got, ok := r.Get("did:log")
	if !ok || got != w.set {
		t.Fatal("Get(did:log) mismatch")
	}
	if _, ok := r.Get("did:nope"); ok {
		t.Fatal("unknown log should miss")
	}
	// Mutating a snapshot must not affect the registry.
	snap := r.Snapshot()
	if snap["did:log"] != w.set {
		t.Fatal("snapshot missing seeded set")
	}
	snap["injected"] = nil
	if r.Len() != 1 {
		t.Fatal("snapshot mutation leaked into registry")
	}
}

func TestWitnessSetRegistry_ApplyRotation_HappyPath(t *testing.T) {
	cur := newVGWitnesses(t, 3, 2)
	next := newVGWitnesses(t, 3, 2) // fresh keys
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": cur.set}, cur.nid)

	if err := r.ApplyRotation("did:log", cur.buildRotation(t, next.keys), 2); err != nil {
		t.Fatalf("ApplyRotation: %v", err)
	}
	got, _ := r.Get("did:log")
	if got == cur.set {
		t.Fatal("witness set not swapped after valid rotation")
	}
	if got.Size() != 3 || got.Quorum() != 2 {
		t.Fatalf("rotated set size=%d quorum=%d, want 3/2", got.Size(), got.Quorum())
	}
}

// The zero-trust invariant: a rotation that does NOT verify against the current
// set must leave trust completely unchanged.
func TestWitnessSetRegistry_ApplyRotation_BogusLeavesTrustUnchanged(t *testing.T) {
	cur := newVGWitnesses(t, 3, 2)
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": cur.set}, cur.nid)

	bogus := types.WitnessRotation{
		CurrentSetHash:    [32]byte{0xDE, 0xAD}, // wrong hash → fails verify-before-swap
		NewSet:            cur.keys,
		SchemeTagOld:      signatures.SchemeECDSA,
		CurrentSignatures: []types.WitnessSignature{{PubKeyID: [32]byte{0x01}, SchemeTag: signatures.SchemeECDSA, SigBytes: []byte{0xAA}}},
		SchemeTagNew:      signatures.SchemeECDSA,
	}
	if err := r.ApplyRotation("did:log", bogus, 2); !errors.Is(err, ErrWitnessRegistry) {
		t.Fatalf("err = %v, want ErrWitnessRegistry", err)
	}
	if got, _ := r.Get("did:log"); got != cur.set {
		t.Fatal("trust mutated despite a failed rotation")
	}
}

// A stale rotation that was valid against an OLDER set must not re-apply once
// the set has moved on (monotonicity — no revert to a superseded set).
func TestWitnessSetRegistry_ApplyRotation_StaleRotationRejected(t *testing.T) {
	gen := newVGWitnesses(t, 3, 2)
	next := newVGWitnesses(t, 3, 2)
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": gen.set}, gen.nid)

	staleRot := gen.buildRotation(t, next.keys) // valid against gen
	if err := r.ApplyRotation("did:log", staleRot, 2); err != nil {
		t.Fatalf("first ApplyRotation: %v", err)
	}
	// Set is now `next`. Replaying the gen→next rotation must fail: its
	// CurrentSetHash pins `gen`, which is no longer current.
	if err := r.ApplyRotation("did:log", staleRot, 2); !errors.Is(err, ErrWitnessRegistry) {
		t.Fatalf("stale replay err = %v, want ErrWitnessRegistry", err)
	}
}

func TestWitnessSetRegistry_ApplyRotation_UnknownLog(t *testing.T) {
	cur := newVGWitnesses(t, 1, 1)
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": cur.set}, cur.nid)
	if err := r.ApplyRotation("did:other", cur.buildRotation(t, cur.keys), 1); !errors.Is(err, ErrWitnessRegistry) {
		t.Fatalf("err = %v, want ErrWitnessRegistry", err)
	}
}
