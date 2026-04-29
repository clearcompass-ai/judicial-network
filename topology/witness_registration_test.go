/*
FILE PATH: topology/witness_registration_test.go

COVERAGE:
    Every code path in witness_registration.go has at least one
    assertion that fails for a distinct reason. Auditor invocations
    are pinned at every state-changing transition so a future
    refactor that drops audit emission breaks here, not in production.
*/
package topology

import (
	"errors"
	"sync"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─── Test helpers ───────────────────────────────────────────────────

// countingAuditor records every call so tests can assert that every
// state-changing operation produced exactly one audit event.
type countingAuditor struct {
	mu      sync.Mutex
	admits  []types.WitnessPublicKey
	revokes []types.WitnessPublicKey
	rejects []rejectRecord
}

type rejectRecord struct {
	id     [32]byte
	reason error
}

func (c *countingAuditor) OnAdmit(w types.WitnessPublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.admits = append(c.admits, w)
}

func (c *countingAuditor) OnRevoke(w types.WitnessPublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revokes = append(c.revokes, w)
}

func (c *countingAuditor) OnReject(id [32]byte, reason error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rejects = append(c.rejects, rejectRecord{id: id, reason: reason})
}

// makeWitness generates a valid (id, pubKey, pop) triple.
func makeWitness(t *testing.T, id [32]byte) ([32]byte, []byte, []byte) {
	t.Helper()
	sk, pk, err := signatures.GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}
	pop, err := signatures.SignBLSPoP(pk, sk)
	if err != nil {
		t.Fatalf("SignBLSPoP: %v", err)
	}
	return id, signatures.BLSPubKeyBytes(pk), pop
}

func id32(seed byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = seed
	}
	return out
}

// ─── Register: happy path ──────────────────────────────────────────

func TestRegister_ValidPoP_Admitted(t *testing.T) {
	auditor := &countingAuditor{}
	r := NewWitnessRegistry(auditor)

	id, pub, pop := makeWitness(t, id32(0x01))
	if err := r.Register(id, pub, pop); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if r.Size() != 1 {
		t.Errorf("Size = %d, want 1", r.Size())
	}
	if len(auditor.admits) != 1 {
		t.Errorf("admits = %d, want 1", len(auditor.admits))
	}
	if len(auditor.rejects) != 0 {
		t.Errorf("rejects = %d, want 0", len(auditor.rejects))
	}
	got, ok := r.Lookup(id)
	if !ok {
		t.Fatal("Lookup: id not found after Register")
	}
	if string(got.PublicKey) != string(pub) {
		t.Error("Lookup PublicKey mismatch")
	}
}

// ─── Register: nil auditor → no-op default ──────────────────────────

func TestRegister_NilAuditor_NoOpDefault(t *testing.T) {
	// Exercise admit, revoke, and reject paths through the noop
	// auditor to confirm none panics and the registry state is
	// consistent. This is the contract NewWitnessRegistry(nil) makes.
	r := NewWitnessRegistry(nil)

	id, pub, pop := makeWitness(t, id32(0x02))
	if err := r.Register(id, pub, pop); err != nil { // exercises noopAuditor.OnAdmit
		t.Fatalf("Register: %v", err)
	}
	if r.Size() != 1 {
		t.Errorf("Size = %d", r.Size())
	}

	// Drive a rejection — empty pubkey — so noopAuditor.OnReject
	// fires without panic.
	if err := r.Register(id32(0xFE), nil, nil); err == nil {
		t.Fatal("expected length-mismatch rejection")
	}

	if err := r.Revoke(id); err != nil { // exercises noopAuditor.OnRevoke
		t.Fatalf("Revoke: %v", err)
	}
	if r.Size() != 0 {
		t.Errorf("Size = %d after revoke, want 0", r.Size())
	}
}

// ─── Register: invalid lengths rejected before any crypto ──────────

func TestRegister_PubKeyWrongLength_Rejected(t *testing.T) {
	auditor := &countingAuditor{}
	r := NewWitnessRegistry(auditor)

	id := id32(0x03)
	err := r.Register(id, make([]byte, 95), make([]byte, signatures.BLSG1CompressedLen))
	if err == nil {
		t.Fatal("expected error for short pubkey")
	}
	if !errors.Is(err, ErrInvalidPubKeyLength) {
		t.Errorf("err = %v, want ErrInvalidPubKeyLength", err)
	}
	if r.Size() != 0 {
		t.Error("registry must remain empty after rejection")
	}
	if len(auditor.rejects) != 1 {
		t.Errorf("rejects = %d, want 1", len(auditor.rejects))
	}
}

func TestRegister_PoPWrongLength_Rejected(t *testing.T) {
	auditor := &countingAuditor{}
	r := NewWitnessRegistry(auditor)

	id, pub, _ := makeWitness(t, id32(0x04))
	err := r.Register(id, pub, make([]byte, 47))
	if err == nil {
		t.Fatal("expected error for short pop")
	}
	if !errors.Is(err, ErrInvalidPoPLength) {
		t.Errorf("err = %v, want ErrInvalidPoPLength", err)
	}
	if len(auditor.rejects) != 1 {
		t.Errorf("rejects = %d, want 1", len(auditor.rejects))
	}
}

// ─── Register: bad PoP rejected by VerifyBLSPoP ────────────────────

func TestRegister_TamperedPoP_Rejected(t *testing.T) {
	auditor := &countingAuditor{}
	r := NewWitnessRegistry(auditor)

	id, pub, pop := makeWitness(t, id32(0x05))
	pop[0] ^= 0xFF // tamper

	err := r.Register(id, pub, pop)
	if err == nil {
		t.Fatal("expected PoP verification to fail")
	}
	if !errors.Is(err, ErrPoPVerifyFailed) {
		t.Errorf("err = %v, want ErrPoPVerifyFailed", err)
	}
	if r.Size() != 0 {
		t.Error("registry must remain empty after PoP failure")
	}
	if len(auditor.rejects) != 1 || len(auditor.admits) != 0 {
		t.Errorf("audit counts off: rejects=%d admits=%d",
			len(auditor.rejects), len(auditor.admits))
	}
}

// ─── Register: PoP for a different key rejected (rogue-key defense) ─

func TestRegister_PoPFromDifferentKey_Rejected(t *testing.T) {
	auditor := &countingAuditor{}
	r := NewWitnessRegistry(auditor)

	idA, pubA, _ := makeWitness(t, id32(0x06))
	_, _, popB := makeWitness(t, id32(0x07))

	err := r.Register(idA, pubA, popB)
	if err == nil {
		t.Fatal("expected rejection of cross-key PoP")
	}
	if !errors.Is(err, ErrPoPVerifyFailed) {
		t.Errorf("err = %v, want ErrPoPVerifyFailed", err)
	}
}

// ─── Register: malformed pubkey bytes rejected at parse ─────────────

func TestRegister_MalformedPubKey_Rejected(t *testing.T) {
	auditor := &countingAuditor{}
	r := NewWitnessRegistry(auditor)

	id := id32(0x08)
	bogus := make([]byte, signatures.BLSG2CompressedLen) // all zeros, not a valid point
	bogus[0] = 0xFF                                      // make it definitively garbage
	pop := make([]byte, signatures.BLSG1CompressedLen)

	err := r.Register(id, bogus, pop)
	if err == nil {
		t.Fatal("expected error for malformed pubkey")
	}
	if !errors.Is(err, ErrPoPVerifyFailed) {
		t.Errorf("err = %v, want ErrPoPVerifyFailed (parse-pubkey wraps it)", err)
	}
}

// ─── Register: duplicate ID rejected after PoP verification ─────────

func TestRegister_DuplicateID_Rejected(t *testing.T) {
	auditor := &countingAuditor{}
	r := NewWitnessRegistry(auditor)

	id, pub, pop := makeWitness(t, id32(0x09))
	if err := r.Register(id, pub, pop); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	// Second registration of same ID with a freshly-generated
	// (different) key+PoP — PoP verifies, but ID is taken.
	_, pub2, pop2 := makeWitness(t, id)
	err := r.Register(id, pub2, pop2)
	if err == nil {
		t.Fatal("expected duplicate-ID error")
	}
	if !errors.Is(err, ErrWitnessAlreadyRegistered) {
		t.Errorf("err = %v, want ErrWitnessAlreadyRegistered", err)
	}
	if r.Size() != 1 {
		t.Errorf("Size = %d, want 1 (duplicate must not double-admit)", r.Size())
	}
}

// ─── Revoke: success + audit ────────────────────────────────────────

func TestRevoke_Registered_Removed(t *testing.T) {
	auditor := &countingAuditor{}
	r := NewWitnessRegistry(auditor)

	id, pub, pop := makeWitness(t, id32(0x0A))
	_ = r.Register(id, pub, pop)

	if err := r.Revoke(id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if r.Size() != 0 {
		t.Errorf("Size = %d, want 0", r.Size())
	}
	if len(auditor.revokes) != 1 {
		t.Errorf("revokes = %d, want 1", len(auditor.revokes))
	}
	if _, ok := r.Lookup(id); ok {
		t.Error("Lookup must return false after Revoke")
	}
}

// ─── Revoke: not-registered surfaces as reject ──────────────────────

func TestRevoke_NotRegistered_Error(t *testing.T) {
	auditor := &countingAuditor{}
	r := NewWitnessRegistry(auditor)

	err := r.Revoke(id32(0x0B))
	if err == nil {
		t.Fatal("expected error for missing ID")
	}
	if !errors.Is(err, ErrWitnessNotRegistered) {
		t.Errorf("err = %v, want ErrWitnessNotRegistered", err)
	}
	if len(auditor.rejects) != 1 {
		t.Errorf("rejects = %d, want 1", len(auditor.rejects))
	}
}

// ─── Snapshot: returns deep copy ────────────────────────────────────

func TestSnapshot_DeepCopy_NoMutationLeak(t *testing.T) {
	r := NewWitnessRegistry(nil)
	id, pub, pop := makeWitness(t, id32(0x0C))
	_ = r.Register(id, pub, pop)

	snap := r.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snap len = %d, want 1", len(snap))
	}

	// Mutate the snapshot's PublicKey; the registry's copy must not change.
	for i := range snap[0].PublicKey {
		snap[0].PublicKey[i] = 0
	}
	got, _ := r.Lookup(id)
	if string(got.PublicKey) != string(pub) {
		t.Error("registry storage was mutated through snapshot")
	}
}

// ─── Lookup: copy-on-read ───────────────────────────────────────────

func TestLookup_DeepCopy_NoMutationLeak(t *testing.T) {
	r := NewWitnessRegistry(nil)
	id, pub, pop := makeWitness(t, id32(0x0D))
	_ = r.Register(id, pub, pop)

	got, _ := r.Lookup(id)
	for i := range got.PublicKey {
		got.PublicKey[i] = 0
	}
	got2, _ := r.Lookup(id)
	if string(got2.PublicKey) != string(pub) {
		t.Error("registry storage was mutated through lookup")
	}
}

// ─── Rotate: happy path replaces oldID with newID ──────────────────

func TestRotate_ValidNewKey_AdmittedOldRevoked(t *testing.T) {
	auditor := &countingAuditor{}
	r := NewWitnessRegistry(auditor)

	oldID, oldPub, oldPoP := makeWitness(t, id32(0x10))
	_ = r.Register(oldID, oldPub, oldPoP)

	newID, newPub, newPoP := makeWitness(t, id32(0x11))
	if err := r.Rotate(oldID, newID, newPub, newPoP); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if r.Size() != 1 {
		t.Errorf("Size = %d, want 1 after rotate", r.Size())
	}
	if _, ok := r.Lookup(oldID); ok {
		t.Error("oldID must be revoked")
	}
	if _, ok := r.Lookup(newID); !ok {
		t.Error("newID must be admitted")
	}
	// 2 admits (initial + new), 1 revoke (old).
	if len(auditor.admits) != 2 || len(auditor.revokes) != 1 {
		t.Errorf("audit counts: admits=%d revokes=%d", len(auditor.admits), len(auditor.revokes))
	}
}

// ─── Rotate: bad PoP leaves old key intact ─────────────────────────

func TestRotate_BadPoP_OldKeyPreserved(t *testing.T) {
	r := NewWitnessRegistry(nil)
	oldID, oldPub, oldPoP := makeWitness(t, id32(0x12))
	_ = r.Register(oldID, oldPub, oldPoP)

	newID, newPub, newPoP := makeWitness(t, id32(0x13))
	newPoP[0] ^= 0xFF

	err := r.Rotate(oldID, newID, newPub, newPoP)
	if err == nil {
		t.Fatal("expected rotate to fail on bad PoP")
	}
	if r.Size() != 1 {
		t.Errorf("Size = %d, want 1 (rotate failed, old preserved)", r.Size())
	}
	if _, ok := r.Lookup(oldID); !ok {
		t.Error("old ID must still be registered after rotate failure")
	}
}

// ─── Rotate: missing old ID rolls back the new admission ───────────

func TestRotate_MissingOldID_RollsBackNewAdmission(t *testing.T) {
	auditor := &countingAuditor{}
	r := NewWitnessRegistry(auditor)

	missingOldID := id32(0xAA)
	newID, newPub, newPoP := makeWitness(t, id32(0xAB))

	err := r.Rotate(missingOldID, newID, newPub, newPoP)
	if err == nil {
		t.Fatal("expected error for missing old ID")
	}
	if !errors.Is(err, ErrWitnessNotRegistered) {
		t.Errorf("err = %v, want ErrWitnessNotRegistered", err)
	}
	if r.Size() != 0 {
		t.Errorf("Size = %d, want 0 (rollback must have removed the just-admitted new key)", r.Size())
	}
}

// ─── Concurrency: register + snapshot under contention ─────────────

func TestRegistry_ConcurrentRegisterAndSnapshot(t *testing.T) {
	r := NewWitnessRegistry(nil)
	const N = 25
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(seed byte) {
			defer wg.Done()
			id, pub, pop := makeWitness(t, id32(seed))
			_ = r.Register(id, pub, pop)
			_ = r.Snapshot()
		}(byte(i + 1))
	}
	wg.Wait()
	if r.Size() != N {
		t.Errorf("Size = %d, want %d", r.Size(), N)
	}
}
