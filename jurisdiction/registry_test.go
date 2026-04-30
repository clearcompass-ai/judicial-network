// FILE PATH: jurisdiction/registry_test.go
//
// Tests pinning the Registry contract: Register, Bundle lookup,
// duplicate rejection, Freeze immutability, ExchangeDIDs sort.
package jurisdiction

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

// ─── Registry: register + lookup ───────────────────────────────────

func TestRegistry_RegisterAndLookup(t *testing.T) {
	r := NewRegistry()
	b := goodBundle(t)
	if err := r.Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if r.Len() != 1 {
		t.Errorf("Len=%d, want 1", r.Len())
	}
	got, err := r.Bundle(b.ExchangeDID())
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if got.ExchangeDID() != b.ExchangeDID() {
		t.Errorf("DID drift: %q", got.ExchangeDID())
	}
}

func TestRegistry_LookupUnknown(t *testing.T) {
	r := NewRegistry()
	_, err := r.Bundle("did:web:nope")
	if !errors.Is(err, ErrUnknownExchange) {
		t.Errorf("expected ErrUnknownExchange, got: %v", err)
	}
}

func TestRegistry_RejectsDuplicate(t *testing.T) {
	r := NewRegistry()
	b := goodBundle(t)
	if err := r.Register(b); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := r.Register(b); !errors.Is(err, ErrDuplicateExchange) {
		t.Errorf("expected ErrDuplicateExchange, got: %v", err)
	}
}

func TestRegistry_RejectsInvalidBundle(t *testing.T) {
	r := NewRegistry()
	bad := &fakeBundle{
		exchange: "", // empty
		roles:    minimalCatalog(t),
		cosig:    minimalCosigPolicy(t, "evt_a"),
		preqs:    minimalPrereqPolicy(t, "evt_a"),
	}
	if err := r.Register(bad); !errors.Is(err, ErrInvalidBundle) {
		t.Errorf("expected ErrInvalidBundle, got: %v", err)
	}
}

func TestRegistry_RejectsVocabularyMismatch(t *testing.T) {
	r := NewRegistry()
	mismatch := &fakeBundle{
		exchange: "did:web:x",
		roles:    minimalCatalog(t),
		cosig:    minimalCosigPolicy(t, "evt_a"),
		preqs:    minimalPrereqPolicy(t, "evt_b"),
	}
	if err := r.Register(mismatch); !errors.Is(err, ErrVocabularyMismatch) {
		t.Errorf("expected ErrVocabularyMismatch, got: %v", err)
	}
}

// ─── ExchangeDIDs: sorted snapshot ──────────────────────────────────

func TestRegistry_ExchangeDIDsSorted(t *testing.T) {
	r := NewRegistry()
	for _, did := range []string{"did:web:c", "did:web:a", "did:web:b"} {
		b := &fakeBundle{
			exchange: did,
			roles:    minimalCatalog(t),
			cosig:    minimalCosigPolicy(t, "evt_a"),
			preqs:    minimalPrereqPolicy(t, "evt_a"),
		}
		if err := r.Register(b); err != nil {
			t.Fatalf("Register %s: %v", did, err)
		}
	}
	got := r.ExchangeDIDs()
	want := []string{"did:web:a", "did:web:b", "did:web:c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExchangeDIDs() = %v, want %v", got, want)
	}
}

// ─── Freeze ─────────────────────────────────────────────────────────

func TestRegistry_Freeze_BlocksRegister(t *testing.T) {
	r := NewRegistry()
	if r.IsFrozen() {
		t.Error("new registry must not be frozen")
	}
	r.Freeze()
	if !r.IsFrozen() {
		t.Error("after Freeze IsFrozen must be true")
	}
	err := r.Register(goodBundle(t))
	if !errors.Is(err, ErrRegistryFrozen) {
		t.Errorf("expected ErrRegistryFrozen, got: %v", err)
	}
}

func TestRegistry_Freeze_AllowsLookup(t *testing.T) {
	r := NewRegistry()
	b := goodBundle(t)
	r.Register(b)
	r.Freeze()
	got, err := r.Bundle(b.ExchangeDID())
	if err != nil {
		t.Errorf("lookup post-Freeze: %v", err)
	}
	if got == nil {
		t.Error("Bundle returned nil")
	}
}

func TestRegistry_Freeze_Idempotent(t *testing.T) {
	r := NewRegistry()
	r.Freeze()
	r.Freeze() // second call must not panic / return new state.
	if !r.IsFrozen() {
		t.Error("still frozen")
	}
}

// ─── concurrency ────────────────────────────────────────────────────

func TestRegistry_ConcurrentReadersAfterFreeze(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 10; i++ {
		b := &fakeBundle{
			exchange: "did:web:" + string(rune('a'+i)),
			roles:    minimalCatalog(t),
			cosig:    minimalCosigPolicy(t, "evt_a"),
			preqs:    minimalPrereqPolicy(t, "evt_a"),
		}
		r.Register(b)
	}
	r.Freeze()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.Bundle("did:web:a")
			_ = r.ExchangeDIDs()
			_ = r.Len()
		}()
	}
	wg.Wait()
}
