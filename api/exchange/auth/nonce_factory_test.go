/*
FILE PATH: api/exchange/auth/nonce_factory_test.go

DESCRIPTION:
    Coverage for the NonceStore factory and the new strict-forever
    semantics. Tests three things:

    1. The factory selects the right SDK backend per cfg.Backend.
    2. The freshness window is independent of replay tracking — stale
       timestamps fail before reservation.
    3. The strict-forever contract holds: a once-reserved nonce stays
       reserved forever (no TTL pruning behind our back).
*/
package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sdkauth "github.com/clearcompass-ai/ortholog-sdk/exchange/auth"
)

// ─────────────────────────────────────────────────────────────────────
// Factory backend selection
// ─────────────────────────────────────────────────────────────────────

func TestFactory_DefaultsToMemoryBackend(t *testing.T) {
	store, err := NewNonceStoreFromConfig(NonceStoreConfig{})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if store == nil {
		t.Fatal("factory returned nil store")
	}
	// Memory backend smoke test: first reservation succeeds, second
	// fails as ErrNonceReserved.
	ctx := context.Background()
	if err := store.Reserve(ctx, "n1"); err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	if err := store.Reserve(ctx, "n1"); !errors.Is(err, sdkauth.ErrNonceReserved) {
		t.Errorf("second Reserve: got %v, want ErrNonceReserved", err)
	}
}

func TestFactory_ExplicitMemoryBackend(t *testing.T) {
	store, err := NewNonceStoreFromConfig(NonceStoreConfig{Backend: BackendMemory})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if store == nil {
		t.Fatal("memory backend returned nil store")
	}
}

func TestFactory_RedisBackend_MissingAddrErrors(t *testing.T) {
	_, err := NewNonceStoreFromConfig(NonceStoreConfig{
		Backend:     BackendRedis,
		ExchangeDID: "did:web:exchange.test",
	})
	if err == nil {
		t.Fatal("expected error for missing RedisAddr")
	}
	if !errors.Is(err, ErrInvalidNonceConfig) {
		t.Errorf("error should wrap ErrInvalidNonceConfig: %v", err)
	}
	if !strings.Contains(err.Error(), "RedisAddr") {
		t.Errorf("error should mention RedisAddr: %v", err)
	}
}

func TestFactory_RedisBackend_MissingExchangeDIDErrors(t *testing.T) {
	_, err := NewNonceStoreFromConfig(NonceStoreConfig{
		Backend:   BackendRedis,
		RedisAddr: "redis.svc:6379",
	})
	if err == nil {
		t.Fatal("expected error for missing ExchangeDID")
	}
	if !strings.Contains(err.Error(), "ExchangeDID") {
		t.Errorf("error should mention ExchangeDID: %v", err)
	}
}

func TestFactory_UnknownBackendErrors(t *testing.T) {
	_, err := NewNonceStoreFromConfig(NonceStoreConfig{
		Backend: NonceStoreBackend("postgres"),
	})
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
	if !errors.Is(err, ErrInvalidNonceConfig) {
		t.Errorf("error should wrap ErrInvalidNonceConfig: %v", err)
	}
}

func TestFactory_BackendConstantsStable(t *testing.T) {
	if string(BackendMemory) != "memory" {
		t.Errorf("BackendMemory = %q, want \"memory\"", BackendMemory)
	}
	if string(BackendRedis) != "redis" {
		t.Errorf("BackendRedis = %q, want \"redis\"", BackendRedis)
	}
	if DefaultNonceStoreBackend != BackendMemory {
		t.Errorf("default backend = %q, want %q", DefaultNonceStoreBackend, BackendMemory)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Strict-forever contract: no TTL pruning
// ─────────────────────────────────────────────────────────────────────

// TestNonceStore_StrictForever_NoPruning pins the SDK contract on
// the JN-side wrapper. The pre-Phase-1B local store TTL-pruned
// reservations on every Check call; this test confirms that's gone.
// A nonce reserved at t=now is still reserved when checked again
// after the freshness window has elapsed — only the freshness gate
// rejects, the replay gate still says "seen."
func TestNonceStore_StrictForever_NoPruning(t *testing.T) {
	ns := NewNonceStore(50 * time.Millisecond)
	ctx := context.Background()
	if err := ns.Reserve(ctx, "permanent"); err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	// Wait past the freshness window — the strict-forever contract
	// means the reservation MUST persist.
	time.Sleep(100 * time.Millisecond)
	if err := ns.Reserve(ctx, "permanent"); !errors.Is(err, sdkauth.ErrNonceReserved) {
		t.Errorf("post-window Reserve: got %v, want ErrNonceReserved (strict-forever violated)", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Freshness gate is independent of replay gate
// ─────────────────────────────────────────────────────────────────────

func TestNonceStore_CheckFreshness_StaleTimestampRejected(t *testing.T) {
	ns := NewNonceStore(1 * time.Second)
	stale := time.Now().Add(-10 * time.Second)
	if err := ns.CheckFreshness(stale); err == nil {
		t.Error("stale timestamp should be rejected")
	}
	if err := ns.CheckFreshness(stale); !errors.Is(err, ErrTimestampStale) {
		t.Errorf("error should be ErrTimestampStale: %v", err)
	}
}

func TestNonceStore_CheckFreshness_FreshTimestampAccepted(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)
	if err := ns.CheckFreshness(time.Now()); err != nil {
		t.Errorf("fresh timestamp: %v", err)
	}
}

func TestNonceStore_CheckFreshness_ZeroWindowDisablesGate(t *testing.T) {
	ns := NewNonceStore(0) // 0 disables the gate
	ancient := time.Now().Add(-100 * 365 * 24 * time.Hour)
	if err := ns.CheckFreshness(ancient); err != nil {
		t.Errorf("zero window should disable gate: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Reserve surfaces SDK sentinels
// ─────────────────────────────────────────────────────────────────────

func TestNonceStore_Reserve_ReturnsSDKErrors(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)
	ctx := context.Background()
	if err := ns.Reserve(ctx, ""); !errors.Is(err, sdkauth.ErrNonceEmpty) {
		t.Errorf("empty nonce: got %v, want ErrNonceEmpty", err)
	}
	if err := ns.Reserve(ctx, "x"); err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	if err := ns.Reserve(ctx, "x"); !errors.Is(err, sdkauth.ErrNonceReserved) {
		t.Errorf("replay: got %v, want ErrNonceReserved", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Backend swap via NewNonceStoreWithBackend
// ─────────────────────────────────────────────────────────────────────

// stubFailingStore exercises the ErrNonceStoreUnavailable surface so
// the sentinel-routing in SignerAuth.authenticate is testable without
// a real Redis instance.
type stubFailingStore struct{}

func (stubFailingStore) Reserve(_ context.Context, _ string) error {
	return sdkauth.ErrNonceStoreUnavailable
}

func TestNonceStoreWithBackend_AcceptsArbitraryStore(t *testing.T) {
	ns := NewNonceStoreWithBackend(stubFailingStore{}, 5*time.Minute)
	ctx := context.Background()
	err := ns.Reserve(ctx, "x")
	if !errors.Is(err, sdkauth.ErrNonceStoreUnavailable) {
		t.Errorf("custom backend error: got %v, want ErrNonceStoreUnavailable", err)
	}
}
