/*
FILE PATH: api/exchange/auth/nonce_factory_test.go

DESCRIPTION:

	Coverage for the NonceStore factory and the strict-forever
	semantics. Tests four things:

	1. The factory selects the right SDK backend per cfg.Backend.
	2. The factory's per-destination namespace works — two destinations
	   sharing the same backend connection do NOT collide on identical
	   nonce values.
	3. The freshness window is independent of replay tracking — stale
	   timestamps fail before reservation.
	4. The strict-forever contract holds: a once-reserved nonce stays
	   reserved forever (no TTL pruning behind our back).

	Redis-backed paths exercise an in-process miniredis so the tests
	are hermetic — no Docker, no external Redis required.
*/
package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	sdkauth "github.com/clearcompass-ai/attesta/exchange/auth"
)

// ─────────────────────────────────────────────────────────────────────
// Factory backend selection — multi-tenant via BuildForExchange
// ─────────────────────────────────────────────────────────────────────

const testTenantDID = "did:web:exchange.test"

func TestFactory_DefaultsToMemoryBackend(t *testing.T) {
	store, err := NonceStoreConfig{}.BuildForExchange(testTenantDID)
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
	store, err := NonceStoreConfig{Backend: BackendMemory}.BuildForExchange(testTenantDID)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if store == nil {
		t.Fatal("memory backend returned nil store")
	}
}

func TestFactory_PerTenantNamespacing_MemoryBackend(t *testing.T) {
	// Two tenants on the memory backend — each gets its own store, so
	// the same nonce is reservable independently in both namespaces.
	a, err := NonceStoreConfig{}.BuildForExchange("did:web:tenant-a")
	if err != nil {
		t.Fatalf("tenant A: %v", err)
	}
	b, err := NonceStoreConfig{}.BuildForExchange("did:web:tenant-b")
	if err != nil {
		t.Fatalf("tenant B: %v", err)
	}
	ctx := context.Background()
	if err := a.Reserve(ctx, "shared"); err != nil {
		t.Fatalf("A first Reserve: %v", err)
	}
	if err := b.Reserve(ctx, "shared"); err != nil {
		t.Errorf("B first Reserve should succeed (different tenant): %v", err)
	}
	if err := a.Reserve(ctx, "shared"); !errors.Is(err, sdkauth.ErrNonceReserved) {
		t.Errorf("A replay should fail: got %v", err)
	}
}

func TestFactory_RedisBackend_MissingAddrErrors(t *testing.T) {
	_, err := NonceStoreConfig{
		Backend: BackendRedis,
	}.BuildForExchange(testTenantDID)
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

func TestFactory_BuildForExchange_RequiresDestination(t *testing.T) {
	_, err := NonceStoreConfig{}.BuildForExchange("")
	if err == nil {
		t.Fatal("expected error for empty destination")
	}
	if !errors.Is(err, ErrInvalidNonceConfig) {
		t.Errorf("error should wrap ErrInvalidNonceConfig: %v", err)
	}
	if !strings.Contains(err.Error(), "destination") {
		t.Errorf("error should mention destination: %v", err)
	}
}

func TestFactory_UnknownBackendErrors(t *testing.T) {
	_, err := NonceStoreConfig{
		Backend: NonceStoreBackend("postgres"),
	}.BuildForExchange(testTenantDID)
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
// the JN-side wrapper. The previous local store TTL-pruned
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

// ─────────────────────────────────────────────────────────────────────
// Redis backend — exercised via miniredis (hermetic, no Docker)
// ─────────────────────────────────────────────────────────────────────

// newMiniRedis stands up an in-process Redis and registers cleanup.
func newMiniRedis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr := miniredis.RunT(t)
	t.Cleanup(mr.Close)
	return mr
}

// TestFactory_RedisBackend_HappyPath_Reserve verifies the Redis-backed
// path end-to-end: factory builds a *NonceStore against miniredis, the
// first Reserve succeeds, the second errors as ErrNonceReserved. This
// is the smoke-test that proves connection-vs-namespace split actually
// produces a working Redis store.
func TestFactory_RedisBackend_HappyPath_Reserve(t *testing.T) {
	mr := newMiniRedis(t)
	cfg := NonceStoreConfig{
		Backend:   BackendRedis,
		RedisAddr: mr.Addr(),
	}
	ns, err := cfg.BuildForExchange("did:web:exchange.test")
	if err != nil {
		t.Fatalf("BuildForExchange: %v", err)
	}
	ctx := context.Background()
	if err := ns.Reserve(ctx, "n1"); err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	if err := ns.Reserve(ctx, "n1"); !errors.Is(err, sdkauth.ErrNonceReserved) {
		t.Errorf("replay Reserve: got %v, want ErrNonceReserved", err)
	}
}

// TestFactory_RedisBackend_PerDestinationNamespacing pins the load-bearing
// multi-tenant invariant: the SAME nonce value reserved against destination A
// MUST NOT cause a replay rejection for destination B sharing the same Redis
// instance. Cross-tenant collision protection comes from the SDK's
// "{prefix}{destination}:{nonce}" key shape — this test proves we are
// passing the destination through the JN-side factory correctly.
func TestFactory_RedisBackend_PerDestinationNamespacing(t *testing.T) {
	mr := newMiniRedis(t)
	cfg := NonceStoreConfig{Backend: BackendRedis, RedisAddr: mr.Addr()}

	storeA, err := cfg.BuildForExchange("did:web:tenant-a")
	if err != nil {
		t.Fatalf("tenant A build: %v", err)
	}
	storeB, err := cfg.BuildForExchange("did:web:tenant-b")
	if err != nil {
		t.Fatalf("tenant B build: %v", err)
	}

	ctx := context.Background()
	const sharedNonce = "collision-candidate"

	if err := storeA.Reserve(ctx, sharedNonce); err != nil {
		t.Fatalf("tenant A first Reserve: %v", err)
	}
	if err := storeB.Reserve(ctx, sharedNonce); err != nil {
		t.Errorf("tenant B should accept the same nonce (different namespace), got %v", err)
	}
	// Replays in each tenant's own namespace still fire as expected.
	if err := storeA.Reserve(ctx, sharedNonce); !errors.Is(err, sdkauth.ErrNonceReserved) {
		t.Errorf("tenant A replay: got %v, want ErrNonceReserved", err)
	}
	if err := storeB.Reserve(ctx, sharedNonce); !errors.Is(err, sdkauth.ErrNonceReserved) {
		t.Errorf("tenant B replay: got %v, want ErrNonceReserved", err)
	}
}

// TestFactory_RedisBackend_KeyPrefixHonored confirms the JN-side factory
// passes RedisKeyPrefix through to the SDK. Probes miniredis directly for
// a key with the configured prefix after a successful reserve.
func TestFactory_RedisBackend_KeyPrefixHonored(t *testing.T) {
	mr := newMiniRedis(t)
	const customPrefix = "jn:phase4:nonce:"
	cfg := NonceStoreConfig{
		Backend:        BackendRedis,
		RedisAddr:      mr.Addr(),
		RedisKeyPrefix: customPrefix,
	}
	ns, err := cfg.BuildForExchange("did:web:exchange.test")
	if err != nil {
		t.Fatalf("BuildForExchange: %v", err)
	}
	if err := ns.Reserve(context.Background(), "abc"); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	// Key shape should be {customPrefix}{destination}:{nonce}.
	wantKey := customPrefix + "did:web:exchange.test:abc"
	if !mr.Exists(wantKey) {
		t.Errorf("expected key %q in miniredis; keys present = %v",
			wantKey, mr.Keys())
	}
}

// TestFactory_RedisBackend_RedisDBHonored confirms the JN-side factory
// passes RedisDB through to the SDK. Defaults to DB 0; setting it to 1
// makes the reservation invisible from DB 0.
func TestFactory_RedisBackend_RedisDBHonored(t *testing.T) {
	mr := newMiniRedis(t)
	cfg := NonceStoreConfig{
		Backend:   BackendRedis,
		RedisAddr: mr.Addr(),
		RedisDB:   1,
	}
	ns, err := cfg.BuildForExchange("did:web:exchange.test")
	if err != nil {
		t.Fatalf("BuildForExchange: %v", err)
	}
	if err := ns.Reserve(context.Background(), "x"); err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	// Probe DB 0 directly: should be empty.
	probeDB0 := redis.NewClient(&redis.Options{Addr: mr.Addr(), DB: 0})
	defer probeDB0.Close()
	keys, err := probeDB0.Keys(context.Background(), "*").Result()
	if err != nil {
		t.Fatalf("probe DB 0: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("DB 0 should be empty; got keys %v", keys)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Concurrency: per-tenant Reserve under -race
// ─────────────────────────────────────────────────────────────────────

// TestNonceStore_ConcurrentReserve_StrictForever fires N goroutines at
// the same memory-backed store racing to reserve the SAME nonce.
// EXACTLY ONE may succeed; the rest must surface ErrNonceReserved.
// Run with -race to catch any unsynchronized state.
func TestNonceStore_ConcurrentReserve_StrictForever(t *testing.T) {
	const goroutines = 32
	ns, err := NonceStoreConfig{}.BuildForExchange("did:web:exchange.test")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ctx := context.Background()

	var wg sync.WaitGroup
	var winners atomic.Int32
	var collisions atomic.Int32
	wg.Add(goroutines)
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			err := ns.Reserve(ctx, "race")
			switch {
			case err == nil:
				winners.Add(1)
			case errors.Is(err, sdkauth.ErrNonceReserved):
				collisions.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners.Load() != 1 {
		t.Errorf("winners = %d, want exactly 1", winners.Load())
	}
	if collisions.Load() != goroutines-1 {
		t.Errorf("collisions = %d, want %d", collisions.Load(), goroutines-1)
	}
}

// TestNonceStore_ConcurrentReserve_DifferentTenants — N goroutines hit
// N tenant stores with the SAME nonce; every goroutine must succeed
// (no cross-tenant interference).
func TestNonceStore_ConcurrentReserve_DifferentTenants(t *testing.T) {
	const tenants = 16
	stores := make([]*NonceStore, tenants)
	for i := 0; i < tenants; i++ {
		s, err := NonceStoreConfig{}.BuildForExchange(
			"did:web:tenant-" + string(rune('a'+i)))
		if err != nil {
			t.Fatalf("tenant %d build: %v", i, err)
		}
		stores[i] = s
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	var failures atomic.Int32
	wg.Add(tenants)
	start := make(chan struct{})

	for i := 0; i < tenants; i++ {
		s := stores[i]
		go func() {
			defer wg.Done()
			<-start
			if err := s.Reserve(ctx, "shared-nonce"); err != nil {
				failures.Add(1)
				t.Errorf("tenant Reserve: %v (cross-tenant interference)", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if failures.Load() != 0 {
		t.Errorf("expected zero cross-tenant collisions, got %d", failures.Load())
	}
}

// ─────────────────────────────────────────────────────────────────────
// Custom freshness window on factory-built store
// ─────────────────────────────────────────────────────────────────────

// TestFactory_FreshnessWindow_Honored verifies the FreshnessWindow on
// the config flows into the wrapping NonceStore.
func TestFactory_FreshnessWindow_Honored(t *testing.T) {
	const customWindow = 17 * time.Second
	ns, err := NonceStoreConfig{
		FreshnessWindow: customWindow,
	}.BuildForExchange("did:web:exchange.test")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// A timestamp 10s in the past is fresh under 17s window…
	near := time.Now().Add(-10 * time.Second)
	if err := ns.CheckFreshness(near); err != nil {
		t.Errorf("near-fresh timestamp should pass 17s window, got %v", err)
	}
	// …and a timestamp 30s in the past is stale.
	old := time.Now().Add(-30 * time.Second)
	if err := ns.CheckFreshness(old); err == nil {
		t.Errorf("30s-old timestamp should fail 17s window")
	}
}

// TestFactory_FreshnessWindow_DefaultApplied verifies the default kicks
// in when FreshnessWindow is left zero.
func TestFactory_FreshnessWindow_DefaultApplied(t *testing.T) {
	ns, err := NonceStoreConfig{}.BuildForExchange("did:web:exchange.test")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// DefaultFreshnessWindow is 5 minutes; a 4-minute-old stamp passes,
	// a 6-minute-old stamp fails.
	if err := ns.CheckFreshness(time.Now().Add(-4 * time.Minute)); err != nil {
		t.Errorf("4-minute-old should pass 5-minute default window: %v", err)
	}
	if err := ns.CheckFreshness(time.Now().Add(-6 * time.Minute)); err == nil {
		t.Error("6-minute-old should fail 5-minute default window")
	}
}

// TestDefaultFreshnessWindow_StableValue pins the constant so an
// accidental edit to seconds-vs-minutes doesn't slip through review.
func TestDefaultFreshnessWindow_StableValue(t *testing.T) {
	if DefaultFreshnessWindow != 5*time.Minute {
		t.Errorf("DefaultFreshnessWindow = %v, want 5m (changing this changes "+
			"freshness behavior across every deployment)", DefaultFreshnessWindow)
	}
}
