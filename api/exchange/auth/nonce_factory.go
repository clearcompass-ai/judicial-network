/*
FILE PATH: api/exchange/auth/nonce_factory.go

DESCRIPTION:
    Deployment-time selector for the SDK strict-forever NonceStore
    backend. Multi-tenant: a single process serves N destinations,
    each addressed by its own destination DID. The factory constructs
    one backend-bound *NonceStore per registered destination; the
    composition root looks up the right one per request from
    entry.Header.Destination.

    Two backends:

      "memory" (default) → sdkauth.InMemoryNonceStore.
                            Single-process, no replay protection
                            across restarts. Fine for dev, CI, and
                            single-replica deploys.
      "redis"            → sdkauth.RedisNonceStore.
                            Multi-replica safe, persistent, namespaced
                            by destination DID. Required for production
                            federations and any deployment with N>1
                            replicas behind a load balancer.

KEY ARCHITECTURAL DECISIONS:
    - Connection-vs-namespace split. NonceStoreConfig holds backend
      selection + connection params (RedisAddr, RedisPassword, …).
      Per-tenant namespacing lives on the per-destination BuildForExchange
      call. One Redis connection, N stores keyed by destination DID.
    - Strict-forever contract preserved by both backends. The factory
      does NOT add TTL, eviction, or any other reservation-forgetting
      behavior — the SDK contract requires reservations to be permanent.
      Freshness handling is JN's responsibility (window in the wrapping
      NonceStore) and is deliberately separate from replay protection.
    - Memory backend's per-destination namespace is implicit (each
      destination gets its own *InMemoryNonceStore instance). Redis
      backend requires the destination DID at build time so the SDK's
      RedisNonceStore can prefix every key with it.
    - Cross-tenant collision protection: the SDK's RedisNonceStore
      formats keys as "{prefix}{destination}:{nonce}" — two different
      destinations sharing the same Redis instance never collide.

KEY DEPENDENCIES:
    - ortholog-sdk/exchange/auth: NonceStore interface +
      InMemoryNonceStore + RedisNonceStore concrete impls.
    - github.com/redis/go-redis/v9: Redis client (transitive).
*/
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	sdkauth "github.com/clearcompass-ai/ortholog-sdk/exchange/auth"
)

// ─────────────────────────────────────────────────────────────────────
// Backend enum + defaults
// ─────────────────────────────────────────────────────────────────────

// NonceStoreBackend is the deployment-time selection of which concrete
// SDK NonceStore impl the factory returns. Stable string values so
// they can be set from JSON config or NONCE_STORE_BACKEND env var
// without recompilation.
type NonceStoreBackend string

const (
	BackendMemory NonceStoreBackend = "memory"
	BackendRedis  NonceStoreBackend = "redis"
)

// DefaultNonceStoreBackend is the backend used when NonceStoreConfig
// leaves Backend empty.
const DefaultNonceStoreBackend = BackendMemory

// DefaultFreshnessWindow caps the timestamp staleness for signed
// requests. Backpressure that bounds NonceStore growth in practice.
const DefaultFreshnessWindow = 5 * time.Minute

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrInvalidNonceConfig wraps factory validation failures (unknown
// backend, missing required field, etc.).
var ErrInvalidNonceConfig = errors.New("auth: invalid nonce store configuration")

// ─────────────────────────────────────────────────────────────────────
// Config — connection only; per-tenant namespacing is per-call
// ─────────────────────────────────────────────────────────────────────

// NonceStoreConfig configures the factory. Backend selects the
// concrete impl; the rest are backend-specific connection parameters.
// Per-tenant namespacing (the destination DID) is supplied per-call
// via BuildForExchange, so a single connection can serve N
// destinations.
type NonceStoreConfig struct {
	// Backend selects which NonceStore concrete impl to construct.
	// Empty defaults to DefaultNonceStoreBackend.
	Backend NonceStoreBackend

	// FreshnessWindow caps signed-request timestamp staleness.
	// Empty/zero defaults to DefaultFreshnessWindow.
	FreshnessWindow time.Duration

	// RedisAddr is the redis endpoint (e.g., "redis.svc:6379").
	// Required when Backend == BackendRedis.
	RedisAddr string

	// RedisPassword is the optional redis password. Empty means no
	// AUTH command is sent.
	RedisPassword string

	// RedisDB selects the redis logical DB. Default 0.
	RedisDB int

	// RedisKeyPrefix overrides the SDK default ("ortholog:nonce:").
	// Empty uses the SDK default.
	RedisKeyPrefix string
}

// ─────────────────────────────────────────────────────────────────────
// Factory — per-tenant build
// ─────────────────────────────────────────────────────────────────────

// BuildForExchange returns a *NonceStore namespaced for destination.
// For BackendMemory the destination is recorded for diagnostics but
// not enforced — each call gets its own *InMemoryNonceStore, so the
// namespace is implicit. For BackendRedis the destination is required
// and used as the key namespace ({prefix}{destination}:{nonce}).
//
// Composition root pattern:
//
//	stores := map[string]*NonceStore{}
//	for _, did := range registry.ExchangeDIDs() {
//	    s, err := cfg.BuildForExchange(did)
//	    if err != nil { return err }
//	    stores[did] = s
//	}
//
// Per-request lookup:
//
//	store := stores[entry.Header.Destination]
//
// (registry.ExchangeDIDs() is the jurisdiction.Registry method that
// returns the registered destination DIDs in sorted order — its name
// is fixed by the jurisdiction package.)
//
// Returns ErrInvalidNonceConfig wrapped with a specific message on
// validation failure.
func (cfg NonceStoreConfig) BuildForExchange(destination string) (*NonceStore, error) {
	if destination == "" {
		return nil, fmt.Errorf("%w: destination required", ErrInvalidNonceConfig)
	}

	window := cfg.FreshnessWindow
	if window <= 0 {
		window = DefaultFreshnessWindow
	}

	backend := cfg.Backend
	if backend == "" {
		backend = DefaultNonceStoreBackend
	}

	var store sdkauth.NonceStore
	switch backend {
	case BackendMemory:
		// Memory backend: single-process namespace, implicit because
		// each destination gets its own *InMemoryNonceStore instance.
		store = sdkauth.NewInMemoryNonceStore()
	case BackendRedis:
		s, err := cfg.buildRedisStore(destination)
		if err != nil {
			return nil, err
		}
		store = s
	default:
		return nil, fmt.Errorf("%w: unknown backend %q (expected %q or %q)",
			ErrInvalidNonceConfig, backend, BackendMemory, BackendRedis)
	}

	return NewNonceStoreWithBackend(store, window), nil
}

// buildRedisStore constructs an SDK RedisNonceStore for destination
// using the connection params on cfg.
func (cfg NonceStoreConfig) buildRedisStore(destination string) (sdkauth.NonceStore, error) {
	if cfg.RedisAddr == "" {
		return nil, fmt.Errorf("%w: RedisAddr required for redis backend",
			ErrInvalidNonceConfig)
	}
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	return sdkauth.NewRedisNonceStore(sdkauth.RedisNonceStoreConfig{
		Client:      client,
		Destination: destination,
		KeyPrefix:   cfg.RedisKeyPrefix,
	})
}
