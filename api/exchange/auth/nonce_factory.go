/*
FILE PATH: api/exchange/auth/nonce_factory.go

DESCRIPTION:
    Deployment-time selector for the SDK strict-forever NonceStore
    backend. Mirrors the operator's nonce_factory pattern: production
    deployments switch from in-memory to Redis via a single config
    knob without changing call sites.

    Two backends:

      "memory" (default) → sdkauth.InMemoryNonceStore.
                            Single-process, no replay protection
                            across restarts. Fine for dev, CI, and
                            single-replica deploys.
      "redis"            → sdkauth.RedisNonceStore.
                            Multi-replica safe, persistent, namespaced
                            by exchange DID. Required for production
                            federations and any deployment with N>1
                            replicas behind a load balancer.

KEY ARCHITECTURAL DECISIONS:
    - Factory pattern, not direct construction: callers (server.go
      composition root) hold a NonceStoreConfig and ask for an
      *NonceStore. The factory owns backend selection so changing the
      default flips the deployment in one place.
    - Strict-forever contract preserved by both backends. The factory
      does NOT add TTL, eviction, or any other reservation-forgetting
      behavior — the SDK contract requires reservations to be
      permanent. Freshness handling is JN's responsibility (window in
      the wrapping NonceStore) and is deliberately separate from
      replay protection.
    - ExchangeDID is required for redis (cross-tenant namespacing per
      SDK CONTRACT — NAMESPACING). For memory it is accepted but
      ignored, so ops can flip the env var without re-deploying with
      new config.
    - The redis branch builds the redis client from cfg fields
      directly; if a future deployment needs OTel tracing or sentinel
      mode, extend NonceStoreConfig rather than introducing a separate
      factory.

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
// Config
// ─────────────────────────────────────────────────────────────────────

// NonceStoreConfig configures the factory. Backend selects the
// concrete impl; the rest are backend-specific.
type NonceStoreConfig struct {
	// Backend selects which NonceStore concrete impl to construct.
	// Empty defaults to DefaultNonceStoreBackend.
	Backend NonceStoreBackend

	// FreshnessWindow caps signed-request timestamp staleness.
	// Empty/zero defaults to DefaultFreshnessWindow.
	FreshnessWindow time.Duration

	// ExchangeDID namespaces every reservation when using the redis
	// backend (per SDK CONTRACT — NAMESPACING). Required when
	// Backend == BackendRedis. Ignored when Backend == BackendMemory.
	ExchangeDID string

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
// Factory
// ─────────────────────────────────────────────────────────────────────

// NewNonceStoreFromConfig returns a *NonceStore whose backend honors
// cfg.Backend. Returns ErrInvalidNonceConfig wrapped with a specific
// message on validation failure.
func NewNonceStoreFromConfig(cfg NonceStoreConfig) (*NonceStore, error) {
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
		store = sdkauth.NewInMemoryNonceStore()
	case BackendRedis:
		s, err := buildRedisStore(cfg)
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

// buildRedisStore validates redis config and constructs the SDK
// RedisNonceStore. ExchangeDID is required for cross-tenant
// namespacing per the SDK contract.
func buildRedisStore(cfg NonceStoreConfig) (sdkauth.NonceStore, error) {
	if cfg.RedisAddr == "" {
		return nil, fmt.Errorf("%w: RedisAddr required for redis backend",
			ErrInvalidNonceConfig)
	}
	if cfg.ExchangeDID == "" {
		return nil, fmt.Errorf("%w: ExchangeDID required for redis backend",
			ErrInvalidNonceConfig)
	}
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	return sdkauth.NewRedisNonceStore(sdkauth.RedisNonceStoreConfig{
		Client:      client,
		ExchangeDID: cfg.ExchangeDID,
		KeyPrefix:   cfg.RedisKeyPrefix,
	})
}
