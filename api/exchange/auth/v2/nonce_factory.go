/*
FILE PATH: api/exchange/auth/v2/nonce_factory.go

DESCRIPTION:

	Deployment-time selector for the SDK strict-forever NonceStore
	backend. Multi-tenant: a single process serves N destinations,
	each addressed by its own destination DID. The factory constructs
	one backend-bound sdkauth.NonceStore per registered destination;
	SignerAuth looks up the right one per request from
	Request.Destination via SignerAuthConfig.PerDestinationNonceStores.

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

CHANGED FROM PRE-V2

  - Returns sdkauth.NonceStore directly. The pre-v2 wrapper type
    (with freshness window) is GONE — freshness is now folded into
    the SDK envelope's IssuedAt/ExpiresAt + MaxValidityWindow
    ceiling (1h). Wall-clock freshness checks happen inside
    sdkauth.VerifyRequest; the factory no longer carries a
    FreshnessWindow.

  - No JN wrapper type. PerDestinationNonceStores is map[string]
    sdkauth.NonceStore directly; consumers of the factory output
    pass it through to SignerAuthConfig verbatim.

KEY ARCHITECTURAL DECISIONS:

  - Connection-vs-namespace split. NonceStoreConfig holds backend
    selection + connection params (RedisAddr, RedisPassword, …).
    Per-tenant namespacing lives on the per-destination
    BuildForExchange call. One Redis connection, N stores keyed
    by destination DID.
  - Strict-forever contract preserved by both backends. The factory
    does NOT add TTL, eviction, or any other reservation-forgetting
    behavior — the SDK contract requires reservations to be
    permanent.
  - Cross-tenant collision protection: the SDK's RedisNonceStore
    formats keys as "{prefix}{destination}:{nonce}" — two different
    destinations sharing the same Redis instance never collide.
*/
package v2

import (
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"

	sdkauth "github.com/clearcompass-ai/attesta/exchange/auth"
)

// NonceStoreBackend is the deployment-time selection of which
// concrete SDK NonceStore impl the factory returns. Stable string
// values so they can be set from JSON config or env var without
// recompilation.
type NonceStoreBackend string

const (
	BackendMemory NonceStoreBackend = "memory"
	BackendRedis  NonceStoreBackend = "redis"
)

// DefaultNonceStoreBackend is the backend used when
// NonceStoreConfig leaves Backend empty.
const DefaultNonceStoreBackend = BackendMemory

// ErrInvalidNonceConfig wraps factory validation failures.
var ErrInvalidNonceConfig = errors.New("auth/v2: invalid nonce store configuration")

// NonceStoreConfig configures the factory. Backend selects the
// concrete impl; the rest are backend-specific connection
// parameters. Per-tenant namespacing (the destination DID) is
// supplied per-call via BuildForExchange so a single connection
// serves N destinations.
type NonceStoreConfig struct {
	// Backend selects which concrete impl to construct.
	// Empty defaults to DefaultNonceStoreBackend.
	Backend NonceStoreBackend

	// RedisAddr is the redis endpoint (e.g., "redis.svc:6379").
	// Required when Backend == BackendRedis.
	RedisAddr string

	// RedisPassword is the optional redis password. Empty means no
	// AUTH command is sent.
	RedisPassword string

	// RedisDB selects the redis logical DB. Default 0.
	RedisDB int

	// RedisKeyPrefix overrides the SDK default ("attesta:nonce:").
	// Empty uses the SDK default.
	RedisKeyPrefix string
}

// BuildForExchange returns an sdkauth.NonceStore namespaced for
// destination. For BackendMemory the destination is recorded for
// diagnostics but not enforced — each call gets its own
// InMemoryNonceStore, so the namespace is implicit. For
// BackendRedis the destination IS the key namespace
// ("{prefix}{destination}:{nonce}").
//
// Composition root pattern:
//
//	stores := map[string]sdkauth.NonceStore{}
//	for _, did := range registry.ExchangeDIDs() {
//	    s, err := cfg.BuildForExchange(did)
//	    if err != nil { return err }
//	    stores[did] = s
//	}
//
// Returns ErrInvalidNonceConfig wrapped with a specific message
// on validation failure.
func (cfg NonceStoreConfig) BuildForExchange(destination string) (sdkauth.NonceStore, error) {
	if destination == "" {
		return nil, fmt.Errorf("%w: destination required", ErrInvalidNonceConfig)
	}

	backend := cfg.Backend
	if backend == "" {
		backend = DefaultNonceStoreBackend
	}

	switch backend {
	case BackendMemory:
		// Memory backend: single-process namespace, implicit because
		// each destination gets its own InMemoryNonceStore instance.
		return sdkauth.NewInMemoryNonceStore(), nil
	case BackendRedis:
		return cfg.buildRedisStore(destination)
	default:
		return nil, fmt.Errorf("%w: unknown backend %q (expected %q or %q)",
			ErrInvalidNonceConfig, backend, BackendMemory, BackendRedis)
	}
}

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
