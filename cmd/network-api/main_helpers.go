/*
FILE PATH: cmd/network-api/main_helpers.go

DESCRIPTION:

	Boot-time helpers split out of main.go to keep that file focused
	on the run() / main() control flow. Owns:

	  - registerProductionBundles : compile-in deployment Bundles
	  - buildNonceStores          : per-destination NonceStore map
	  - buildKeyStore             : memory / softhsm / vault selector
	  - buildAuthenticator        : mTLS / JWT / none selector

	Each helper is independently testable and replaced by a stub in
	main_test.go via the deps struct.
*/
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	_ "github.com/lib/pq" // postgres driver for the durable gossip store

	"github.com/clearcompass-ai/attesta/gossip"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/exchange/auth"
	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
	pkcs11ks "github.com/clearcompass-ai/judicial-network/api/exchange/keystore/pkcs11"
	vaultks "github.com/clearcompass-ai/judicial-network/api/exchange/keystore/vault"
	"github.com/clearcompass-ai/judicial-network/api/middleware"
	"github.com/clearcompass-ai/judicial-network/api/middleware/observability"
	"github.com/clearcompass-ai/judicial-network/gossipfeed"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"

	tncoa "github.com/clearcompass-ai/judicial-network/deployments/tn/coa"
	tndavidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
	tnsupct "github.com/clearcompass-ai/judicial-network/deployments/tn/sup_ct"
)

// registerProductionBundles imports every JN deployment Bundle and
// registers it into the registry. New deployments add an import line
// + one Register call here — the only place in production code where
// destination DIDs cross from compiled-in Bundle definitions into a
// runtime structure.
func registerProductionBundles(r *jurisdiction.Registry) error {
	for _, factory := range []func() jurisdiction.Bundle{
		tndavidson.MustBundle,
		tncoa.MustBundle,
		tnsupct.MustBundle,
	} {
		b := factory()
		if err := r.Register(b); err != nil {
			return fmt.Errorf("register %s: %w", b.ExchangeDID(), err)
		}
	}
	return nil
}

// buildNonceStores constructs one *NonceStore per registered
// destination DID. The resulting map is keyed by destination so the
// auth middleware can look up the right store per request from
// entry.Header.Destination.
//
// Returned errors propagate verbatim so the binary fails loud on
// missing Redis address / invalid backend / etc.
func buildNonceStores(cfg config.Operational, r *jurisdiction.Registry) (map[string]*auth.NonceStore, error) {
	nonceCfg := auth.NonceStoreConfig{
		Backend:         auth.NonceStoreBackend(cfg.NonceStore.Backend),
		FreshnessWindow: cfg.NonceStore.FreshnessWindow,
		RedisAddr:       cfg.NonceStore.RedisAddr,
		RedisPassword:   cfg.NonceStore.RedisPassword,
		RedisDB:         cfg.NonceStore.RedisDB,
		RedisKeyPrefix:  cfg.NonceStore.RedisKeyPrefix,
	}

	out := make(map[string]*auth.NonceStore, r.Len())
	for _, did := range r.ExchangeDIDs() {
		s, err := nonceCfg.BuildForExchange(did)
		if err != nil {
			return nil, fmt.Errorf("nonce store for %s: %w", did, err)
		}
		out[did] = s
	}
	return out, nil
}

// buildKeyStore returns a keystore.KeyStore for the configured
// backend.  wires SoftHSM (PKCS#11) and Vault Transit native
// alongside the in-memory dev path. The PKCS#11 backend compiles in
// only with -tags pkcs11; the no-cgo build target returns
// pkcs11.ErrNotBuilt, surfaced here so ledgers see a clear message.
func buildKeyStore(cfg config.KeyStoreConfig) (keystore.KeyStore, error) {
	switch cfg.Backend {
	case config.KeyStoreBackendMemory:
		return keystore.NewMemoryKeyStore(), nil

	case config.KeyStoreBackendSoftHSM:
		if cfg.PKCS11 == nil {
			return nil, fmt.Errorf("keystore: softhsm requires pkcs11 config")
		}
		pin, err := pkcs11ks.LoadPINFile(cfg.PKCS11.PINFile)
		if err != nil {
			return nil, fmt.Errorf("keystore: softhsm: %w", err)
		}
		return pkcs11ks.New(pkcs11ks.Config{
			LibraryPath: cfg.PKCS11.LibraryPath,
			SlotID:      cfg.PKCS11.SlotID,
			PIN:         pin,
			TokenLabel:  cfg.PKCS11.TokenLabel,
		})

	case config.KeyStoreBackendVault:
		if cfg.Vault == nil {
			return nil, fmt.Errorf("keystore: vault requires vault config")
		}
		token, err := vaultks.LoadTokenFile(cfg.Vault.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("keystore: vault: %w", err)
		}
		return vaultks.New(vaultks.Config{
			Address: cfg.Vault.Address,
			Token:   token,
			Mount:   cfg.Vault.Mount,
		})

	default:
		return nil, fmt.Errorf("keystore: unknown backend %q", cfg.Backend)
	}
}

// buildReadyzChecks builds the composer's /readyz check list.
// Includes ledger + artifact-store HTTP reachability when their
// respective endpoints are configured. An unset endpoint is
// silently skipped — the composer's /readyz returns 200 only
// when EVERY configured check passes; missing checks neither
// pass nor fail.
func buildReadyzChecks(cfg config.Operational) []observability.ReadyCheck {
	var checks []observability.ReadyCheck
	if cfg.LedgerEndpoint != "" {
		checks = append(checks, observability.CheckHTTPGet(
			"ledger", cfg.LedgerEndpoint+"/healthz"))
	}
	if cfg.ArtifactStoreEndpoint != "" {
		checks = append(checks, observability.CheckHTTPGet(
			"artifact_store", cfg.ArtifactStoreEndpoint+"/healthz"))
	}
	return checks
}

// buildAuthenticator constructs the composer-level Authenticator from
// cfg.Mode. Returns:
//
//	mtls → middleware.MTLSAuth{} (composer's listener already verifies
//	       the cert chain when ClientCAFile is set; this middleware
//	       lifts the SAN URI DID into request context).
//	jwt  → *middleware.JWTAuth fetched against cfg.JWKSURL.
//	""   → nil, nil (no auth; dev / single-process deployments).
//
// Any other Mode value is a config-validation failure and never
// reaches here — config.Validate rejects unknown modes at boot.
func buildAuthenticator(cfg config.AuthConfig) (middleware.Authenticator, error) {
	switch cfg.Mode {
	case config.AuthModeMTLS:
		return middleware.MTLSAuth{}, nil
	case config.AuthModeJWT:
		return middleware.NewJWTAuth(middleware.JWTConfig{
			Issuer:  cfg.JWTIssuer,
			JWKSURL: cfg.JWKSURL,
		})
	case "":
		return nil, nil
	default:
		return nil, fmt.Errorf("authenticator: unknown auth mode %q", cfg.Mode)
	}
}

// buildGossipStore constructs the gossip.Store shared by the serve feed
// and (when wired) inbound persistence. A configured PostgresDSN yields
// a durable PostgresStore (the JN's sovereign auditor memory, surviving
// restarts); an empty DSN falls back to the in-memory store so dev/test
// boots stay dependency-free. Returns the store plus a closer the caller
// defers on shutdown.
func buildGossipStore(cfg config.Operational, logger *slog.Logger) (gossip.Store, func(context.Context) error, error) {
	if cfg.GossipStore.PostgresDSN == "" {
		logger.Warn("gossip store: no PostgresDSN configured; using in-memory store (NOT durable across restarts)")
		store := gossip.NewInMemoryStore()
		return store, store.Close, nil
	}

	db, err := sql.Open("postgres", cfg.GossipStore.PostgresDSN)
	if err != nil {
		return nil, nil, fmt.Errorf("gossip store: open postgres: %w", err)
	}
	maxConns := cfg.GossipStore.MaxOpenConns
	if maxConns <= 0 {
		maxConns = 8
	}
	db.SetMaxOpenConns(maxConns)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("gossip store: ping postgres: %w", err)
	}
	store, err := gossipfeed.NewPostgresStore(db)
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("gossip store: %w", err)
	}
	if err := store.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("gossip store: migrate: %w", err)
	}
	logger.Info("gossip store: durable Postgres backend ready (peer_gossip)")
	return store, store.Close, nil
}

// buildGossipFeed constructs the SDK gossip feed mount over the supplied
// store when cfg.GossipFeed.Enabled is true. Returns (nil, nil) when
// disabled — api.NewServer treats a nil Gossip as "skip mount." The
// store is shared (not owned) here; the caller owns its lifecycle.
func buildGossipFeed(cfg config.Operational, store gossip.Store) (*gossipfeed.Feed, error) {
	if !cfg.GossipFeed.Enabled {
		return nil, nil
	}
	feed, err := gossipfeed.NewFeedMount(gossipfeed.FeedConfig{
		Store:      store,
		PathPrefix: cfg.GossipFeed.PathPrefix,
	})
	if err != nil {
		return nil, fmt.Errorf("gossip feed mount: %w", err)
	}
	return feed, nil
}
