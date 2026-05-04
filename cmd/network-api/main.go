/*
Command network-api is the JN judicial network API binary.

Boot order (every step is testable; see main_test.go):

  1. Parse --config flag and load operational config from JSON.
     Apply env overrides on top (precedence: env > file > defaults).
     Validate the merged config; abort fast on any failure.

  2. Register every compiled-in deployment Bundle into the
     jurisdiction.Registry. Each Bundle is its own deployment
     profile (definition-as-code; see deployments/.../bundle.go).
     Adding a new court is "import a new package + one
     registry.Register call" — no JSON, no DNS, no env DID.

  3. Freeze the registry. After Freeze the registry is read-only and
     reads are wait-free; this is the property the api/exchange
     hot-path relies on.

  4. Build per-destination NonceStore via cfg.BuildForExchange — one
     store per registered destination DID. With the redis backend a
     single shared connection serves all of them, namespaced by
     destination at the SDK layer.

  5. Compose api/exchange + api/verification under api.NewServer.
     Single listener, single TLS endpoint, single auth surface.

  6. Block on SIGINT / SIGTERM; on signal, drain via Shutdown.

What this binary does NOT do:

  - It does NOT load a court_did from JSON. Identities come from
    imported deployment packages — never from operational config.
    See api/config.Operational's docstring for the rule.
  - It does NOT run an aggregator, a tools/courts handler, or any
    helper. Helpers (tools/*) are clients, not composed in.
  - It does NOT touch the operator. The operator is a separate
    upstream service the api/ talks to over HTTP.
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/clearcompass-ai/judicial-network/api"
	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/exchange"
	"github.com/clearcompass-ai/judicial-network/api/exchange/index"
	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
	"github.com/clearcompass-ai/judicial-network/api/middleware"
	"github.com/clearcompass-ai/judicial-network/api/middleware/observability"
	"github.com/clearcompass-ai/judicial-network/api/middleware/reliability"
	"github.com/clearcompass-ai/judicial-network/api/verification"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// shutdownTimeout caps how long Shutdown will wait for in-flight
// requests to drain before forcing close.
const shutdownTimeout = 30 * time.Second

func main() {
	if err := run(os.Args[1:], realDeps()); err != nil {
		log.Fatalf("network-api: %v", err)
	}
}

// deps groups the boot-time injection points main_test substitutes.
// The real binary uses realDeps(); tests pass deps that fake out
// keystore construction and other side-effecting steps so booting
// does not require a real HSM or real Redis.
type deps struct {
	// registerBundles loads deployment Bundles into the supplied
	// registry. realDeps points this at registerProductionBundles
	// which imports davidson + coa + sup_ct. Tests can register a
	// no-op or a stub Bundle.
	registerBundles func(*jurisdiction.Registry) error

	// newKeyStore returns the keystore.KeyStore implementation for
	// the given KeyStore config. realDeps returns an in-memory
	// KeyStore for the "memory" backend; future Phase 8 wires
	// PKCS#11 / Vault here.
	newKeyStore func(config.KeyStoreConfig) (keystore.KeyStore, error)

	// newAuthenticator builds the composer-level Authenticator from
	// cfg.Auth (mtls or jwt). realDeps points at buildAuthenticator;
	// tests substitute a stub that authenticates with a fixed DID.
	// Returning nil + nil means "no composer auth"; the composer
	// then runs unwrapped (constituent handlers' own auth still
	// applies).
	newAuthenticator func(config.AuthConfig) (middleware.Authenticator, error)
}

func realDeps() deps {
	return deps{
		registerBundles:  registerProductionBundles,
		newKeyStore:      buildKeyStore,
		newAuthenticator: buildAuthenticator,
	}
}

// run is the testable entry point. main calls it with os.Args[1:]
// and realDeps; main_test calls it with crafted args and stub deps.
// run blocks until the server stops or shutdown completes.
func run(argv []string, d deps) error {
	cfg, err := loadConfig(argv)
	if err != nil {
		return err
	}

	registry := jurisdiction.NewRegistry()
	if err := d.registerBundles(registry); err != nil {
		return fmt.Errorf("register bundles: %w", err)
	}
	registry.Freeze()
	log.Printf("network-api: registered %d destination(s): %v",
		registry.Len(), registry.ExchangeDIDs())

	// Per-destination NonceStores. Passed into exchange.ServerConfig
	// below so SignedRequest replay defence is namespace-isolated per
	// destination (Redis backend) and falls back to the single in-
	// memory store when an unknown destination shows up.
	nonceStores, err := buildNonceStores(cfg, registry)
	if err != nil {
		return fmt.Errorf("nonce stores: %w", err)
	}

	// Construct the keystore. Phase 8 swaps this for HSM / Vault
	// backends; for now the binary supports the "memory" backend
	// out-of-the-box.
	ks, err := d.newKeyStore(cfg.KeyStore)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}

	// Construct the composer-level authenticator (mTLS or JWT) per
	// cfg.Auth.Mode. nil return means "no composer auth"; the
	// constituent handlers' own auth still applies.
	authenticator, err := d.newAuthenticator(cfg.Auth)
	if err != nil {
		return fmt.Errorf("authenticator: %w", err)
	}

	// Build the judicial-domain Dependencies. The composer mounts
	// /v1/judicial/ regardless; the deps decide which handlers can
	// actually fulfil their work vs. surface a clean 500 / 501.
	judicialDeps, err := buildJudicialDeps(cfg, registry)
	if err != nil {
		return fmt.Errorf("judicial deps: %w", err)
	}

	// Bind api/judicial's caller-DID resolver to the composer's
	// auth-set callerDID. Without this hook the judicial handlers
	// never see the authenticated caller — every request 401s. The
	// shim adapts middleware.CallerDIDFromContext (ctx-shaped) to
	// the request-shaped resolver api/judicial accepts.
	judicial.SetCallerDIDResolver(func(r *http.Request) string {
		return middleware.CallerDIDFromContext(r.Context())
	})

	// Phase 15 observability bundle is constructed once and shared
	// between the composer's /metrics endpoint and the operator-
	// submit metrics so all jn_* metrics scrape from one registry.
	obs := api.NewObservability()

	// Phase 14b operator-submit protection: circuit breaker +
	// per-submit metrics. Both wired into Exchange config.
	operatorBreaker := reliability.NewBreaker(reliability.DefaultCircuitConfig())
	operatorMetrics := observability.NewOperatorSubmitMetrics(obs.Metrics())

	// Priority 3 /readyz checks: operator + artifact-store
	// reachability via GET /healthz on each. k8s scrapes /readyz
	// to gate traffic to a replica that can fulfill its job.
	readyzChecks := buildReadyzChecks(cfg)

	srv, err := api.NewServer(api.Config{
		Addr:         cfg.ListenAddr,
		TLSCertFile:  cfg.Auth.TLSCertFile,
		TLSKeyFile:   cfg.Auth.TLSKeyFile,
		ClientCAFile: cfg.Auth.ClientCAFile,
		Auth:          authenticator,
		Observability: obs,
		ReadyzChecks:  readyzChecks,
		Exchange: exchange.ServerConfig{
			OperatorEndpoint:      cfg.OperatorEndpoint,
			ArtifactStoreEndpoint: cfg.ArtifactStoreEndpoint,
			VerificationEndpoint:  cfg.VerificationEndpoint,
			KeyStore:              ks,
			Index:                 index.NewLogIndex(),
			NonceStores:           nonceStores,
			OperatorBreaker:       operatorBreaker,
			OperatorMetrics:       operatorMetrics,
		},
		Verification: verification.ServerConfig{
			// Phase 7 wires real LogQueries + LeafReader from the
			// operator/aggregator surface. For boot-time the
			// verification handler tree is registered with empty deps;
			// any /v1/verify/* request reaching it returns a clean
			// "unknown log" error rather than a panic.
		},
		Judicial: judicial.ServerConfig{Deps: judicialDeps},
	})
	if err != nil {
		return fmt.Errorf("compose server: %w", err)
	}

	// Signal handling: SIGINT / SIGTERM trigger a graceful drain.
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run the listener in a goroutine; main goroutine waits on
	// either the server exiting (error) or the context being
	// cancelled (signal).
	serverErr := make(chan error, 1)
	go func() {
		switch cfg.Auth.Mode {
		case config.AuthModeMTLS:
			serverErr <- srv.StartTLS()
		default:
			// Plain HTTP for dev / non-mTLS deployments. JWT auth
			// is layered in middleware (Phase 5) — TLS material
			// is the operator's responsibility in that case.
			serverErr <- srv.Start()
		}
	}()

	select {
	case err := <-serverErr:
		// Listener exited on its own; surface the error verbatim.
		return fmt.Errorf("server: %w", err)
	case <-ctx.Done():
		log.Printf("network-api: signal received; shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Boot helpers
// ─────────────────────────────────────────────────────────────────────

// loadConfig parses --config flag, loads the JSON file (if any),
// applies env overrides, and validates. Returns the merged config.
func loadConfig(argv []string) (config.Operational, error) {
	fs := flag.NewFlagSet("network-api", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to operational config JSON; empty = use defaults + env")
	if err := fs.Parse(argv); err != nil {
		return config.Operational{}, fmt.Errorf("parse flags: %w", err)
	}

	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		return config.Operational{}, err
	}
	cfg = config.ApplyEnvOverrides(cfg)
	if err := cfg.Validate(); err != nil {
		return config.Operational{}, err
	}
	return cfg, nil
}

