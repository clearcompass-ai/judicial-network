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
  - It does NOT touch the ledger. The ledger is a separate
    upstream service the api/ talks to over HTTP.
*/
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	middleware "github.com/clearcompass-ai/attesta-tools/libs/httpmw"
	"github.com/clearcompass-ai/attesta-tools/libs/httpmw/observability"
	"github.com/clearcompass-ai/attesta-tools/libs/httpmw/reliability"
	"github.com/clearcompass-ai/attesta-tools/libs/keystore"
	"github.com/clearcompass-ai/judicial-network/api"
	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/exchange"
	"github.com/clearcompass-ai/judicial-network/api/exchange/index"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
	"github.com/clearcompass-ai/judicial-network/api/verification"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// shutdownTimeout caps how long Shutdown will wait for in-flight
// requests to drain before forcing close.
const shutdownTimeout = 30 * time.Second

// Version is the build version, stamped at link time via
// -ldflags "-X main.Version=...". Defaults to "dev" for un-stamped builds.
var Version = "dev"

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
	// KeyStore for the "memory" backend; future  wires
	// PKCS#11 / Vault here.
	newKeyStore func(config.KeyStoreConfig) (keystore.KeyStore, error)

	// newAuthenticator builds the composer-level Authenticator from
	// cfg.Auth (mtls or jwt). realDeps points at buildAuthenticator;
	// tests substitute a stub that authenticates with a fixed DID.
	// Returning nil + nil means "no composer auth"; the composer
	// then runs unwrapped (constituent handlers' own auth still
	// applies).
	newAuthenticator func(config.AuthConfig) (middleware.Authenticator, error)

	// requireLedger enforces the JN's hard dependency on the ledger at
	// boot: the network is an AUDITOR of a ledger and has no purpose
	// without one, so the binary refuses to start unless the ledger is
	// reachable. realDeps points at probeLedgerReachable (a real HTTP
	// probe with bounded retries); tests substitute a no-op so booting
	// does not require a live ledger.
	requireLedger func(context.Context, config.Operational) error
}

func realDeps() deps {
	return deps{
		registerBundles:  registerProductionBundles,
		newKeyStore:      buildKeyStore,
		newAuthenticator: buildAuthenticator,
		requireLedger:    probeLedgerReachable,
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

	// The JN is the Smart Edge over a ledger — an auditor with no purpose
	// without one. Refuse to start unless the ledger is reachable. /readyz
	// keeps it honest after boot; this keeps it honest AT boot. Injected via
	// deps so tests don't need a live ledger.
	if err := d.requireLedger(context.Background(), cfg); err != nil {
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

	// Construct the keystore.  swaps this for HSM / Vault
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

	// Build the native v1.7.1 signature verifier for the Path C
	// admission gate (/v1/verify/complete). Reuse the judicial deps'
	// DID resolver when it was wired (production); otherwise build a
	// standalone resolver so EOA + did:key + did:web verification is
	// live even in ledger-less dev mode. EIP-1271 K-of-N is added
	// when cfg.SmartContractWallet.Enabled is set.
	sigResolver := judicialDeps.Resolver
	if sigResolver == nil {
		sigResolver, err = buildDIDResolver()
		if err != nil {
			return fmt.Errorf("did resolver for signature verifier: %w", err)
		}
	}
	sigVerifier, err := buildSignatureVerifier(cfg, sigResolver)
	if err != nil {
		return fmt.Errorf("signature verifier: %w", err)
	}

	// Inbound gossip anti-entropy (verify-only): pull peer feeds, re-verify
	// each event (envelope + finding proof) against JN-local trust, and advance
	// JN's trusted view. The JN hosts NO durable store and serves NO feed —
	// custody of evidence is the external auditor's role (Separation of Duties).
	// nil when GossipIngest is disabled / has no peers.
	gossipPuller, trustedHeads, err := buildGossipIngest(cfg, sigVerifier, slog.Default())
	if err != nil {
		return fmt.Errorf("gossip ingest: %w", err)
	}
	// Surface the verify-only ingest's trusted-head view read-only via
	// GET /v1/judicial/monitoring/peer-consistency. The source DIDs are the
	// configured gossip peers' log DIDs (= the source logs the store records).
	judicialDeps.TrustedHeads = trustedHeads
	for _, p := range cfg.GossipIngest.Peers {
		judicialDeps.TrustedSources = append(judicialDeps.TrustedSources, p.LogDID)
	}

	//  observability bundle is constructed once and shared
	// between the composer's /metrics endpoint and the ledger-
	// submit metrics so all jn_* metrics scrape from one registry.
	obs := api.NewObservability()

	//  ledger-submit protection: circuit breaker +
	// per-submit metrics. Both wired into Exchange config.
	ledgerBreaker := reliability.NewBreaker(reliability.DefaultCircuitConfig())
	ledgerMetrics := observability.NewLedgerSubmitMetrics(obs.Metrics())

	// Continuous-monitoring scheduler: autonomous audits (mirror /
	// anchor / sealing) + gossip retention prune, publishing per-job OTel
	// health gauges (jn_monitor_*). nil when disabled. Built before the
	// listener so a misconfiguration aborts boot rather than failing in a
	// background goroutine.
	monScheduler, err := buildMonitoringScheduler(
		cfg, judicialDeps,
		observability.NewMonitoringMetrics(obs.Metrics()), slog.Default())
	if err != nil {
		return fmt.Errorf("monitoring scheduler: %w", err)
	}

	// Priority 3 /readyz checks: ledger + artifact-store
	// reachability via GET /healthz on each. k8s scrapes /readyz
	// to gate traffic to a replica that can fulfill its job.
	readyzChecks := buildReadyzChecks(cfg)

	srv, err := api.NewServer(api.Config{
		Addr:          cfg.ListenAddr,
		TLSCertFile:   cfg.Auth.TLSCertFile,
		TLSKeyFile:    cfg.Auth.TLSKeyFile,
		ClientCAFile:  cfg.Auth.ClientCAFile,
		Auth:          authenticator,
		Observability: obs,
		ReadyzChecks:  readyzChecks,
		Exchange: exchange.ServerConfig{
			LedgerEndpoint:        cfg.LedgerEndpoint,
			ArtifactStoreEndpoint: cfg.ArtifactStoreEndpoint,
			VerificationEndpoint:  cfg.VerificationEndpoint,
			KeyStore:              ks,
			Index:                 index.NewLogIndex(),
			NonceStores:           nonceStores,
			LedgerBreaker:         ledgerBreaker,
			LedgerMetrics:         ledgerMetrics,
			// Per-jurisdiction admission gate: cosignature policy +
			// prerequisite walker on POST /v1/entries/submit, resolved
			// from the same frozen Bundle registry. Without this the
			// submit path is a pass-through proxy (the gate is dormant).
			SubmitGate: exchange.NewBundleSubmitGate(registry),
		},
		Verification: verification.ServerConfig{
			// SignatureVerifier is the native v1.7.1 receipt-aware
			// verifier (did:key + did:pkh-EOA + did:web always live;
			// EIP-1271 K-of-N when SmartContractWallet.Enabled). It
			// implements both attestation.SignatureVerifier and
			// SignatureVerifierWithReceipt, so the Path C composite
			// collects per-signature Web3VerificationReceipts.
			SignatureVerifier: sigVerifier,
			// LogQueries + LeafReader complete the Path C composite:
			// /v1/verify/complete re-derives Merkle inclusion locally
			// (SDK smt.LeafReader + per-log LedgerQueryAPI) instead of
			// trusting the ledger's answer — the zero-trust "parse,
			// don't validate" read path. Shared with the judicial deps
			// so both surfaces read the same per-destination clients.
			// Nil in ledger-less dev mode (cfg.LedgerEndpoint empty),
			// where the inclusion stages return a clean error.
			LogQueries: judicialDeps.LogQueries,
			LeafReader: judicialDeps.LeafReader,
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

	// Start the inbound gossip puller (if configured) under the signal ctx so
	// it drains on shutdown. It is a background observer — it never blocks the
	// listener or the commit hot-path (the two-clock discipline).
	if gossipPuller != nil {
		go func() {
			if err := gossipPuller.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("network-api: gossip ingest stopped: %v", err)
			}
		}()
		log.Printf("network-api: gossip ingest pulling %d peer(s)", len(cfg.GossipIngest.Peers))
	}

	// Start the continuous-monitoring scheduler (if enabled) under the
	// signal ctx so its tickers stop on shutdown.
	if monScheduler != nil {
		go monScheduler.Run(ctx)
		log.Printf("network-api: monitoring scheduler running %d job(s)", monScheduler.Len())
	}

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
			// is layered in middleware — TLS material
			// is the ledger's responsibility in that case.
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
	// Derive the witness set + gossip peer from the (env-pointed) bootstrap
	// so the active auditor is configured by toggles + K, not hand-listed
	// DIDs — identical on native / docker / k8s.
	cfg, err = applyBootstrapDerivations(cfg)
	if err != nil {
		return config.Operational{}, fmt.Errorf("%w: %w", config.ErrInvalidConfig, err)
	}
	if err := cfg.Validate(); err != nil {
		return config.Operational{}, err
	}
	return cfg, nil
}
