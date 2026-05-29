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
	"github.com/clearcompass-ai/attesta-tools/libs/sdkguard"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/did"
	sdkauth "github.com/clearcompass-ai/attesta/exchange/auth"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/judicial-network/api"
	"github.com/clearcompass-ai/judicial-network/api/config"
	authv2 "github.com/clearcompass-ai/judicial-network/api/exchange/auth/v2"
	"github.com/clearcompass-ai/judicial-network/api/exchange"
	"github.com/clearcompass-ai/judicial-network/api/exchange/handlers"
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
	// applies). The *http.Client is the hoisted outbound client used
	// for JWKS fetches in JWT mode (libs/v1.29.0 requires non-nil).
	newAuthenticator func(config.AuthConfig, *http.Client) (middleware.Authenticator, error)

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

	// Exchange→ledger mTLS client: composed ONCE at boot so the entire
	// outbound surface (admission write path AND judicial reads —
	// /v1/log-info discovery, entry fetchers, query APIs, checkpoint
	// client, content-store push) shares one pool + retry semantics +
	// cert material. Fail-closed when cert/key are set but the
	// material is unreadable. When both are empty (dev / pre-cert
	// deploys pointing at a plaintext ledger), nil propagates and
	// every SDK constructor falls back to its server-verify-only
	// default. Production ledgers refuse non-mTLS connections at the
	// transport layer (ledger/api/server.go::buildServerTLSConfig).
	//
	// Built BEFORE the authenticator so the JWT-mode JWKS fetch shares
	// the same operator-chosen mTLS posture (libs/v1.29.0 JWTConfig
	// rejects a nil Client to prevent silent demotion).
	var ledgerSubmitClient *http.Client
	if cfg.LedgerCertFile != "" || cfg.LedgerKeyFile != "" {
		ledgerSubmitClient, err = exchange.BuildLedgerSubmitClient(exchange.ServerConfig{
			LedgerCert: cfg.LedgerCertFile,
			LedgerKey:  cfg.LedgerKeyFile,
			LedgerCA:   cfg.LedgerCAFile,
		})
		if err != nil {
			return fmt.Errorf("ledger submit client: %w", err)
		}
	}

	// Construct the composer-level authenticator (mTLS or JWT) per
	// cfg.Auth.Mode. nil return means "no composer auth"; the
	// constituent handlers' own auth still applies. JWT mode threads
	// the hoisted outbound client (or http.DefaultClient in dev) into
	// the JWKS fetcher.
	authClient := ledgerSubmitClient
	if authClient == nil {
		authClient = http.DefaultClient
	}
	authenticator, err := d.newAuthenticator(cfg.Auth, authClient)
	if err != nil {
		return fmt.Errorf("authenticator: %w", err)
	}

	// Build the judicial-domain Dependencies. The composer mounts
	// /v1/judicial/ regardless; the deps decide which handlers can
	// actually fulfil their work vs. surface a clean 500 / 501. The
	// mTLS client (when configured) is threaded into every SDK call
	// that touches the ledger.
	judicialDeps, err := buildJudicialDeps(cfg, registry, ledgerSubmitClient)
	if err != nil {
		return fmt.Errorf("judicial deps: %w", err)
	}

	// T7: assert the v1.32+ authoritative resolver is properly populated
	// when present. In strict mode (ATTESTA_FAIL_ON_PLAINTEXT_FALLBACK=true)
	// a misconfigured resolver panics at boot rather than at first lookup;
	// no-op in dev. Skip when the resolver is nil (no bootstrap configured,
	// dev / pre-cert deployments).
	if judicialDeps.AuthoritativeResolver != nil {
		sdkguard.AssertResolverPopulated(judicialDeps.AuthoritativeResolver, "jn-authoritative-resolver")
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
	// nil when GossipIngest is disabled / has no peers. judicialDeps is passed
	// in so the reconciler can install the v1.33.x auditor-scope gate inputs
	// (AuditorRegistry, AuditorAmendments, AuditorScopeAsOf).
	gossipPuller, trustedHeads, _, err := buildGossipIngest(cfg, sigVerifier, judicialDeps, slog.Default())
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

	// Gate-5 issuance (gating axis): load the JN's on-log admission EOA (J) from
	// API_ADMISSION_AUTHORITY_KEY_FILE. When set, the exchange mints + attaches a
	// detached WriteAuthorization to every forwarded write; the ledger verifies it
	// against its current admission keyset and drops it. Unset → no attach
	// (ungated logs / dev).
	//
	// ZERO-TRUST anchor: the as-of anchor is a WITNESS-COSIGNED, verified horizon
	// (sdklog.FetchVerifiedHorizon over the per-log K-of-N cosign.WitnessKeySet —
	// the same trust root VerifyingLeafReader uses), NOT the ledger's unverified
	// /v1/tree/head word. Fail-closed: no witness set for the log ⇒ refuse to mint.
	var admissionAuthorizer *handlers.AdmissionAuthorizer
	if keyFile := os.Getenv("API_ADMISSION_AUTHORITY_KEY_FILE"); keyFile != "" {
		anchorWitnessSets, wErr := buildWitnessSets(cfg)
		if wErr != nil {
			return fmt.Errorf("admission anchor witness sets: %w", wErr)
		}
		// SDK v1.26.0: HTTPCheckpointClientConfig.Client is required. Reuse
		// the boot-wired mTLS client (or a plain default) so the admission
		// authorizer's verified-horizon fetch presents the JN's cert.
		anchorHTTPClient := ledgerSubmitClient
		if anchorHTTPClient == nil {
			anchorHTTPClient = sdklog.DefaultClient(15*time.Second, nil)
		}
		checkpointClient, ccErr := sdklog.NewHTTPCheckpointClient(sdklog.HTTPCheckpointClientConfig{
			BaseURL: cfg.LedgerEndpoint,
			Client:  anchorHTTPClient,
		})
		if ccErr != nil {
			return fmt.Errorf("admission anchor checkpoint client: %w", ccErr)
		}
		verifiedAnchor := func(logDID string) ([32]byte, error) {
			set := anchorWitnessSets[logDID]
			if set == nil {
				return [32]byte{}, fmt.Errorf("no witness set for log %q — cannot verify anchor (fail-closed)", logDID)
			}
			actx, acancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer acancel()
			head, hErr := checkpointClient.FetchVerifiedHorizon(actx, set)
			if hErr != nil {
				return [32]byte{}, fmt.Errorf("verified horizon for %q: %w", logDID, hErr)
			}
			return head.RootHash, nil
		}
		admissionAuthorizer, err = handlers.LoadAdmissionAuthorizer(keyFile, verifiedAnchor)
		if err != nil {
			return fmt.Errorf("admission authorizer: %w", err)
		}
	}

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
	readyzChecks := buildReadyzChecks(cfg, ledgerSubmitClient)

	// ledgerSubmitClient was built once at boot above (see the
	// hoisted construction near buildJudicialDeps) so the exchange
	// AND the judicial deps share the same outbound client.

	// v2 signed-request auth middleware. Carries:
	//   - did:key signature verifier (matches the JN's Ed25519
	//     signer-DID convention; production adds did:web/did:pkh
	//     as their consumers come on-log).
	//   - Per-destination nonce stores from buildNonceStores.
	//   - A process-local fallback nonce store for empty /
	//     unknown destination requests.
	//   - mTLS SAN-cert extractor so mTLS requests bypass the
	//     envelope check (same posture as pre-v2).
	authRegistry := did.NewVerifierRegistry()
	if regErr := authRegistry.Register("key", did.NewKeyVerifier()); regErr != nil {
		return fmt.Errorf("auth registry: did:key register: %w", regErr)
	}
	signerAuth, err := authv2.NewSignerAuth(authv2.SignerAuthConfig{
		Registry:                  authRegistry,
		AlgoID:                    envelope.SigAlgoEd25519,
		PerDestinationNonceStores: nonceStores,
		FallbackNonceStore:        sdkauth.NewInMemoryNonceStore(),
		MTLSExtractor:             authv2.SANCertExtractor{},
	})
	if err != nil {
		return fmt.Errorf("signer auth: %w", err)
	}

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
			LedgerCert:            cfg.LedgerCertFile,
			LedgerKey:             cfg.LedgerKeyFile,
			LedgerCA:              cfg.LedgerCAFile,
			ArtifactStoreEndpoint: cfg.ArtifactStoreEndpoint,
			VerificationEndpoint:  cfg.VerificationEndpoint,
			KeyStore:              ks,
			Index:                 index.NewLogIndex(),
			SignerAuth:            signerAuth,
			LedgerBreaker:         ledgerBreaker,
			LedgerMetrics:         ledgerMetrics,
			// SDK-wired content store: same instance the judicial deps hold.
			// Carries the mTLS client when configured; nil ⇒ the artifact-
			// publish handler surfaces 503.
			ContentStore: judicialDeps.ContentStore,
			// mTLS client for the exchange→ledger hop. nil when no cert/key are
			// configured (dev/test against a plaintext ledger) — exchange falls
			// back to the SDK's server-verify-only client in that case. In
			// production this must be wired: the ledger's TLS listener refuses
			// connections without a verified client cert.
			LedgerSubmitClient: ledgerSubmitClient,
			// Per-jurisdiction admission gate: cosignature policy +
			// prerequisite walker on POST /v1/entries/submit, resolved
			// from the same frozen Bundle registry. Without this the
			// submit path is a pass-through proxy (the gate is dormant).
			SubmitGate: exchange.NewBundleSubmitGate(registry),
			// Gate-5 issuance: mint+attach a WriteAuthorization on every forwarded
			// write when J is configured (nil → ungated proxy).
			AdmissionAuthorizer: admissionAuthorizer,
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
			// VerifyConsistencyHandler's Static-CT tile fetcher carries
			// this client cert when peer mTLS is in effect; nil falls
			// back to a plain 15s client for dev / pre-cert deployments.
			LedgerHTTPClient: ledgerSubmitClient,
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

// ──────────────────────────────────────────────────────────────────
// Boot helpers
// ──────────────────────────────────────────────────────────────────

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
	// DIDs — identical on native / docker / k8s. May discover the source log's
	// gossip-originator did:key from the ledger's /v1/log-info (bounded).
	dctx, dcancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer dcancel()
	cfg, err = applyBootstrapDerivations(dctx, cfg)
	if err != nil {
		return config.Operational{}, fmt.Errorf("%w: %w", config.ErrInvalidConfig, err)
	}
	// Resolve any did:web gossip-peer base to its AttestaLedger endpoint (parity
	// with the auditor's AUDITOR_PEERS did:web form). No-op when ingest is off or
	// every peer base is already an http(s) URL.
	if cfg.GossipIngest.Enabled && len(cfg.GossipIngest.Peers) > 0 {
		resolved, rerr := resolveGossipPeerEndpoints(dctx, cfg.GossipIngest.Peers,
			newDIDWebPeerResolver(cfg.GossipIngest.PeerResolveTTL))
		if rerr != nil {
			return config.Operational{}, fmt.Errorf("%w: %w", config.ErrInvalidConfig, rerr)
		}
		cfg.GossipIngest.Peers = resolved
	}
	if err := cfg.Validate(); err != nil {
		return config.Operational{}, err
	}
	return cfg, nil
}
