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

	"github.com/baseproof/baseproof/core/envelope"
	sdkauth "github.com/baseproof/baseproof/exchange/auth"
	sdklog "github.com/baseproof/baseproof/log"
	middleware "github.com/baseproof/tooling/libs/httpmw"
	"github.com/baseproof/tooling/libs/httpmw/observability"
	"github.com/baseproof/tooling/libs/httpmw/reliability"
	"github.com/baseproof/tooling/libs/keystore"
	"github.com/baseproof/tooling/libs/sdkguard"
	"github.com/baseproof/tooling/libs/tracing"
	"github.com/clearcompass-ai/judicial-network/api"
	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/exchange"
	authv2 "github.com/clearcompass-ai/judicial-network/api/exchange/auth/v2"
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

	// Tracing: install the global W3C propagator (so the JN edge starts a trace
	// that the ledger/witness continue) and export the JN's own spans when
	// NETWORK_API_OTLP_TRACES_ENDPOINT is set. Always returns a usable shutdown.
	traceShutdown, err := tracing.Setup(tracing.Config{
		ServiceName: "network-api",
		Endpoint:    os.Getenv("NETWORK_API_OTLP_TRACES_ENDPOINT"),
	})
	if err != nil {
		return fmt.Errorf("tracing setup: %w", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = traceShutdown(ctx)
	}()

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
	if err := requireLedgerMTLS(cfg.LedgerEndpoint, cfg.LedgerCertFile, cfg.LedgerKeyFile, cfg.LedgerAllowPlaintext, cfg.LedgerAllowSelfSigned, cfg.LedgerCAFile); err != nil {
		return err
	}
	var ledgerSubmitClient *http.Client
	switch {
	case cfg.LedgerCertFile != "" || cfg.LedgerKeyFile != "":
		ledgerSubmitClient, err = exchange.BuildLedgerSubmitClient(exchange.ServerConfig{
			LedgerCert: cfg.LedgerCertFile,
			LedgerKey:  cfg.LedgerKeyFile,
			LedgerCA:   cfg.LedgerCAFile,
		})
		if err != nil {
			return fmt.Errorf("ledger submit client: %w", err)
		}
	case cfg.LedgerAllowSelfSigned:
		// Open HTTPS: pin the ledger CA, present no client cert. Threaded into
		// every SDK call so the privately-signed ledger verifies (server-verify),
		// instead of the nil-client fallback to system roots.
		ledgerSubmitClient, err = exchange.BuildLedgerServerVerifyClient(cfg.LedgerCAFile)
		if err != nil {
			return fmt.Errorf("ledger server-verify client: %w", err)
		}
	}
	// Trace + propagate on the single outbound ledger surface: every admission
	// write and judicial read carries a client span and injects traceparent, so
	// the ledger's admission SERVER span continues THIS request's trace.
	if ledgerSubmitClient != nil {
		ledgerSubmitClient.Transport = sdklog.WithOTel(ledgerSubmitClient.Transport)
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
	// FED-1 #107: era-correct witness-set resolution — the shared rotation
	// journal (fed by the gossip reconcilers below) + the resolver every
	// cross-log verify path consumes. Built BEFORE deps so both servers and
	// the ingest pipelines share one journal and one resolver.
	eraResolver, rotJournal, err := buildEraResolution(cfg, slog.Default())
	if err != nil {
		return fmt.Errorf("era resolution: %w", err)
	}

	judicialDeps, err := buildJudicialDeps(cfg, registry, ledgerSubmitClient, eraResolver)
	if err != nil {
		return fmt.Errorf("judicial deps: %w", err)
	}

	// T7: assert the v1.32+ authoritative resolver is properly populated
	// when present. In strict mode (BASEPROOF_FAIL_ON_PLAINTEXT_FALLBACK=true)
	// a misconfigured resolver panics at boot rather than at first lookup;
	// no-op in dev. Skip when the resolver is nil (no bootstrap configured,
	// dev / pre-cert deployments).
	if judicialDeps.AuthoritativeResolver != nil {
		sdkguard.AssertResolverPopulated(judicialDeps.AuthoritativeResolver, "jn-authoritative-resolver")
	}

	// PRE-13b #181 (G19): wire the verifying AuthorityChainResolver into
	// the Bundle seam so the cosignature gate checks each cosigner's
	// claimed role against its on-log delegation chain. No-op (seam stays
	// closed → fail-closed) when the ledger inputs are absent.
	wireAuthorityResolvers(judicialDeps.Fetcher, judicialDeps.LeafReader)

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
	//
	// v1.34+ MULTI-NETWORK: one pipeline per home network + one per
	// cfg.GossipIngest.PeerLogs entry. All pipelines share the same
	// TrustedHeadStore + HeadsJournal so cross-log reads see a unified
	// worldview (LogDID-keyed, globally unique).
	gossipPipelines, err := buildGossipIngest(cfg, sigVerifier, rotJournal, judicialDeps, slog.Default())
	if err != nil {
		return fmt.Errorf("gossip ingest: %w", err)
	}
	// Surface the verify-only ingest's trusted-head view + durable
	// archive to the judicial handlers. The source DIDs are the
	// configured gossip peers' log DIDs (home) PLUS each foreign
	// PeerLog's LogDID (multi-network enumeration).
	judicialDeps.TrustedHeads = gossipPipelines.Heads
	judicialDeps.HeadsJournal = gossipPipelines.Journal
	for _, p := range cfg.GossipIngest.Peers {
		judicialDeps.TrustedSources = append(judicialDeps.TrustedSources, p.LogDID)
	}
	for _, pl := range cfg.GossipIngest.PeerLogs {
		judicialDeps.TrustedSources = append(judicialDeps.TrustedSources, pl.LogDID)
	}

	// C-3: assemble the cross-network LogTrustProvider once the
	// journal + per-log Fetcher/LeafReader are in place. Returns nil
	// when no foreign PeerLogs are configured — call sites then keep
	// using trust.NewLocalTrust (the v1.33 single-network path).
	multiTrust, err := buildMultiJurisdictionTrust(cfg, judicialDeps, gossipPipelines.Journal)
	if err != nil {
		return fmt.Errorf("build multi-jurisdiction trust: %w", err)
	}
	judicialDeps.MultiTrust = multiTrust

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
	// Standard-path fallback: env wins; else a Secret mounted at the conventional
	// path is picked up with zero env (the orchestrator-agnostic convention).
	keyFile := os.Getenv("API_ADMISSION_AUTHORITY_KEY_FILE")
	if keyFile == "" {
		if info, err := os.Stat("/etc/network-api/keys/admission-authority.pem"); err == nil && !info.IsDir() {
			keyFile = "/etc/network-api/keys/admission-authority.pem"
		}
	}
	if keyFile != "" {
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
	//   - the FULL-method DID verifier registry (did:pkh + did:key +
	//     did:web) — the same registry the entry-signature path uses, so
	//     a did:web or did:pkh signer is never SILENTLY rejected as
	//     "method not registered" (an unsupported algorithm now fails
	//     with a specific error). The signed-request signature algorithm
	//     is still pinned by AlgoID below (Ed25519, the JN signer-DID
	//     convention); per-request algorithm negotiation is a separate
	//     SDK-coordinated change (see auth/v2/doc.go).
	//   - Per-destination nonce stores from buildNonceStores.
	//   - A process-local fallback nonce store for empty /
	//     unknown destination requests.
	//   - mTLS SAN-cert extractor so mTLS requests bypass the
	//     envelope check (same posture as pre-v2).
	authRegistry, err := buildVerifierRegistry(cfg, sigResolver)
	if err != nil {
		return fmt.Errorf("auth registry: %w", err)
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

	// Network consumption manifest (GET /v1/network/bundle) — the describe
	// projection of the SAME frozen registry the SubmitGate enforces with.
	manifestHandler, err := buildManifestHandler(registry, cfg.LedgerEndpoint, ledgerSubmitClient, admissionAuthorizer != nil)
	if err != nil {
		return fmt.Errorf("network manifest handler: %w", err)
	}

	srv, err := api.NewServer(api.Config{
		Addr:          cfg.ListenAddr,
		TLSCertFile:   cfg.Auth.TLSCertFile,
		TLSKeyFile:    cfg.Auth.TLSKeyFile,
		ClientCAFile:  cfg.Auth.ClientCAFile,
		Auth:          authenticator,
		Observability: obs,
		ReadyzChecks:  readyzChecks,
		Manifest:      manifestHandler,
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
			// PAYMENT axis (Mode A): the JN's credit-session Bearer token, relayed
			// on every forwarded write so the ledger authenticates it → skips Mode B
			// PoW + deducts a credit (its balance>0 gate is the backstop). Empty ⇒
			// Mode B (the entry carries its own PoW stamp). Orthogonal to the gating
			// attach above; a gated network needs both.
			LedgerCreditToken: os.Getenv("API_LEDGER_CREDIT_TOKEN"),
		},
		Verification: verification.ServerConfig{
			// FED-1 #107: era-correct source-set resolution for cross-log verify.
			Eras: eraResolver,
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
			// C-4: thread the cross-network LogTrustProvider so the
			// VerifyAuthority + VerifyBatch handlers dispatch trust
			// identically to the judicial surface (one provider, two
			// HTTP-facing surfaces). nil when no foreign PeerLogs are
			// declared — handlers then fall back to per-request
			// LocalTrust (v1.33 byte-for-byte equivalent).
			MultiTrust: judicialDeps.MultiTrust,
			// SDK-4 + ZT-IMM-01: the shared heads journal backs cross-log
			// burn gating (TrustStatus) and historical ?as_of=N head pins.
			Journal: judicialDeps.HeadsJournal,
			// Read-side crypto-aware cosignature verification
			// (/v1/verify/cosignature) resolves the destination bundle's
			// cosignature policy via the SAME registry the submit gate uses,
			// so the auditor re-derives the identical per-jurisdiction rule
			// table — only crypto-verified (CheckCosignatureWithVerifier runs
			// attestation.VerifyEntrySignatures first).
			Registry: registry,
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

	// Start every inbound gossip puller (home + per foreign PeerLog) under
	// the signal ctx so they drain on shutdown. Each pipeline is a
	// background observer — none blocks the listener or the commit
	// hot-path (the two-clock discipline). All pipelines write through to
	// the SHARED TrustedHeadStore + HeadsJournal so cross-log reads see
	// a unified worldview.
	for i, puller := range gossipPipelines.Pullers {
		puller := puller
		i := i
		go func() {
			if err := puller.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("network-api: gossip pipeline %d stopped: %v", i, err)
			}
		}()
	}
	if n := len(gossipPipelines.Pullers); n > 0 {
		log.Printf("network-api: gossip ingest running %d pipeline(s) — %d home peer(s), %d foreign peer log(s)",
			n, len(cfg.GossipIngest.Peers), len(cfg.GossipIngest.PeerLogs))
	}

	// D13: hot-reload the v1.33.x auditor-scope gate inputs on
	// SIGHUP. No-op unless cfg.AuditorScope.ReloadOnSIGHUP=true AND
	// the home Reconciler is wired AND at least one of
	// RegistryFile / AmendmentFile is configured. See cmd/network-
	// api/sighup_reload.go for the per-file fault-tolerance contract.
	runSIGHUPReload(ctx, cfg, gossipPipelines.HomeReconciler, slog.Default())

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
	// Resolve any did:web gossip-peer base to its BaseproofLedger endpoint (parity
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
