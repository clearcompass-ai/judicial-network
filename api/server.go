/*
Package api is the JN network's common API surface composer.

A single api/ binary serves N destinations on ONE listener. The
binary mounts:

  - api/exchange     → all write paths (POST /v1/entries/...,
    /v1/artifacts/..., /v1/delegations,
    /v1/keys/..., /v1/dids, /v1/scope/...)
  - api/verification → all read paths (GET /v1/verify/...)
  - GET /healthz     → composer-owned aggregated health

Routing model is multi-tenant payload-driven (per the v1.6 invariant
in jurisdiction/registry.go): every entry's target destination is
sourced from entry.Header.Destination, which the per-handler logic
looks up in the Bundle Registry. The composer does NOT route by URL
prefix to a per-destination handler — there is exactly ONE handler
tree per route family, shared across all registered destinations.

What the composer DOES NOT do:

  - It does not run an aggregator, a tools/courts handler, or any
    other helper. Helpers (tools/*) are clients of this surface,
    never composed in.
  - It does not register Bundles. The cmd/network-api/main.go boot
    path does that against jurisdiction.Registry; the composer just
    receives wired-up sub-server configs.
  - It does not parse JSON config or read env. Operational config
    (api/config.Operational) is parsed by the binary and translated
    into the constituent ServerConfig structs the composer expects.

What the composer DOES guarantee:

  - Single listener; single TLS endpoint; single auth surface.
  - Per-route delegation: /v1/verify/* → verification handler,
    everything else under /v1/ → exchange handler. The longer-prefix
    rule of net/http.ServeMux makes this unambiguous.
  - Composer-owned /healthz that does NOT delegate to the
    constituents' /healthz (each constituent still has one for
    stand-alone deploys; under composition, the parent's wins).
  - Lifecycle (Start/Shutdown) over the unified http.Server.
*/
package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/exchange"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
	"github.com/clearcompass-ai/judicial-network/api/middleware"
	"github.com/clearcompass-ai/judicial-network/api/middleware/observability"
	"github.com/clearcompass-ai/judicial-network/api/openapi"
	"github.com/clearcompass-ai/judicial-network/api/verification"
	"github.com/clearcompass-ai/judicial-network/gossipfeed"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrInvalidConfig wraps composer-config validation failures.
var ErrInvalidConfig = errors.New("api: invalid composer configuration")

// ─────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────

// Config configures the composed api server. The TLS material here
// is what the unified listener uses; the constituent ServerConfigs'
// own TLS fields (e.g., exchange.ServerConfig.SignerCA) are unused
// under composition.
type Config struct {
	// Addr is the unified listener address. Required.
	Addr string

	// TLSCertFile / TLSKeyFile are the server's leaf cert and private
	// key. Required when ClientCAFile is set (mTLS) or when the
	// composer is started via StartTLS. Optional for plain-HTTP
	// dev (Start without TLS).
	TLSCertFile string
	TLSKeyFile  string

	// ClientCAFile is the CA pool that verifies client certs for
	// mTLS auth. When empty, mTLS is disabled and other auth modes
	// (JWT) are responsible for callerDID derivation.
	ClientCAFile string

	// Exchange and Verification are the per-surface configs the
	// composer feeds into BuildHandler on each constituent package.
	Exchange     exchange.ServerConfig
	Verification verification.ServerConfig

	// Judicial is the judicial-domain handler tree mounted at
	// /v1/judicial/. Optional — empty Deps.Registry means handlers
	// boot with no destinations registered (every route surfaces 401).
	Judicial judicial.ServerConfig

	// Gossip is the optional gossip-feed mount (Phase 4). nil → no
	// /v1/gossip/* surface. When non-nil, the composer registers the
	// mount under its configured PathPrefix and ALWAYS exposes it
	// unauthenticated so external auditors and CDNs can pull
	// findings without client certs. Trust Alignment 11: pure-pull
	// gossip with standard HTTP cache semantics.
	Gossip *gossipfeed.Feed

	// Auth is the optional composer-level authenticator (mTLS / JWT).
	// nil → no composer auth; constituent handlers' own auth still
	// applies. /healthz, /metrics, /v1/openapi.yaml are NEVER wrapped.
	Auth middleware.Authenticator

	// Reliability knobs. MaxBodyBytes: 0 = 1 MiB default,
	// -1 disables. PerRequestTimeout: 0 = no wrapper. GlobalRPS /
	// GlobalBurst: both 0 disables the global rate limiter.
	MaxBodyBytes      int64
	PerRequestTimeout time.Duration
	GlobalRPS         float64
	GlobalBurst       int

	// Observability bundle. nil → NewObservability().
	Observability *Observability

	// ReadyzChecks (Priority 3) populates the composer's /readyz
	// endpoint with ledger + artifact-store reachability checks.
	// Empty slice → /readyz always returns 200 ("nothing to check,
	// process is up"). Ledgers wire CheckHTTPGet helpers from
	// the observability package per-deployment.
	ReadyzChecks []observability.ReadyCheck

	// ReadTimeout / WriteTimeout / IdleTimeout cap each request's
	// lifecycle. Empty/zero values default to safe production values.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// validate enforces composer-level constraints. Per-constituent
// validation is the constituent's responsibility (exchange.NewServer
// would catch its own missing fields when called stand-alone; the
// composer is intentionally lighter so it can be exercised in tests
// without full TLS material).
func (cfg Config) validate() error {
	if cfg.Addr == "" {
		return fmt.Errorf("%w: Addr required", ErrInvalidConfig)
	}
	if cfg.ClientCAFile != "" && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
		return fmt.Errorf("%w: ClientCAFile (mTLS) requires TLSCertFile and TLSKeyFile", ErrInvalidConfig)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────────────────────────

// Server is the composed api server. Use NewServer to construct;
// call Start (or StartTLS) to listen and Shutdown for graceful exit.
type Server struct {
	cfg        Config
	httpServer *http.Server
}

// NewServer composes exchange + verification into one HTTP handler
// tree behind a unified http.Server. Returns ErrInvalidConfig on
// composer-level validation failure.
func NewServer(cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	// Constituent handlers. Build separately so each retains its own
	// internal route registration; the parent mux delegates by prefix.
	exchHandler := exchange.BuildHandler(cfg.Exchange)
	verifyHandler := verification.BuildHandler(cfg.Verification)
	judicialHandler := judicial.BuildHandler(cfg.Judicial)

	// Composer-level auth wraps every /v1/* delegated handler. When
	// cfg.Auth is nil (e.g., dev / test) the handlers run unwrapped.
	// /healthz is registered separately below and is NEVER wrapped —
	// liveness probes don't authenticate.
	if cfg.Auth != nil {
		exchHandler = cfg.Auth.Wrap(exchHandler)
		verifyHandler = cfg.Auth.Wrap(verifyHandler)
		judicialHandler = cfg.Auth.Wrap(judicialHandler)
	}

	// Reliability middleware. Outer→inner: RateLimitGlobal
	// → RequestTimeout → MaxBodyBytes → Auth → handler. /healthz +
	// /metrics + /readyz + /v1/openapi.yaml are NOT wrapped.
	exchHandler = wrapReliability(cfg, exchHandler)
	verifyHandler = wrapReliability(cfg, verifyHandler)
	judicialHandler = wrapReliability(cfg, judicialHandler)

	// Observability middleware. Outermost wrap so
	// request_id + metrics + logs see auth + reliability outcomes.
	if cfg.Observability == nil {
		cfg.Observability = NewObservability()
	}
	exchHandler = cfg.Observability.Wrap("/v1/exchange", exchHandler)
	verifyHandler = cfg.Observability.Wrap("/v1/verify", verifyHandler)
	judicialHandler = cfg.Observability.Wrap("/v1/judicial", judicialHandler)

	// Order of registration is irrelevant for net/http.ServeMux —
	// longest-matching-prefix wins. /v1/verify/ and /v1/judicial/ are
	// more specific than /v1/ so they always take precedence over the
	// exchange catch-all.
	mux.Handle("/v1/verify/", verifyHandler)
	mux.Handle("/v1/judicial/", judicialHandler)
	mux.Handle("/v1/", exchHandler)

	// Composer-owned health probe. Returns 200 unconditionally; the
	// constituent /healthz endpoints are shadowed under composition.
	// Future expansion: aggregate liveness from constituents (e.g.,
	// keystore reachable, ledger reachable). Ship the simple form
	// first; instrument later.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// /metrics — Prometheus scrape (unauth, no wrappers, static-
	// route labels keep cardinality bounded).
	mux.Handle("GET /metrics", cfg.Observability.MetricsHandler())

	// /readyz — readiness probe (Priority 3). 200 when every
	// configured check passes; 503 otherwise. Empty checks → 200.
	mux.Handle("GET /readyz", cfg.Observability.ReadyzHandler(cfg.ReadyzChecks))

	// OpenAPI 3.1 spec — served unauthenticated so external tooling
	// (Swagger UI, code generators) can fetch the canonical artifact
	// without a client cert. The spec bytes are embedded into the
	// binary at build time from api/openapi/openapi.yaml.
	mux.Handle("GET /v1/openapi.yaml", openapi.Handler())

	// Phase 4 — gossip pull feed. Mounted ONLY when explicitly
	// configured. The prefix is whatever the Feed was constructed
	// with; production deployments use gossip.DefaultFeedPathPrefix
	// ("/v1/gossip"). The feed is unauthenticated by design — its
	// payloads are already cryptographically self-verifying (every
	// SignedEvent carries its originator's signature), and the read
	// path is meant to be CDN-cacheable. Composer-level auth +
	// reliability middleware are intentionally NOT applied here.
	if cfg.Gossip != nil {
		prefix := cfg.Gossip.Prefix()
		if prefix == "" {
			prefix = "/v1/gossip"
		}
		// Trailing-slash form so net/http.ServeMux routes the full
		// /v1/gossip/since, /v1/gossip/by-binding, etc. subtree.
		if prefix[len(prefix)-1] != '/' {
			prefix += "/"
		}
		mux.Handle(prefix, cfg.Gossip)
	}

	// Default timeouts mirror api/exchange's stand-alone values.
	read := cfg.ReadTimeout
	if read <= 0 {
		read = 30 * time.Second
	}
	write := cfg.WriteTimeout
	if write <= 0 {
		write = 60 * time.Second
	}
	idle := cfg.IdleTimeout
	if idle <= 0 {
		idle = 120 * time.Second
	}

	srv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  read,
		WriteTimeout: write,
		IdleTimeout:  idle,
	}

	// mTLS configuration when a ClientCAFile is supplied. The composer
	// does NOT enforce a single auth mode — JWT is layered as
	// middleware on top . Today: TLS material is wired and
	// client-cert verification is on; absent ClientCAFile the listener
	// runs plain HTTPS with optional auth handled by middleware.
	if cfg.ClientCAFile != "" {
		tlsCfg, err := buildMTLSConfig(cfg.ClientCAFile)
		if err != nil {
			return nil, err
		}
		srv.TLSConfig = tlsCfg
	}

	return &Server{cfg: cfg, httpServer: srv}, nil
}

// Handler returns the composed http.Handler. Useful for tests that
// drive the surface via httptest without binding to a real port.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// Start begins listening with the configured timeouts. Use StartTLS
// for production deployments; Start is for plain-HTTP dev / tests.
// Blocks until Shutdown is called or a network error fires.
func (s *Server) Start() error {
	log.Printf("api: listening on %s (plain HTTP)", s.cfg.Addr)
	return s.httpServer.ListenAndServe()
}

// StartTLS begins listening with TLS using cfg.TLSCertFile and
// cfg.TLSKeyFile. mTLS is enforced when cfg.ClientCAFile is set.
// Blocks until Shutdown.
func (s *Server) StartTLS() error {
	if s.cfg.TLSCertFile == "" || s.cfg.TLSKeyFile == "" {
		return fmt.Errorf("%w: StartTLS requires TLSCertFile and TLSKeyFile", ErrInvalidConfig)
	}
	log.Printf("api: listening on %s (TLS)", s.cfg.Addr)
	return s.httpServer.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
}

// Shutdown gracefully drains active requests and stops accepting new
// ones. Wraps http.Server.Shutdown.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
