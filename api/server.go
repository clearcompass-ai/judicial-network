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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/exchange"
	"github.com/clearcompass-ai/judicial-network/api/verification"
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

	// Order of registration is irrelevant for net/http.ServeMux —
	// longest-matching-prefix wins. /v1/verify/ is more specific than
	// /v1/ so verification routes always take precedence over the
	// exchange catch-all when their patterns overlap.
	mux.Handle("/v1/verify/", verifyHandler)
	mux.Handle("/v1/", exchHandler)

	// Composer-owned health probe. Returns 200 unconditionally; the
	// constituent /healthz endpoints are shadowed under composition.
	// Future expansion: aggregate liveness from constituents (e.g.,
	// keystore reachable, operator reachable). Ship the simple form
	// first; instrument later.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

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
	// middleware on top in Phase 5. Today: TLS material is wired and
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

// ─────────────────────────────────────────────────────────────────────
// TLS helpers
// ─────────────────────────────────────────────────────────────────────

// buildMTLSConfig reads the client-CA PEM file and returns a
// *tls.Config that REQUIRES client certs verified against that CA.
// The pre-Phase-5 mTLS contract: every authenticated request presents
// a client cert whose SAN contains the signer's DID; auth middleware
// (Phase 5) extracts callerDID from the verified cert and threads it
// into request context.
func buildMTLSConfig(caFile string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("%w: read ClientCAFile %q: %w", ErrInvalidConfig, caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: ClientCAFile %q has no PEM certs", ErrInvalidConfig, caFile)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
	}, nil
}
