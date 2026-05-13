// Package verification serves the JN's verification HTTP API:
// /v1/verify/origin, /v1/verify/authority, /v1/verify/batch,
// /v1/verify/delegation, /v1/verify/cross-log, /v1/verify/fraud-proof.
//
// It is the read-side complement of api/exchange. Callers reach it
// directly to validate entries against the SDK verifier without
// having to construct an envelope themselves.
//
// The package was renamed from api/core  to match the URL
// prefix it serves and to avoid the misleading "core" naming —
// nothing about this service is more "core" than the other api/
// packages; it just verifies.
package verification

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/schema"

	"github.com/clearcompass-ai/judicial-network/api/verification/handlers"
)

// ServerConfig configures the verification service.
//
// v0.3.0: WitnessSets replaces the legacy trio of WitnessKeys /
// WitnessQuorum / WitnessNetwork + BLSVerifier. One *cosign.WitnessKeySet
// per log DID carries keys, K, NetworkID, and the BLSAggregateVerifier
// together — SDK Principle 10 (Two-Tier Quorum Encapsulation).
type ServerConfig struct {
	Addr           string
	LogQueries     map[string]sdklog.LedgerQueryAPI
	LeafReader     smt.LeafReader
	Extractor      schema.SchemaParameterExtractor
	SchemaResolver builder.SchemaResolver
	WitnessSets    map[string]*cosign.WitnessKeySet
}

// Server is the verification service HTTP server.
type Server struct {
	httpServer *http.Server
	cfg        ServerConfig
}

// BuildHandler constructs the verification service's HTTP handler
// tree from cfg without instantiating an http.Server. The api/
// composer (api/server.go) uses this to mount /v1/verify/* alongside
// the exchange surface under one shared listener.
//
// Stand-alone callers wanting an isolated verification listener
// should use NewServer instead.
func BuildHandler(cfg ServerConfig) http.Handler {
	deps := &handlers.Dependencies{
		LogQueries:     cfg.LogQueries,
		LeafReader:     cfg.LeafReader,
		Extractor:      cfg.Extractor,
		SchemaResolver: cfg.SchemaResolver,
		WitnessSets:    cfg.WitnessSets,
	}

	mux := http.NewServeMux()

	mux.Handle("GET /v1/verify/origin/{logID}/{pos}", handlers.NewVerifyOriginHandler(deps))
	mux.Handle("GET /v1/verify/authority/{logID}/{pos}", handlers.NewVerifyAuthorityHandler(deps))
	mux.Handle("GET /v1/verify/batch/{logID}/{positions}", handlers.NewVerifyBatchHandler(deps))
	mux.Handle("GET /v1/verify/delegation/{logID}/{pos}", handlers.NewVerifyDelegationHandler(deps))
	mux.Handle("POST /v1/verify/cross-log", handlers.NewVerifyCrossLogHandler(deps))
	mux.Handle("POST /v1/verify/fraud-proof", handlers.NewVerifyFraudProofHandler(deps))
	// Phase 8 — Static-CT consistency endpoint. Trust Alignment 6
	// (Zero-Trust Dual Verification): external auditors pull
	// tiles and run the SDK verifier themselves; we expose the
	// same verifier here so callers without a local SDK build
	// can issue an HTTP request and get a cryptographic answer.
	mux.Handle("POST /v1/verify/consistency", handlers.NewVerifyConsistencyHandler(deps))

	// Health (no auth). Stand-alone deployments use this directly;
	// composed deployments are routed by the parent mux at api/server.go.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	return mux
}

// NewServer creates the verification service as a stand-alone listener.
// Composed deployments use BuildHandler instead.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}

	return &Server{
		httpServer: &http.Server{
			Addr:         cfg.Addr,
			Handler:      BuildHandler(cfg),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
		cfg: cfg,
	}, nil
}

func (s *Server) Start() error {
	log.Printf("verification api: listening on %s", s.cfg.Addr)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
