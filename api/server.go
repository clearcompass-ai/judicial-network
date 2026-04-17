/*
FILE PATH: api/server.go

DESCRIPTION:
    Verification service for the judicial network. Reads entries from
    the operator (Phase 2), runs SDK verifier functions, and returns
    evaluated protocol state.

    This is the gap between raw log infrastructure and business APIs.
    The operator sequences and proves. The artifact store stores blobs.
    This service evaluates: is this delegation chain valid? Is this
    entry's activation condition met? Has it been contested?

    6 endpoints. All reads. All domain-agnostic.

    What this service does NOT do:
      - Submit entries (operator does that)
      - Store or encrypt artifacts (artifact store does that)
      - Parse Domain Payloads (business APIs do that)
      - Apply sealing policy (business APIs do that)
      - Search by docket/party/name (business APIs do that)

KEY DEPENDENCIES:
    - ortholog-sdk/verifier (guide §§23-24)
    - ortholog-sdk/log: OperatorQueryAPI (guide §27.3)
*/
package api

import (
	"context"
	"log"
	"net/http"
	"time"

	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"

	"github.com/clearcompass-ai/judicial-network/api/handlers"
)

// ServerConfig configures the verification service.
type ServerConfig struct {
	// Addr is the listen address (e.g., ":8080").
	Addr string

	// LogQueries maps log DID → query API for that log's operator.
	// The verification service reads entries from these.
	LogQueries map[string]sdklog.OperatorQueryAPI

	// Verifiers — SDK evaluator instances.
	OriginEvaluator    verifier.OriginEvaluator
	AuthorityEvaluator verifier.AuthorityEvaluator
	ConditionEvaluator verifier.ConditionEvaluator
	ContestEvaluator   verifier.ContestEvaluator
	DelegationWalker   verifier.DelegationWalker
	CrossLogVerifier   verifier.CrossLogVerifier
	FraudProofVerifier verifier.FraudProofVerifier
}

// Server is the verification service HTTP server.
type Server struct {
	httpServer *http.Server
	cfg        ServerConfig
}

// NewServer creates the verification service with all routes.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}

	deps := &handlers.Dependencies{
		LogQueries:         cfg.LogQueries,
		OriginEvaluator:    cfg.OriginEvaluator,
		AuthorityEvaluator: cfg.AuthorityEvaluator,
		ConditionEvaluator: cfg.ConditionEvaluator,
		ContestEvaluator:   cfg.ContestEvaluator,
		DelegationWalker:   cfg.DelegationWalker,
		CrossLogVerifier:   cfg.CrossLogVerifier,
		FraudProofVerifier: cfg.FraudProofVerifier,
	}

	mux := http.NewServeMux()

	// Verification endpoints.
	mux.Handle("GET /v1/verify/origin/{logID}/{pos}", handlers.NewVerifyOriginHandler(deps))
	mux.Handle("GET /v1/verify/authority/{logID}/{pos}", handlers.NewVerifyAuthorityHandler(deps))
	mux.Handle("POST /v1/verify/batch", handlers.NewVerifyBatchHandler(deps))
	mux.Handle("GET /v1/verify/delegation/{logID}/{did}", handlers.NewVerifyDelegationHandler(deps))
	mux.Handle("POST /v1/verify/cross-log", handlers.NewVerifyCrossLogHandler(deps))
	mux.Handle("POST /v1/verify/fraud-proof", handlers.NewVerifyFraudProofHandler(deps))

	// Health.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	return &Server{
		httpServer: &http.Server{
			Addr:         cfg.Addr,
			Handler:      mux,
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
