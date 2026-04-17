package api

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/api/handlers"
)

// ServerConfig configures the verification service.
type ServerConfig struct {
	Addr           string
	LogQueries     map[string]sdklog.OperatorQueryAPI
	LeafReader     smt.LeafReader
	Extractor      schema.SchemaParameterExtractor
	SchemaResolver builder.SchemaResolver
	BLSVerifier    signatures.BLSVerifier
	WitnessKeys    map[string][]types.WitnessPublicKey
	WitnessQuorum  map[string]int
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
		LogQueries:     cfg.LogQueries,
		LeafReader:     cfg.LeafReader,
		Extractor:      cfg.Extractor,
		SchemaResolver: cfg.SchemaResolver,
		BLSVerifier:    cfg.BLSVerifier,
		WitnessKeys:    cfg.WitnessKeys,
		WitnessQuorum:  cfg.WitnessQuorum,
	}

	mux := http.NewServeMux()

	mux.Handle("GET /v1/verify/origin/{logID}/{pos}", handlers.NewVerifyOriginHandler(deps))
	mux.Handle("GET /v1/verify/authority/{logID}/{pos}", handlers.NewVerifyAuthorityHandler(deps))
	mux.Handle("GET /v1/verify/batch/{logID}/{positions}", handlers.NewVerifyBatchHandler(deps))
	mux.Handle("GET /v1/verify/delegation/{logID}/{pos}", handlers.NewVerifyDelegationHandler(deps))
	mux.Handle("POST /v1/verify/cross-log", handlers.NewVerifyCrossLogHandler(deps))
	mux.Handle("POST /v1/verify/fraud-proof", handlers.NewVerifyFraudProofHandler(deps))

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
