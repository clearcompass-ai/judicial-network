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
	"os"
	"strings"
	"time"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/schema"

	"github.com/clearcompass-ai/judicial-network/api/verification/handlers"
)

// envPolicyStageEnable is the environment variable that gates the
// PR-2 read-time Stage 6 path on /v1/verify/complete. Default OFF
// (the SDK Path C composite continues to run only Signatures +
// Authority + Origin). Set to true/1/yes/on to enable.
const envPolicyStageEnable = "JN_VERIFY_POLICY_STAGE_ENABLE"

// policyStageEnabledFromEnv parses envPolicyStageEnable into a bool.
// Unrecognized values keep the default OFF — a typo in the env var
// MUST NOT silently flip enforcement on, since the feature surfaces
// new failure modes (cosignature_of round-trips, delegation chain
// walks) that callers haven't tested against.
func policyStageEnabledFromEnv() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(envPolicyStageEnable)))
	switch v {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

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

	// SignatureVerifier feeds /v1/verify/complete's SDK Path C
	// composite. Optional at boot — leaving it nil keeps the rest
	// of the verification surface live; the /v1/verify/complete
	// route will return 500 on calls because the SDK rejects nil
	// verifier at envelope level.
	SignatureVerifier attestation.SignatureVerifier

	// PR-2 — read-time Stage 6 (attesta v1.5.1 / issue #75).
	//
	// PolicyStage carries per-log dependencies (cosignature_of query
	// API, raw-bytes fetcher, delegation chain resolver) used by the
	// Path C composite's Policy stage. The Policy stage only fires
	// when (a) the feature flag JN_VERIFY_POLICY_STAGE_ENABLE is on
	// AND (b) PolicyStage has an entry for the request's logID.
	//
	// Production wiring constructs each PolicyStageDeps from:
	//   * sdklog.HTTPLedgerQueryAPI  (cosignature_of source)
	//   * sdklog.HTTPEntryFetcher    (/raw bytes for candidate hydration)
	//   * verification.LedgerDelegationResolver
	//                                (DelegationChain walks)
	//
	// Tests inject fakes (see verify_complete_test.go).
	//
	// Absent map / absent logID / flag off → the handler runs only
	// Signatures + Authority + Origin, the shape PR D shipped.
	PolicyStage map[string]handlers.PolicyStageDeps
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
		LogQueries:         cfg.LogQueries,
		LeafReader:         cfg.LeafReader,
		Extractor:          cfg.Extractor,
		SchemaResolver:     cfg.SchemaResolver,
		WitnessSets:        cfg.WitnessSets,
		SignatureVerifier:  cfg.SignatureVerifier,
		PolicyStage:        cfg.PolicyStage,
		PolicyStageEnabled: policyStageEnabledFromEnv(),
	}

	mux := http.NewServeMux()

	mux.Handle("GET /v1/verify/origin/{logID}/{pos}", handlers.NewVerifyOriginHandler(deps))
	mux.Handle("GET /v1/verify/authority/{logID}/{pos}", handlers.NewVerifyAuthorityHandler(deps))
	mux.Handle("GET /v1/verify/batch/{logID}/{positions}", handlers.NewVerifyBatchHandler(deps))
	mux.Handle("GET /v1/verify/delegation/{logID}/{pos}", handlers.NewVerifyDelegationHandler(deps))
	// PR D — read-side SDK Path C composite verifier. Runs every
	// opted-in stage in one frame (Signatures → Authority → Origin)
	// on an already-committed entry. NOT the write-side admission
	// gate — that lives in the ledger. Per-stage failures populate
	// the report; envelope-level errors return 500.
	mux.Handle("GET /v1/verify/complete/{logID}/{pos}", handlers.NewVerifyCompleteHandler(deps))
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
