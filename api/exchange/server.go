/*
FILE PATH: exchange/server.go

DESCRIPTION:
    Exchange service — the write path. Holds signer keys, builds entries
    via SDK, signs them, submits to the operator, encrypts artifacts,
    pushes to the artifact store, creates grants.

    Auth model:
      Exchange → Operator:   mTLS (exchange DID in cert SAN)
      Signer → Exchange:     Signed request envelope (Ed25519) or
                             mTLS (signer DID in cert SAN) for
                             non-custodial pre-signed submissions

    This service is domain-agnostic. A court exchange, a hospital
    exchange, a land registry exchange — all expose these endpoints.
    The domain_payload is opaque bytes flowing through.

KEY DEPENDENCIES:
    - ortholog-sdk/builder (guide §11.3)
    - ortholog-sdk/crypto/artifact (guide §14)
    - ortholog-sdk/lifecycle (guide §20)
    - ortholog-sdk/storage (guide §8)
*/
package exchange

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/exchange/auth"
	"github.com/clearcompass-ai/judicial-network/api/exchange/handlers"
	"github.com/clearcompass-ai/judicial-network/api/exchange/index"
	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
	"github.com/clearcompass-ai/judicial-network/api/middleware/observability"
	"github.com/clearcompass-ai/judicial-network/api/middleware/reliability"
)

// ServerConfig configures the exchange service.
type ServerConfig struct {
	Addr string // ":8443"

	// TLS for signer→exchange mTLS.
	TLSCert    string // server cert
	TLSKey     string // server key
	SignerCA   string // CA that issued signer certs

	// Operator connection (exchange→operator mTLS).
	OperatorEndpoint string
	OperatorCert     string // exchange's client cert for operator
	OperatorKey      string // exchange's client key for operator
	OperatorCA       string // operator's CA cert

	// Artifact store connection.
	ArtifactStoreEndpoint string

	// Verification service for delegation checks.
	VerificationEndpoint string

	// Key store backend.
	KeyStore keystore.KeyStore

	// Log index for sequential scanning.
	Index *index.LogIndex

	// NonceStores maps destination DID → per-destination NonceStore.
	// Built once at boot via NonceStoreConfig.BuildForExchange (one
	// call per registered destination). When non-nil, multi-tenant
	// signed requests with a Destination field route to the matching
	// store; nil keeps the single-tenant fallback path.
	NonceStores map[string]*auth.NonceStore

	// OperatorBreaker fast-fails operator submits when the operator
	// is down. Phase 14 reliability primitive. nil → no breaker.
	OperatorBreaker *reliability.Breaker

	// OperatorMetrics records per-submit metrics. Phase 15
	// observability primitive. nil → no metrics observed.
	OperatorMetrics *observability.OperatorSubmitMetrics
}

// Server is the exchange HTTP server.
type Server struct {
	httpServer *http.Server
	cfg        ServerConfig
}

// BuildHandler constructs the exchange's HTTP handler tree from cfg
// without instantiating an http.Server or loading TLS material. The
// api/ composer (api/server.go) uses this to mount exchange routes
// alongside the verification surface under one shared listener.
//
// Stand-alone callers wanting an isolated exchange-only listener
// should use NewServer instead — it wraps BuildHandler with a TLS-
// enabled http.Server. BuildHandler is the testable, composable seam.
func BuildHandler(cfg ServerConfig) http.Handler {
	deps := &handlers.Dependencies{
		OperatorEndpoint:      cfg.OperatorEndpoint,
		ArtifactStoreEndpoint: cfg.ArtifactStoreEndpoint,
		VerificationEndpoint:  cfg.VerificationEndpoint,
		KeyStore:              cfg.KeyStore,
		Index:                 cfg.Index,
		OperatorBreaker:       cfg.OperatorBreaker,
		OperatorMetrics:       cfg.OperatorMetrics,
	}

	mux := http.NewServeMux()

	// Auth middleware: verify signer identity on every write request.
	// Multi-tenant when cfg.NonceStores is non-empty; single-tenant
	// fallback otherwise (preserves dev / test behaviour).
	var signerAuth *auth.SignerAuth
	if len(cfg.NonceStores) > 0 {
		signerAuth = auth.NewSignerAuthWithNonceStores(cfg.VerificationEndpoint, cfg.NonceStores, nil)
	} else {
		signerAuth = auth.NewSignerAuth(cfg.VerificationEndpoint)
	}

	// Entry lifecycle.
	mux.Handle("POST /v1/entries/build", signerAuth.Wrap(handlers.NewEntryBuildHandler(deps)))
	mux.Handle("POST /v1/entries/sign", signerAuth.Wrap(handlers.NewEntrySignHandler(deps)))
	mux.Handle("POST /v1/entries/submit", signerAuth.Wrap(handlers.NewEntrySubmitHandler(deps)))
	mux.Handle("POST /v1/entries/build-sign-submit", signerAuth.Wrap(handlers.NewEntryFullHandler(deps)))
	mux.Handle("GET /v1/entries/status/{hash}", handlers.NewEntryStatusHandler(deps))

	// Artifact lifecycle.
	mux.Handle("POST /v1/artifacts/publish", signerAuth.Wrap(handlers.NewArtifactPublishHandler(deps)))
	mux.Handle("POST /v1/artifacts/{cid}/grant", signerAuth.Wrap(handlers.NewArtifactGrantHandler(deps)))

	// Delegation management.
	mux.Handle("POST /v1/delegations", signerAuth.Wrap(handlers.NewDelegationCreateHandler(deps)))
	mux.Handle("DELETE /v1/delegations/{did}", signerAuth.Wrap(handlers.NewDelegationRevokeHandler(deps)))

	// Key management.
	mux.Handle("POST /v1/keys/generate", signerAuth.Wrap(handlers.NewKeyGenerateHandler(deps)))
	mux.Handle("POST /v1/keys/rotate", signerAuth.Wrap(handlers.NewKeyRotateHandler(deps)))
	mux.Handle("POST /v1/keys/escrow", signerAuth.Wrap(handlers.NewKeyEscrowHandler(deps)))
	mux.Handle("GET /v1/keys", signerAuth.Wrap(handlers.NewKeyListHandler(deps)))

	// Identity.
	mux.Handle("POST /v1/dids", signerAuth.Wrap(handlers.NewDIDCreateHandler(deps)))
	mux.Handle("GET /v1/dids", signerAuth.Wrap(handlers.NewDIDListHandler(deps)))

	// Scope governance.
	mux.Handle("POST /v1/scope/propose", signerAuth.Wrap(handlers.NewScopeProposeHandler(deps)))
	mux.Handle("POST /v1/scope/approve/{pos}", signerAuth.Wrap(handlers.NewScopeApproveHandler(deps)))
	mux.Handle("POST /v1/scope/execute/{pos}", signerAuth.Wrap(handlers.NewScopeExecuteHandler(deps)))

	// Health (no auth). When the exchange runs stand-alone, this is its
	// readiness probe target. Under the composer (api/server.go), the
	// composer's parent mux owns /healthz directly and this entry is
	// shadowed by prefix-routing — see api/server.go for the contract.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	return mux
}

// NewServer creates the exchange service as a stand-alone listener.
// Composed deployments use BuildHandler instead.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = ":8443"
	}

	handler := BuildHandler(cfg)

	tlsConfig, err := buildTLSConfig(cfg.SignerCA)
	if err != nil {
		return nil, err
	}

	return &Server{
		httpServer: &http.Server{
			Addr:         cfg.Addr,
			Handler:      handler,
			TLSConfig:    tlsConfig,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
		},
		cfg: cfg,
	}, nil
}

func (s *Server) Start() error {
	log.Printf("exchange: listening on %s (mTLS)", s.cfg.Addr)
	return s.httpServer.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func buildTLSConfig(caFile string) (*tls.Config, error) {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		ClientAuth: tls.VerifyClientCertIfGiven, // mTLS optional; signed requests also accepted
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS13,
	}, nil
}
