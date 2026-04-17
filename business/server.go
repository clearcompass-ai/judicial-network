/*
FILE PATH: business/server.go

DESCRIPTION:
    Davidson County Court API — the business layer. Domain-specific.
    Maps docket numbers → log positions, applies sealing policy,
    parses Domain Payloads, renders case views.

    Auth model:
      Public reads:  No auth. Transparency. Proofs in response headers.
      CMS writes:    mTLS + on-log delegation check.
      Admin:         mTLS + on-log delegation with scope "admin".

    Composes three downstream services:
      Exchange:       build/sign/submit entries, encrypt artifacts
      Verification:   evaluate protocol state (delegation, activation)
      Operator:       raw entry reads (via exchange index)

    This is the only layer that parses Domain Payloads. Everything
    below treats Domain Payload as opaque bytes.

KEY DEPENDENCIES:
    - judicial-network/exchange: entry/artifact lifecycle
    - judicial-network/api: verification service
    - judicial-network/exchange/index: docket→position mappings
    - judicial-network/business/auth: mTLS + delegation check
    - judicial-network/business/middleware: sealed_filter
*/
package business

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"time"

	bauth "github.com/clearcompass-ai/judicial-network/business/auth"
	"github.com/clearcompass-ai/judicial-network/business/handlers"
	"github.com/clearcompass-ai/judicial-network/business/middleware"
	"github.com/clearcompass-ai/judicial-network/exchange/index"
)

// ServerConfig configures the Davidson County court API.
type ServerConfig struct {
	Addr string // ":8444"

	// TLS for CMS/admin mTLS.
	TLSCert string
	TLSKey  string
	CMSCA   string // CA that issued CMS agent certs

	// Downstream services.
	ExchangeEndpoint     string
	VerificationEndpoint string
	ArtifactStoreEndpoint string

	// Index from exchange (docket→position, etc.)
	Index *index.LogIndex

	// Court identity.
	CourtDID    string
	OfficersLog string // log DID for delegation checks
	CasesLog    string
	PartiesLog  string
}

// Server is the court API HTTP server.
type Server struct {
	httpServer *http.Server
	cfg        ServerConfig
}

// NewServer creates the court API.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = ":8444"
	}

	deps := &handlers.Dependencies{
		ExchangeEndpoint:      cfg.ExchangeEndpoint,
		VerificationEndpoint:  cfg.VerificationEndpoint,
		ArtifactStoreEndpoint: cfg.ArtifactStoreEndpoint,
		Index:                 cfg.Index,
		CourtDID:              cfg.CourtDID,
		OfficersLog:           cfg.OfficersLog,
		CasesLog:              cfg.CasesLog,
		PartiesLog:            cfg.PartiesLog,
	}

	mux := http.NewServeMux()

	// Auth middleware: mTLS + on-log delegation.
	delegationAuth := bauth.NewDelegationAuth(bauth.DelegationAuthConfig{
		VerificationEndpoint: cfg.VerificationEndpoint,
		OfficersLogID:        cfg.OfficersLog,
		CourtDID:             cfg.CourtDID,
	})

	// Sealed filter middleware.
	sealedFilter := middleware.NewSealedFilter(middleware.SealedFilterConfig{
		VerificationEndpoint: cfg.VerificationEndpoint,
		CasesLogID:           cfg.CasesLog,
		Index:                cfg.Index,
	})

	// ─── Public reads (no auth, sealed filter applied) ──────────
	mux.Handle("GET /v1/cases/{docket}", sealedFilter.Wrap(handlers.NewCaseLookupHandler(deps)))
	mux.Handle("GET /v1/cases/{docket}/documents", sealedFilter.Wrap(handlers.NewCaseDocumentsHandler(deps)))
	mux.Handle("GET /v1/cases/{docket}/documents/{docID}", sealedFilter.Wrap(handlers.NewDocumentDownloadHandler(deps)))
	mux.Handle("GET /v1/officers", handlers.NewOfficerRosterHandler(deps))
	mux.Handle("GET /v1/docket/daily", handlers.NewDailyDocketReadHandler(deps))

	// ─── CMS writes (mTLS + delegation auth) ────────────────────
	mux.Handle("POST /v1/cases/{docket}/file", delegationAuth.RequireScope("filing_submission", handlers.NewCaseFilingHandler(deps)))
	mux.Handle("POST /v1/docket/daily", delegationAuth.RequireScope("docket_management", handlers.NewDailyDocketWriteHandler(deps)))

	// ─── Party search (no auth, no sealed filter — party bindings
	//     don't expose sealed case data) ─────────────────────────
	mux.Handle("GET /v1/parties/search", handlers.NewPartySearchHandler(deps))

	// ─── Health ─────────────────────────────────────────────────
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	tlsConfig, err := buildTLSConfig(cfg.CMSCA)
	if err != nil {
		return nil, err
	}

	return &Server{
		httpServer: &http.Server{
			Addr:         cfg.Addr,
			Handler:      mux,
			TLSConfig:    tlsConfig,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
		},
		cfg: cfg,
	}, nil
}

func (s *Server) Start() error {
	log.Printf("court api: listening on %s", s.cfg.Addr)
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
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS13,
	}, nil
}
