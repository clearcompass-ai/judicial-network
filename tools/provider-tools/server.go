package providers

import (
	"log"
	"net/http"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// Server is the data provider tools HTTP server. Read-only — never touches exchange.
type Server struct {
	cfg    common.Config
	verify *common.VerifyClient
	db     *common.DB
	mux    *http.ServeMux
}

// NewServer creates a provider tools server.
func NewServer(cfg common.Config, verify *common.VerifyClient, db *common.DB) *Server {
	s := &Server{
		cfg:    cfg,
		verify: verify,
		db:     db,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	auth := APIKeyMiddleware(s.cfg)

	s.mux.Handle("GET /v1/records/search", auth(http.HandlerFunc(s.SearchRecords)))
	s.mux.Handle("GET /v1/records/{docket}", auth(http.HandlerFunc(s.GetRecord)))
	s.mux.Handle("GET /v1/records/{docket}/documents", auth(http.HandlerFunc(s.ListDocuments)))
	s.mux.Handle("GET /v1/records/{docket}/documents/{cid}", auth(http.HandlerFunc(s.GetDocument)))
	s.mux.Handle("POST /v1/background-check", auth(http.HandlerFunc(s.BackgroundCheck)))

	// Verification proxy.
	s.mux.Handle("GET /v1/verify/entry/{courtDID}/{log}/{pos}", auth(http.HandlerFunc(s.VerifyEntry)))
	s.mux.Handle("GET /v1/verify/delegation/{courtDID}/{officerDID}", auth(http.HandlerFunc(s.VerifyOfficer)))

	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
}

// ListenAndServe starts the server.
func (s *Server) ListenAndServe() error {
	log.Printf("provider-tools: listening on %s", s.cfg.ProviderToolsAddr)
	return http.ListenAndServe(s.cfg.ProviderToolsAddr, s.mux)
}

// Handler returns the http.Handler for testing.
func (s *Server) Handler() http.Handler {
	return s.mux
}
