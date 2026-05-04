package courts

import (
	"log"
	"net/http"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// Server is the court tools HTTP server.
type Server struct {
	cfg      common.Config
	exchange *common.ExchangeClient
	verify   *common.VerifyClient
	db       *common.DB
	mux      *http.ServeMux
}

// NewServer creates a court tools server wired to upstream services.
func NewServer(cfg common.Config, exchange *common.ExchangeClient, verify *common.VerifyClient, db *common.DB) *Server {
	s := &Server{
		cfg:      cfg,
		exchange: exchange,
		verify:   verify,
		db:       db,
		mux:      http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	auth := AuthMiddleware(s.cfg)
	sealed := SealedFilterMiddleware(s.db)

	// Cases.
	s.mux.Handle("POST /v1/cases", auth(http.HandlerFunc(s.CreateCase)))
	s.mux.Handle("GET /v1/cases/{docket}", auth(http.HandlerFunc(s.GetCase)))
	s.mux.Handle("GET /v1/cases/{docket}/timeline", auth(http.HandlerFunc(s.GetCaseTimeline)))
	s.mux.Handle("PATCH /v1/cases/{docket}/status", auth(http.HandlerFunc(s.UpdateCaseStatus)))
	s.mux.Handle("POST /v1/cases/{docket}/transfer", auth(http.HandlerFunc(s.TransferCase)))

	// Filings.
	s.mux.Handle("POST /v1/cases/{docket}/filings", auth(sealed(http.HandlerFunc(s.CreateFiling))))
	s.mux.Handle("GET /v1/cases/{docket}/filings", auth(http.HandlerFunc(s.ListFilings)))
	s.mux.Handle("GET /v1/cases/{docket}/filings/{cid}", auth(sealed(http.HandlerFunc(s.GetFiling))))

	// Orders.
	s.mux.Handle("POST /v1/cases/{docket}/orders", auth(http.HandlerFunc(s.CreateOrder)))
	s.mux.Handle("POST /v1/cases/{docket}/orders/{orderID}/cosign", auth(http.HandlerFunc(s.CosignOrder)))
	s.mux.Handle("GET /v1/cases/{docket}/orders", auth(http.HandlerFunc(s.ListOrders)))

	// Sealing.
	s.mux.Handle("POST /v1/cases/{docket}/seal", auth(http.HandlerFunc(s.SealCase)))
	s.mux.Handle("POST /v1/cases/{docket}/unseal", auth(http.HandlerFunc(s.UnsealCase)))
	s.mux.Handle("POST /v1/cases/{docket}/expunge", auth(http.HandlerFunc(s.ExpungeCase)))

	// Officers.
	s.mux.Handle("POST /v1/officers", auth(http.HandlerFunc(s.CreateOfficer)))
	s.mux.Handle("DELETE /v1/officers/{did}", auth(http.HandlerFunc(s.RevokeOfficer)))
	s.mux.Handle("GET /v1/officers", auth(http.HandlerFunc(s.ListOfficers)))
	s.mux.Handle("GET /v1/officers/{did}", auth(http.HandlerFunc(s.GetOfficer)))

	// Docket.
	s.mux.Handle("POST /v1/docket", auth(http.HandlerFunc(s.PublishDocket)))
	s.mux.Handle("GET /v1/docket/{date}", auth(http.HandlerFunc(s.GetDocket)))
	s.mux.Handle("POST /v1/docket/reassign", auth(http.HandlerFunc(s.Reassign)))

	// Health.
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
}

// ListenAndServe starts the server.
func (s *Server) ListenAndServe() error {
	log.Printf("court-tools: listening on %s", s.cfg.CourtToolsAddr)
	return http.ListenAndServe(s.cfg.CourtToolsAddr, s.mux)
}

// Handler returns the http.Handler for testing.
func (s *Server) Handler() http.Handler {
	return s.mux
}
