/*
FILE PATH: exchange/server.go

DESCRIPTION:

	Exchange service — the write path. Holds signer keys, builds entries
	via SDK, signs them, submits to the ledger, encrypts artifacts,
	pushes to the artifact store, creates grants.

	Auth model:
	  Exchange → Ledger:   mTLS (exchange DID in cert SAN)
	  Signer → Exchange:     Signed request envelope (Ed25519) or
	                         mTLS (signer DID in cert SAN) for
	                         non-custodial pre-signed submissions

	This service is domain-agnostic. A court exchange, a hospital
	exchange, a land registry exchange — all expose these endpoints.
	The domain_payload is opaque bytes flowing through.

KEY DEPENDENCIES:
  - attesta/builder (guide §11.3)
  - attesta/crypto/artifact (guide §14)
  - attesta/lifecycle (guide §20)
  - attesta/storage (guide §8)
*/
package exchange

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/clearcompass-ai/attesta-tools/libs/httpmw/observability"
	"github.com/clearcompass-ai/attesta-tools/libs/httpmw/reliability"
	"github.com/clearcompass-ai/attesta-tools/libs/keystore"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/storage"
	auth "github.com/clearcompass-ai/judicial-network/api/exchange/auth/v2"
	"github.com/clearcompass-ai/judicial-network/api/exchange/handlers"
	"github.com/clearcompass-ai/judicial-network/api/exchange/index"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// ServerConfig configures the exchange service.
type ServerConfig struct {
	Addr string // ":8443"

	// TLS for signer→exchange mTLS.
	TLSCert  string // server cert
	TLSKey   string // server key
	SignerCA string // CA that issued signer certs

	// Ledger connection (exchange→ledger mTLS).
	LedgerEndpoint string
	LedgerCert     string // exchange's client cert for ledger
	LedgerKey      string // exchange's client key for ledger
	LedgerCA       string // ledger's CA cert

	// Artifact store connection.
	ArtifactStoreEndpoint string

	// Verification service for delegation checks.
	VerificationEndpoint string

	// Key store backend.
	KeyStore keystore.KeyStore

	// Log index for sequential scanning.
	Index *index.LogIndex

	// SignerAuth is the v2 signed-request admission middleware,
	// pre-built by the caller via auth.NewSignerAuth(SignerAuthConfig{...}).
	// Required.
	//
	// The caller wires the full SignerAuthConfig: did.VerifierRegistry
	// (typically with did:key registered), AlgoID
	// (envelope.SigAlgoEd25519 etc.), per-destination NonceStores
	// (built via auth.NonceStoreConfig.BuildForExchange), a fallback
	// NonceStore, and the optional mTLS extractor. This keeps the
	// exchange server free of identity / key resolution concerns.
	SignerAuth *auth.SignerAuth

	// LedgerBreaker fast-fails ledger submits when the ledger
	// is down.  reliability primitive. nil → no breaker.
	LedgerBreaker *reliability.Breaker

	// LedgerMetrics records per-submit metrics.
	// observability primitive. nil → no metrics observed.
	LedgerMetrics *observability.LedgerSubmitMetrics

	// SubmitGate is the per-jurisdiction admission gate run on
	// POST /v1/entries/submit before the entry is forwarded to the
	// ledger (cosignature policy + prerequisite walker). nil keeps
	// the pre-3E.4 pass-through proxy (tests / pre-roster dev).
	// Production wires NewBundleSubmitGate(registry).
	SubmitGate handlers.SubmitGater

	// AdmissionAuthorizer mints the gate-5 WriteAuthorization (gating axis)
	// attached at the submit chokepoint after SubmitGate accepts. nil → no
	// attach (ungated logs / tests). main.go wires it from
	// API_ADMISSION_AUTHORITY_KEY_FILE (the JN's on-log admission EOA).
	AdmissionAuthorizer *handlers.AdmissionAuthorizer

	// LedgerSubmitClient is the HTTP client the exchange uses to POST entries
	// to LedgerEndpoint. Production deployments wire a mutually-authenticated
	// client built from LedgerCert / LedgerKey / LedgerCA via
	// BuildLedgerSubmitClient (this package). nil falls back to the SDK's
	// server-verify-only default — acceptable for tests / pre-cert dev, NOT
	// for production. The ledger refuses non-mTLS connections (see
	// ledger/api/server.go::buildServerTLSConfig).
	LedgerSubmitClient *http.Client

	// ContentStore is the boot-wired SDK content store used by the artifact-
	// publish handler. Production wires storage.NewHTTPContentStore once at
	// boot with the configured artifact-store endpoint + http.Client
	// (cmd/network-api/main.go). nil ⇒ the artifact-publish handler surfaces
	// 503; the rest of the exchange surface keeps working.
	ContentStore storage.ContentStore
}

// NewBundleSubmitGate builds the production per-jurisdiction submit
// gate over a frozen registry. The cosignature RoleResolver is
// derived per-entry from each entry's signed_by_capacities block, so
// the gate needs no off-log registry beyond the compiled-in Bundles.
func NewBundleSubmitGate(r *jurisdiction.Registry) handlers.SubmitGater {
	return &handlers.BundleSubmitGate{Registry: r}
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
		LedgerEndpoint:        cfg.LedgerEndpoint,
		ArtifactStoreEndpoint: cfg.ArtifactStoreEndpoint,
		VerificationEndpoint:  cfg.VerificationEndpoint,
		KeyStore:              cfg.KeyStore,
		Index:                 cfg.Index,
		LedgerBreaker:         cfg.LedgerBreaker,
		LedgerMetrics:         cfg.LedgerMetrics,
		SubmitGate:            cfg.SubmitGate,
		AdmissionAuthorizer:   cfg.AdmissionAuthorizer,
		LedgerSubmitClient:    cfg.LedgerSubmitClient,
		ContentStore:          cfg.ContentStore,
	}

	mux := http.NewServeMux()

	// Auth middleware: pre-built by the caller. When cfg.SignerAuth
	// is nil the exchange handler is mounted in DISABLED mode —
	// every route returns 503 Service Unavailable. This is the
	// "exchange not configured" posture used by composer-only tests
	// that exercise non-exchange endpoints (/metrics, /healthz,
	// verification routes). Production wiring always supplies a
	// SignerAuth.
	if cfg.SignerAuth == nil {
		return disabledExchangeHandler()
	}
	signerAuth := cfg.SignerAuth

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

// disabledExchangeHandler is the placeholder returned by BuildHandler
// when cfg.SignerAuth is nil. Every route returns 503 with a
// directive error pointing the operator at the missing config.
// Composer-only tests (metrics endpoint, verification routes)
// hit this path without bringing up real exchange auth.
func disabledExchangeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w,
			"exchange not configured (SignerAuth required at boot — build via auth.NewSignerAuth)",
			http.StatusServiceUnavailable)
	})
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

// BuildLedgerSubmitClient constructs the mutually-authenticated HTTP client
// the exchange uses to POST entries to the ledger. It pairs the SDK's
// retry-aware transport (RetryAfterRoundTripper) with the production-tuned
// connection pool and the exchange's client cert/key + the ledger's CA.
//
// Returns (nil, err) on any TLS-material failure: missing cert, missing key,
// unparseable CA, mismatched keypair. main.go is expected to fail startup
// rather than fall back to plaintext — the ledger's transport-layer mTLS
// requirement makes plaintext fallback an immediate connect failure anyway.
//
// Callers that want a server-verify-only client (tests / pre-cert dev) leave
// ServerConfig.LedgerCert / LedgerKey empty and the BuildHandler caller passes
// nil into Dependencies.LedgerSubmitClient — the fallback path in
// handlers.ledgerSubmitClientFor handles that case.
func BuildLedgerSubmitClient(cfg ServerConfig) (*http.Client, error) {
	c, err := reliability.NewMTLSClient(
		reliability.ClientConfig{Timeout: 30 * time.Second},
		sdklog.ClientTLSConfig{
			ClientCertFile: cfg.LedgerCert,
			ClientKeyFile:  cfg.LedgerKey,
			RootCAFile:     cfg.LedgerCA,
		},
	)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// BuildLedgerServerVerifyClient constructs the open-HTTPS client the exchange
// uses to reach a ledger that serves reads openly: it pins caFile to verify the
// ledger's privately-signed / self-signed server cert and presents NO client
// cert. The ledger gates writes on the in-body G5 signature, so transport
// identity is not the trust boundary — the JN authenticates WHO the ledger is
// (CA-pinned) without mTLS.
//
// caFile is REQUIRED (an empty CA cannot verify a self-signed cert). Returns
// (nil, err) on CA load failure; the caller MUST fail startup rather than fall
// back to the system roots. Verification is always on — never InsecureSkipVerify.
func BuildLedgerServerVerifyClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return nil, fmt.Errorf("exchange: server-verify ledger client requires a CA file (cannot verify a self-signed cert against nothing)")
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("exchange: read ledger CA %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("exchange: ledger CA %q contains no parseable certificates", caFile)
	}
	return sdklog.DefaultClient(30*time.Second, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}), nil
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
