package judicial

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/cosign"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
	"github.com/clearcompass-ai/ortholog-sdk/witness"

	"github.com/clearcompass-ai/judicial-network/api/exchange/auth"
	lifecycleartifact "github.com/clearcompass-ai/ortholog-sdk/lifecycle/artifact"
	"github.com/clearcompass-ai/judicial-network/cases/artifact"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/topology"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrInvalidRequest wraps every JSON-decode / required-field failure
// surfaced from a handler. Maps to 400 Bad Request.
var ErrInvalidRequest = errors.New("api/judicial: invalid request")

// ─────────────────────────────────────────────────────────────────────
// Dependencies
// ─────────────────────────────────────────────────────────────────────

// Dependencies bundles every external interface the judicial handlers
// share. Populated once at boot by the composer; injected into every
// per-handler constructor. Each field is the SDK or JN interface the
// matching domain function expects — no invented abstractions.
//
// Most handlers use a strict subset; the field is pulled out here so
// the wiring is uniform regardless of how many fields a particular
// handler reads.
type Dependencies struct {
	// Registry resolves entry.Header.Destination to its Bundle for
	// jurisdiction-specific validation. Production: frozen at boot.
	Registry *jurisdiction.Registry

	// Operator-side reads. Set by the binary at boot.
	LogQueries map[string]sdklog.OperatorQueryAPI // logDID → query API
	Fetcher    types.EntryFetcher
	LeafReader smt.LeafReader

	// SDK utility deps. Set by the binary at boot.
	SchemaResolver builder.SchemaResolver
	Extractor      schema.SchemaParameterExtractor
	Resolver       did.DIDResolver
	BLSVerifier    cosign.BLSAggregateVerifier
	WitnessKeys    map[string][]types.WitnessPublicKey
	WitnessQuorum  map[string]int

	// NetworkID is the deployment's 32-byte cosign-domain identifier
	// derived from the network bootstrap document. Threaded into
	// every cosign.Verify / cosign.TreeHeadDigest call site that
	// runs through the judicial verification surface.
	NetworkID cosign.NetworkID

	// Storage / artifact stores. Used by handlers that publish or
	// retrieve documents.
	ContentStore storage.ContentStore
	KeyStore     lifecycleartifact.KeyStore
	DelKeyStore  artifact.DelegationKeyStore

	// Cross-log proof prover (used by appeals / county transfer flows).
	SourceProver verifier.MerkleProver

	// TreeHeadClient fetches cosigned tree heads from operators +
	// witness fallbacks. Required by the anchor / topology handlers
	// and by anchor-freshness monitoring. nil → those handlers
	// surface 503 (configured via witness operational config).
	TreeHeadClient *witness.TreeHeadClient

	// Hierarchy is the JN-side anchor hierarchy (county → state →
	// federal). Built at boot from the registered Bundles' parent
	// relationships. Consumed by topology.DiscoverAnchorChain. nil
	// → anchor-chain handler returns 503.
	Hierarchy *topology.Hierarchy
}

// ─────────────────────────────────────────────────────────────────────
// Server / BuildHandler / NewServer
// ─────────────────────────────────────────────────────────────────────

// ServerConfig configures the judicial service.
type ServerConfig struct {
	Addr string
	Deps Dependencies
}

// Server is the judicial HTTP server. Use NewServer for stand-alone;
// composed deployments use BuildHandler.
type Server struct {
	httpServer *http.Server
	cfg        ServerConfig
}

// BuildHandler constructs the judicial HTTP handler tree from cfg
// without instantiating an http.Server. The api/ composer at
// api/server.go uses this to mount /v1/judicial/* alongside
// /v1/exchange and /v1/verify under the same listener.
//
// Stand-alone callers wanting an isolated judicial-only listener
// should use NewServer instead.
func BuildHandler(cfg ServerConfig) http.Handler {
	mux := http.NewServeMux()

	// ── Cases ────────────────────────────────────────────────────
	registerCaseRoutes(mux, &cfg.Deps)
	// ── Appeals ──────────────────────────────────────────────────
	registerAppealsRoutes(mux, &cfg.Deps)
	// ── Enforcement ──────────────────────────────────────────────
	registerEnforcementRoutes(mux, &cfg.Deps)
	// ── Parties ──────────────────────────────────────────────────
	registerPartiesRoutes(mux, &cfg.Deps)
	// ── Onboarding ───────────────────────────────────────────────
	registerOnboardingRoutes(mux, &cfg.Deps)
	// ── Artifacts ────────────────────────────────────────────────
	registerArtifactRoutes(mux, &cfg.Deps)
	// ── Verification (read-side) ─────────────────────────────────
	registerVerificationRoutes(mux, &cfg.Deps)
	// ── Monitoring ───────────────────────────────────────────────
	registerMonitoringRoutes(mux, &cfg.Deps)
	// ── Consortium (federation) ─────────────────────────────────
	registerConsortiumRoutes(mux, &cfg.Deps)
	// ── Delegation + Topology (operational stubs) ───────────────
	registerDelegationTopologyRoutes(mux, &cfg.Deps)
	// ── Escrow recovery (Phase 10) ──────────────────────────────
	registerEscrowRoutes(mux, &cfg.Deps)

	// Health (stand-alone deployments). Composed mode shadows this
	// with the composer's parent /healthz.
	mux.HandleFunc("GET /v1/judicial/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return mux
}

// NewServer constructs a stand-alone judicial server. Composed
// deployments use BuildHandler.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = ":8090"
	}
	return &Server{
		cfg: cfg,
		httpServer: &http.Server{
			Addr:         cfg.Addr,
			Handler:      BuildHandler(cfg),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}, nil
}

// Start begins listening. Blocks until Shutdown.
func (s *Server) Start() error {
	log.Printf("api/judicial: listening on %s", s.cfg.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully drains active requests.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// ─────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────

// callerDID extracts the authenticated caller's DID. Composer-level
// auth (api/middleware) sets this; handlers call this once at the top
// of ServeHTTP. When auth is wired at the composer, a missing DID is
// a programming bug (the request reached the handler without auth);
// when auth is not wired (dev / test), the empty return signals
// "unauthenticated" and the handler decides whether to proceed.
//
// We also fall back to api/exchange/auth.SignerDIDFromContext for
// backwards compat with callers that still come through the exchange's
// own SignerAuth wrapper (pre-Phase-5 path).
func callerDID(r *http.Request) string {
	if did := middlewareCallerDID(r); did != "" {
		return did
	}
	return auth.SignerDIDFromContext(r.Context())
}

// middlewareCallerDID is wired in test/build via a function indirection
// so the api/judicial package does not need to import api/middleware
// (which would create an unnecessary tight coupling for tests). The
// production binary registers the real reader at boot via SetCallerDID
// resolver; tests stub it directly.
//
// In practice the binary calls SetCallerDIDResolver(middleware.CallerDIDFromContext)
// before BuildHandler; tests substitute a stub.
var middlewareCallerDID = func(r *http.Request) string { return "" }

// SetCallerDIDResolver installs the function that maps a request to
// its authenticated callerDID. Called once at boot by the api/ binary
// with middleware.CallerDIDFromContext. Tests may stub.
func SetCallerDIDResolver(fn func(*http.Request) string) {
	if fn == nil {
		middlewareCallerDID = func(r *http.Request) string { return "" }
		return
	}
	middlewareCallerDID = func(r *http.Request) string { return fn(r) }
}

// ─────────────────────────────────────────────────────────────────────
// Request/response envelope helpers
// ─────────────────────────────────────────────────────────────────────

// buildResponse is the canonical wire shape every handler returns on
// successful build. Carries the signing payload (what the caller
// signs), the assembled but unsigned entry bytes (so the caller can
// inspect/verify shape), and the deserialized header for ergonomic
// access.
type buildResponse struct {
	// SigningPayload is the byte string the caller must SHA-256 hash
	// and sign. Hex-encoded for JSON transport.
	SigningPayload string `json:"signing_payload"`

	// EntryBytes is the same bytes (entry without signatures) as base64
	// for transport ergonomics.
	EntryBytes string `json:"entry_bytes"`

	// Header is the deserialized header for inspection. Callers MAY
	// use this to confirm Destination, SignerDID, SchemaRef, etc.
	// match expectations before signing.
	Header *envelope.ControlHeader `json:"header"`
}

// writeBuildResponse serializes an envelope.Entry into the buildResponse
// shape and writes 200 OK with the JSON body.
func writeBuildResponse(w http.ResponseWriter, entry *envelope.Entry) {
	signing := envelope.SigningPayload(entry)
	resp := buildResponse{
		SigningPayload: base64.StdEncoding.EncodeToString(signing),
		EntryBytes:     base64.StdEncoding.EncodeToString(signing),
		Header:         &entry.Header,
	}
	writeJSON(w, http.StatusOK, resp)
}

// writeJSON is the canonical success-response writer. Always emits
// application/json + the supplied status.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError is the canonical error-response writer. Body is JSON
// {"error": "<message>"}. Status comes from the caller; the handler
// is responsible for translating domain sentinels (e.g.,
// ErrInvalidRequest → 400, callerDID-missing → 401).
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// requireCaller pulls callerDID and writes 401 if absent. Returns ""
// after writing the response so handlers can early-return on the
// boolean value.
func requireCaller(w http.ResponseWriter, r *http.Request) string {
	did := callerDID(r)
	if did == "" {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return ""
	}
	return did
}

// decodeJSON unmarshals r.Body into v. Returns ErrInvalidRequest on
// any decode error so handlers can map it uniformly to 400.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrInvalidRequest
	}
	return nil
}
