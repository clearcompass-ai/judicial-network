package judicial

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/did"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/log/discover"
	"github.com/clearcompass-ai/attesta/network"
	"github.com/clearcompass-ai/attesta/schema"
	"github.com/clearcompass-ai/attesta/storage"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
	"github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/attesta-tools/libs/monitoring"
	lifecycleartifact "github.com/clearcompass-ai/attesta/lifecycle/artifact"
	auth "github.com/clearcompass-ai/judicial-network/api/exchange/auth/v2"
	"github.com/clearcompass-ai/judicial-network/cases/artifact"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/topology"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// ──────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────

// ErrInvalidRequest wraps every JSON-decode / required-field failure
// surfaced from a handler. Maps to 400 Bad Request.
var ErrInvalidRequest = errors.New("api/judicial: invalid request")

// ──────────────────────────────────────────────────────────────────
// Dependencies
// ──────────────────────────────────────────────────────────────────

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

	// Ledger-side reads. Set by the binary at boot.
	LogQueries map[string]sdklog.LedgerQueryAPI // logDID → query API
	Fetcher    types.EntryFetcher
	LeafReader smt.LeafReader

	// DelegateQueriers backs Stage 6's delegation-chain walker. One
	// shim per registered destination, keyed by destination DID, each
	// carrying the boot-wired mTLS http.Client. nil ⇒ Stage 6 falls
	// back to its no-op behaviour (no delegations resolved); production
	// wires one per destination (cmd/network-api/judicial_deps.go).
	//
	// Folds into LogQueries once sdklog.LedgerQueryAPI grows
	// QueryByDelegateDID; see verification/ledger_delegate_query.go.
	DelegateQueriers map[string]verification.DelegateDIDQuerier

	// SDK utility deps. Set by the binary at boot.
	SchemaResolver builder.SchemaResolver
	Extractor      schema.SchemaParameterExtractor
	Resolver       did.DIDResolver

	// WitnessSets is the per-log witness topology — v0.3.0 replaces
	// the legacy trio of WitnessKeys / WitnessQuorum / WitnessNetwork
	// (plus BLSVerifier). Each *cosign.WitnessKeySet binds keys + K
	// + NetworkID + BLSAggregateVerifier together at construction
	// time. SDK Principle 10 (Two-Tier Quorum Encapsulation).
	WitnessSets map[string]*cosign.WitnessKeySet

	// NetworkID is the deployment's 32-byte cosign-domain identifier
	// derived from the network bootstrap document. Threaded into
	// every cosign.Verify / cosign.TreeHeadDigest call site that
	// runs through the judicial verification surface. Distinct from
	// per-log NetworkIDs inside WitnessSets — this is the local log's
	// own network identity; WitnessSets[did].NetworkID() is the
	// source log's identity for cross-log verification.
	NetworkID cosign.NetworkID

	// Storage / artifact stores. Used by handlers that publish or
	// retrieve documents.
	ContentStore storage.ContentStore
	KeyStore     lifecycleartifact.KeyStore
	DelKeyStore  artifact.DelegationKeyStore

	// Cross-log proof prover (used by appeals / county transfer flows).
	SourceProver verifier.MerkleProver

	// TreeHeadClient fetches cosigned tree heads (/v1/tree/head) from ledgers +
	// witness fallbacks. Used by anchor-chain discovery and anchor-freshness
	// monitoring (both need only the live head's TreeSize). nil → those handlers
	// surface 503 (configured via witness operational config).
	TreeHeadClient *witness.TreeHeadClient

	// CheckpointClient fetches a log's PUBLISHED, witness-cosigned horizon
	// (/v1/tree/horizon) by DID. Used by anchor publishing, which must embed the
	// durable, quorum-finalized checkpoint (not the live head). nil → the
	// publish-anchor handler surfaces 503.
	CheckpointClient *sdklog.ResolvingCheckpointClient

	// Hierarchy is the JN-side anchor hierarchy (county → state →
	// federal). Built at boot from the registered Bundles' parent
	// relationships. Consumed by topology.DiscoverAnchorChain. nil
	// → anchor-chain handler returns 503.
	Hierarchy *topology.Hierarchy

	// TrustedHeads is the verify-only ingest's per-source trusted-head view
	// (CosignedTreeHeads pulled from the auditor and re-verified against
	// JN-local trust). Surfaced read-only by GET /v1/judicial/monitoring/
	// peer-consistency. nil when gossip ingest is disabled → that handler
	// returns an empty source set.
	TrustedHeads *monitoring.TrustedHeadStore

	// HeadsJournal is the v1.34+ durable archive — every verified
	// CosignedTreeHeadFinding that the gossip Reconciler advances into
	// TrustedHeads is ALSO written to this journal (multi-log keyed by
	// LogDID). Surfaces three new verification surfaces that the live
	// anchor cannot:
	//
	//   - HISTORICAL-asOf reads (asOfSequence / asOfTime) for
	//     forensic and year-15 verification (Goal 11 — bundles
	//     issued today must verify in 2041 against the head the
	//     log committed to at issue time).
	//   - FORK detection persisted across restarts — a burn
	//     transition observed at runtime survives a restart so
	//     a re-launched JN does not silently re-enter a tainted
	//     log's enforcement path.
	//   - CROSS-NETWORK verification — foreign-log heads pulled
	//     from peer-network gossip pipelines land in the same
	//     journal, keyed by their LogDID. C-3's MultiJurisdiction
	//     LogTrustProvider reads this journal to resolve heads
	//     for cross-log inclusion proofs.
	//
	// nil disables the durable archive (the C-1 baseline / dev mode).
	// Production wires monitoring.MemoryHeadsJournal in-process;
	// the auditor's PostgresHeadsJournal lives at services/auditor/
	// internal/store (Separation of Duties: the JN never persists
	// custody to disk).
	HeadsJournal monitoring.HeadsJournal

	// MultiTrust is the cross-network LogTrustProvider — the C-3
	// successor to the LocalTrust the 5 production call sites use
	// today. It dispatches by LogDID:
	//
	//   - HOME log → delegates to an embedded LocalTrust (byte-
	//     for-byte parity with the existing single-log path).
	//   - FOREIGN log → resolves the head from HeadsJournal at the
	//     requested asOf + pairs it with the pre-declared witness
	//     keyset (one per cfg.GossipIngest.PeerLogs entry).
	//   - UNKNOWN log → verifier.ErrUnknownLog (fail-closed).
	//
	// Production wires this via buildMultiJurisdictionTrust at boot
	// (cmd/network-api/judicial_deps.go). nil leaves the v1.33
	// LocalTrust path in place — the C-4 call-site migration swaps
	// trust.NewLocalTrust(...) → deps.MultiTrust once the foreign
	// PeerLogs are operator-declared.
	MultiTrust verifier.LogTrustProvider

	// TrustedSources is the set of source log DIDs the verify-only ingest
	// tracks (the gossip peers' log DIDs). Used to enumerate TrustedHeads for
	// the peer-consistency endpoint. Empty ⇒ enumerate nothing unless a
	// ?source= filter is supplied.
	TrustedSources []string

	// AuditorRegistry is the on-log auditor registration snapshot used by
	// the v1.33.x reconciler-side scope gate. Each record carries an
	// AuditorDID, public key, Scope bitmap, and EffectivePos. Sorted
	// ascending by EffectivePos. nil disables the gate (pre-v1.33
	// behaviour: every verified finding advances the trusted view). Loaded
	// at boot from cfg.AuditorScope.RegistryFile when present.
	AuditorRegistry network.AuditorRegistrationByPosition

	// AuditorAmendments is the on-log auditor scope-amendment snapshot
	// (v1.33.x). Each record overrides an auditor's registered Scope as of
	// a specific log position. Sorted ascending by EffectivePos. nil /
	// empty is the legal "no amendments yet" state (registry-only scope).
	// Loaded at boot from cfg.AuditorScope.AmendmentFile when present.
	AuditorAmendments network.AuditorScopeAmendmentByPosition

	// AuditorScopeAsOf returns the log position at which the reconciler
	// resolves auditor scopes. Production reads the JN's most recent
	// observed head; tests inject a fixed position. nil falls back to
	// types.LogPosition{} (genesis), which resolves to each auditor's
	// initial registration scope without any amendment overlay.
	AuditorScopeAsOf func(context.Context) types.LogPosition

	// AuthoritativeResolver is the v1.32+ unified endpoint resolver
	// (constructed via crosslog.NewDefaultAuthoritativeResolver) that
	// the JN holds for downstream lookups: ResolveLedger, ResolveWitness,
	// ResolveAuditor, ResolvePeer. Populated at boot from the network
	// bootstrap document + the same registry/amendments slices above.
	// nil when no NetworkBootstrapFile is configured (dev / pre-cert
	// deployments) — call sites then fall back to their bespoke discovery
	// paths.
	//
	// The Materialized record slices (WitnessEndpointRecords,
	// WitnessLabelRecords) start empty pending an on-log walker; the
	// resolver still serves ResolveLedger from MirrorManifest and the
	// auditor surfaces from AuditorRegistryRecords/AuditorScopeAmendmentRecords.
	AuthoritativeResolver *discover.DefaultAuthoritativeResolver
}

// ──────────────────────────────────────────────────────────────────
// Server / BuildHandler / NewServer
// ──────────────────────────────────────────────────────────────────

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

	// ── Cases ─────────────────────────────────────────────
	registerCaseRoutes(mux, &cfg.Deps)
	// ── Appeals ───────────────────────────────────────────
	registerAppealsRoutes(mux, &cfg.Deps)
	// ── Enforcement ───────────────────────────────────────
	registerEnforcementRoutes(mux, &cfg.Deps)
	// ── Parties ───────────────────────────────────────────
	registerPartiesRoutes(mux, &cfg.Deps)
	// ── Onboarding ────────────────────────────────────────
	registerOnboardingRoutes(mux, &cfg.Deps)
	// ── Artifacts ─────────────────────────────────────────
	registerArtifactRoutes(mux, &cfg.Deps)
	// ── Verification (read-side) ─────────────────────────────
	registerVerificationRoutes(mux, &cfg.Deps)
	// ── Monitoring ────────────────────────────────────────
	registerMonitoringRoutes(mux, &cfg.Deps)
	// ── Consortium (federation) ──────────────────────────────
	registerConsortiumRoutes(mux, &cfg.Deps)
	// ── Delegation + Topology (operational stubs) ───────────────
	registerDelegationTopologyRoutes(mux, &cfg.Deps)
	// ── Escrow recovery ────────────────────────────────
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

// ──────────────────────────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────────────────────────

// callerDID extracts the authenticated caller's DID. Composer-level
// auth (api/middleware) sets this; handlers call this once at the top
// of ServeHTTP. When auth is wired at the composer, a missing DID is
// a programming bug (the request reached the handler without auth);
// when auth is not wired (dev / test), the empty return signals
// "unauthenticated" and the handler decides whether to proceed.
//
// We also fall back to api/exchange/auth.SignerDIDFromContext for
// backwards compat with callers that still come through the exchange's
// own SignerAuth wrapper (previous path).
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

// ──────────────────────────────────────────────────────────────────
// Request/response envelope helpers
// ──────────────────────────────────────────────────────────────────

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
