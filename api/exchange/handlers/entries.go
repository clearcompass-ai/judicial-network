/*
FILE PATH: exchange/handlers/entries.go

DESCRIPTION:
    Entry lifecycle handlers: build → sign → submit. The exchange
    holds the private key, builds entries via SDK builders, signs
    with the custodied key, and forwards to the operator.

    Five endpoints:
      POST /v1/entries/build             → SDK Build* → unsigned entry bytes
      POST /v1/entries/sign              → sign with custodied key
      POST /v1/entries/submit            → forward signed bytes to operator
      POST /v1/entries/build-sign-submit → all three in one call
      GET  /v1/entries/status/{hash}     → submission tracking

WAVE 1 ADMISSION GATEKEEPER:
    Per ortholog-sdk/docs/implementation-obligations.md ("Exchange
    Admission Gatekeeper"), the build path MUST consult a domain
    scope_limit registry BEFORE signing. The cryptographic chain on
    the log will eventually catch a violation at read time
    (verification/scope_enforcement.go), but the exchange is the
    earliest place we can refuse to sign — and refusing to sign is
    the only place we can prevent a write that the operator would
    otherwise accept and persist forever.

    Wiring: Dependencies.ScopeChecker (nil = AllowAll, used by tests
    that don't yet have a roster). Production deployments inject a
    registry-backed checker so a request to issue, e.g., a sealing
    order under a key whose scope_limit is "daily_assignment" returns
    403 Forbidden before KeyStore.Sign is ever called.

KEY DEPENDENCIES:
    - ortholog-sdk/builder: all Build* functions (guide §11.3)
    - exchange/keystore: Sign (key custody)
    - exchange/auth: SignerDIDFromContext (authenticated caller)
*/
package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/api/exchange/auth"
	"github.com/clearcompass-ai/judicial-network/api/exchange/index"
	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

// ScopeChecker authorizes a signing request before the exchange
// invokes its key custody. Implementations consult a roster (e.g.,
// the YAML-driven officer registry maintained by
// delegation/roster_sync.go) and return ErrScopeForbidden when the
// signer's scope_limit does not permit the requested builder.
//
// Returning a non-nil error fail-closes admission: KeyStore.Sign is
// not called, no signing payload reaches the wire, no operator round
// trip is initiated.
type ScopeChecker interface {
	// Allowed returns nil iff the (signerDID, builder) pair is
	// permitted under the signer's scope_limit. Returns
	// ErrScopeForbidden on policy denial; returns other error types
	// for infrastructure failure (registry unavailable, malformed
	// scope, etc.). The handler maps ErrScopeForbidden → 403 and any
	// other non-nil error → 500.
	Allowed(signerDID, builder string) error
}

// ErrScopeForbidden is the canonical "this signer cannot issue this
// builder type" sentinel. Domains construct a wrapping error around
// this sentinel so audit pipelines key on errors.Is.
var ErrScopeForbidden = errors.New("exchange/handlers: scope_limit forbids this builder for signer")

// allowAll is the default ScopeChecker for tests / single-tenant
// deployments where every authenticated signer has full breadth.
// Production deployments inject a roster-backed checker.
type allowAll struct{}

func (allowAll) Allowed(string, string) error { return nil }

// AllowAllScopeChecker returns a ScopeChecker that authorizes every
// signing request. Tests and pre-roster deployments use this.
func AllowAllScopeChecker() ScopeChecker { return allowAll{} }

// InMemoryScopeChecker is a roster-backed ScopeChecker. Map values
// are the case-insensitive set of allowed builder names. An empty
// or missing entry denies every builder (closed-by-default — the
// inverse of AllowAllScopeChecker).
type InMemoryScopeChecker struct {
	byDID map[string]map[string]struct{}
}

// NewInMemoryScopeChecker constructs a roster from a DID-keyed map
// of allowed builder names. Names are normalized (trim+lower) at
// construction time so call-time comparison is byte-equality.
func NewInMemoryScopeChecker(roster map[string][]string) *InMemoryScopeChecker {
	out := &InMemoryScopeChecker{byDID: make(map[string]map[string]struct{}, len(roster))}
	for did, names := range roster {
		set := make(map[string]struct{}, len(names))
		for _, n := range names {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == "" {
				continue
			}
			set[n] = struct{}{}
		}
		out.byDID[did] = set
	}
	return out
}

// Allowed implements ScopeChecker.
func (c *InMemoryScopeChecker) Allowed(signerDID, builderName string) error {
	if c == nil {
		return fmt.Errorf("exchange/handlers: nil scope checker")
	}
	set, ok := c.byDID[signerDID]
	if !ok {
		return fmt.Errorf("%w: signer %q not in roster", ErrScopeForbidden, signerDID)
	}
	if len(set) == 0 {
		return fmt.Errorf("%w: signer %q has empty scope_limit", ErrScopeForbidden, signerDID)
	}
	if _, found := set[strings.ToLower(strings.TrimSpace(builderName))]; !found {
		return fmt.Errorf("%w: signer=%q builder=%q", ErrScopeForbidden, signerDID, builderName)
	}
	return nil
}

// Dependencies shared across all exchange handlers.
type Dependencies struct {
	OperatorEndpoint      string
	ArtifactStoreEndpoint string
	VerificationEndpoint  string
	KeyStore              keystore.KeyStore
	Index                 *index.LogIndex
	ExchangeDID           string

	// ScopeChecker authorizes every build/full request BEFORE the
	// exchange invokes its key custody. nil → AllowAllScopeChecker
	// (tests / pre-roster deployments). Production wires an
	// InMemoryScopeChecker (or backend-of-choice) populated from the
	// roster_sync output.
	ScopeChecker ScopeChecker
}

// scopeOrAllowAll returns the configured checker or the AllowAll
// default. Callers receive a non-nil ScopeChecker unconditionally.
func (d *Dependencies) scopeOrAllowAll() ScopeChecker {
	if d == nil || d.ScopeChecker == nil {
		return allowAll{}
	}
	return d.ScopeChecker
}

// ─── Build ──────────────────────────────────────────────────────────

type EntryBuildHandler struct{ deps *Dependencies }

func NewEntryBuildHandler(deps *Dependencies) *EntryBuildHandler {
	return &EntryBuildHandler{deps: deps}
}

type BuildRequest struct {
	Destination string
	Builder       string          `json:"builder"`
	SignerDID     string          `json:"signer_did"`
	DomainPayload json.RawMessage `json:"domain_payload"`
	TargetRoot    *uint64         `json:"target_root,omitempty"`
	LogDID        string          `json:"log_did,omitempty"`
}

func (h *EntryBuildHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())

	var req BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.SignerDID == "" {
		req.SignerDID = callerDID
	}

	// Wave 1 admission gatekeeper: refuse to build (and thereby refuse
	// to subsequently sign) when the signer's scope_limit does not
	// permit this builder type. ErrScopeForbidden → 403; any other
	// error → 500 (registry infra failure).
	if err := h.deps.scopeOrAllowAll().Allowed(req.SignerDID, req.Builder); err != nil {
		if errors.Is(err, ErrScopeForbidden) {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "scope check infra: "+err.Error())
		return
	}

	entry, err := dispatchBuilder(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// SDK v7.75 forbids Serialize on unsigned entries. The build
	// endpoint returns SigningPayload — the exact bytes the caller
	// (or the exchange's key custody) must hash and sign before the
	// envelope can be re-assembled and submitted.
	entryBytes := envelope.SigningPayload(entry)

	writeJSON(w, http.StatusOK, map[string]any{
		"entry_bytes": entryBytes,
	})
}

func dispatchBuilder(req BuildRequest) (*envelope.Entry, error) {
	switch req.Builder {
	case "root_entity":
		return builder.BuildRootEntity(builder.RootEntityParams{
			Destination: req.Destination,
			SignerDID: req.SignerDID,
			Payload:   req.DomainPayload,
		})
	case "amendment":
		var targetRoot types.LogPosition
		if req.TargetRoot != nil {
			targetRoot = types.LogPosition{LogDID: req.LogDID, Sequence: *req.TargetRoot}
		}
		return builder.BuildAmendment(builder.AmendmentParams{
			Destination: req.Destination,
			SignerDID:  req.SignerDID,
			TargetRoot: targetRoot,
			Payload:    req.DomainPayload,
		})
	case "commentary":
		return builder.BuildCommentary(builder.CommentaryParams{
			Destination: req.Destination,
			SignerDID: req.SignerDID,
			Payload:   req.DomainPayload,
		})
	case "enforcement":
		return builder.BuildEnforcement(builder.EnforcementParams{
			Destination: req.Destination,
			SignerDID: req.SignerDID,
			Payload:   req.DomainPayload,
		})
	default:
		return nil, fmt.Errorf("unknown builder: %s", req.Builder)
	}
}

// ─── Sign ───────────────────────────────────────────────────────────

type EntrySignHandler struct{ deps *Dependencies }

func NewEntrySignHandler(deps *Dependencies) *EntrySignHandler {
	return &EntrySignHandler{deps: deps}
}

type SignRequest struct {
	EntryBytes []byte `json:"entry_bytes"`
	SignerDID  string `json:"signer_did"`
}

func (h *EntrySignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	sig, err := h.deps.KeyStore.Sign(req.SignerDID, req.EntryBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"signed_entry_bytes": append(req.EntryBytes, sig...),
		"signature":          sig,
	})
}

// ─── Submit ─────────────────────────────────────────────────────────

type EntrySubmitHandler struct{ deps *Dependencies }

func NewEntrySubmitHandler(deps *Dependencies) *EntrySubmitHandler {
	return &EntrySubmitHandler{deps: deps}
}

func (h *EntrySubmitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body failed")
		return
	}

	// Forward to operator via the SDK-tuned shared client
	// (sdklog.DefaultClient — RetryAfterRoundTripper + 100-conn
	// pool). See management.go::operatorSubmitClient.
	resp, err := operatorSubmitClient.Post(
		h.deps.OperatorEndpoint+"/v1/entries",
		"application/octet-stream",
		bytes.NewReader(body),
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "operator unreachable")
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// ─── Build+Sign+Submit ──────────────────────────────────────────────

type EntryFullHandler struct{ deps *Dependencies }

func NewEntryFullHandler(deps *Dependencies) *EntryFullHandler {
	return &EntryFullHandler{deps: deps}
}

func (h *EntryFullHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())

	var req BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.SignerDID == "" {
		req.SignerDID = callerDID
	}

	// Wave 1 admission gatekeeper: same gate as EntryBuildHandler so
	// the build-sign-submit shortcut cannot bypass the scope_limit
	// check that the staged path enforces. The order is fail-fast:
	// scope first, builder dispatch second, sign last.
	if err := h.deps.scopeOrAllowAll().Allowed(req.SignerDID, req.Builder); err != nil {
		if errors.Is(err, ErrScopeForbidden) {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "scope check infra: "+err.Error())
		return
	}

	// Build.
	entry, err := dispatchBuilder(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// v7.75 split: signers sign over SigningPayload (preamble +
	// header + payload) — never over a Serialize that already
	// includes a signatures section. After signing, re-build the
	// entry with the signature attached and Serialize the result
	// for transport to the operator.
	signingPayload := envelope.SigningPayload(entry)
	sig, err := h.deps.KeyStore.Sign(req.SignerDID, signingPayload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed")
		return
	}
	signedEntry, err := envelope.NewEntry(entry.Header, entry.DomainPayload, []envelope.Signature{
		{
			SignerDID: entry.Header.SignerDID,
			AlgoID:    envelope.SigAlgoECDSA,
			Bytes:     sig,
		},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "assemble signed entry: "+err.Error())
		return
	}
	signed := envelope.Serialize(signedEntry)

	// Submit to operator via shared SDK-tuned client.
	submitToOperator(w, h.deps.OperatorEndpoint, signed)
}

// ─── Status ─────────────────────────────────────────────────────────

type EntryStatusHandler struct{ deps *Dependencies }

func NewEntryStatusHandler(deps *Dependencies) *EntryStatusHandler {
	return &EntryStatusHandler{deps: deps}
}

func (h *EntryStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	// In production, track submission status in a local DB.
	writeJSON(w, http.StatusOK, map[string]any{
		"hash":   hash,
		"status": "submitted",
	})
}

// ─── Helpers ────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
