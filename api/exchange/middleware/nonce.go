/*
FILE PATH: api/exchange/middleware/nonce.go

DESCRIPTION:
    HTTP middleware that gates exchange endpoints on nonce uniqueness.
    Per ortholog-sdk/APPLY-destination-binding.md, NonceStore protects
    non-log-entry traffic — the request paths log dedup does not cover:
        - Sealed-record reads
        - Certified-copy delivery / notifications
        - Control-plane mutations (key rotation, webhook registration)
    The middleware reads a nonce from a header, reserves it via the
    SDK's NonceStore.Reserve, and rejects on collision or
    infrastructure failure.

KEY ARCHITECTURAL DECISIONS:
    - Strict-forever semantics: a reserved nonce stays reserved.
      Replay rejection is permanent. NonceStore does NOT garbage-
      collect — that is by design (see ortholog-sdk/exchange/auth
      package godoc).
    - Endpoint-scoped namespacing: the middleware namespaces every
      reservation as `<scope>::<nonce>` so the same client-supplied
      nonce can be reused across distinct endpoints (sealed-read vs
      certified-copy) without colliding. The scope is fixed at
      construction time per route — distinct scope = distinct
      replay-defense surface.
    - Configurable header name (default "X-Ortholog-Nonce"). Empty
      header → 400 with code `nonce_missing`.
    - Stable JSON 4xx error codes: nonce_missing | nonce_replayed |
      nonce_store_unavailable | nonce_misconfig.
    - Composes upstream of any handler that mutates state or returns
      sensitive data; composes downstream of freshness.go (the
      request must be fresh AND have a unique nonce).

KEY DEPENDENCIES:
    - ortholog-sdk/exchange/auth: NonceStore interface + sentinels.
*/
package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/exchange/auth"
)

// DefaultNonceHeader is the request header name read by the
// NonceMiddleware when no override is set.
const DefaultNonceHeader = "X-Ortholog-Nonce"

// NonceConfig parameterizes a single endpoint's nonce gate. Scope
// MUST be non-empty; HeaderName empty → DefaultNonceHeader.
type NonceConfig struct {
	// Store is the underlying SDK NonceStore. Required.
	Store auth.NonceStore
	// Scope namespaces every reservation. Required. Pick a stable
	// per-endpoint string ("sealed-read", "certified-copy",
	// "key-rotate"); changing the scope amounts to forgetting every
	// historical replay defense for that endpoint.
	Scope string
	// HeaderName is the request header that carries the nonce.
	// Empty → DefaultNonceHeader.
	HeaderName string
}

// nonceCode is the stable rejection enum.
type nonceCode string

const (
	codeNonceMissing      nonceCode = "nonce_missing"
	codeNonceReplayed     nonceCode = "nonce_replayed"
	codeNonceUnavailable  nonceCode = "nonce_store_unavailable"
	codeNonceMisconfig    nonceCode = "nonce_misconfig"
)

// nonceRejectionBody mirrors the freshness rejection shape so SIEM
// pipelines key on a uniform schema.
type nonceRejectionBody struct {
	Error string `json:"error"`
	Code  string `json:"code"`
	Scope string `json:"scope,omitempty"`
}

// NewNonceMiddleware returns an http.Handler that gates next on
// nonce uniqueness. Programmer errors (nil store, empty scope,
// nil next) panic at construction.
func NewNonceMiddleware(cfg NonceConfig, next http.Handler) http.Handler {
	if next == nil {
		panic("middleware/nonce: nil next handler")
	}
	if cfg.Store == nil {
		panic("middleware/nonce: nil store")
	}
	if cfg.Scope == "" {
		panic("middleware/nonce: empty scope")
	}
	header := cfg.HeaderName
	if header == "" {
		header = DefaultNonceHeader
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get(header)
		if nonce == "" {
			writeNonceRejection(w, http.StatusBadRequest, nonceRejectionBody{
				Error: fmt.Sprintf("missing %s header", header),
				Code:  string(codeNonceMissing),
				Scope: cfg.Scope,
			})
			return
		}

		key := cfg.Scope + "::" + nonce
		if err := cfg.Store.Reserve(r.Context(), key); err != nil {
			code, status := classifyNonceError(err)
			writeNonceRejection(w, status, nonceRejectionBody{
				Error: err.Error(),
				Code:  string(code),
				Scope: cfg.Scope,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// classifyNonceError maps the SDK's typed errors to our enum and
// HTTP status. Replay → 409 Conflict (the canonical "this resource
// state has already been claimed" status). Infra error → 503.
// Empty/programmer error → 400.
func classifyNonceError(err error) (nonceCode, int) {
	switch {
	case errors.Is(err, auth.ErrNonceReserved):
		return codeNonceReplayed, http.StatusConflict
	case errors.Is(err, auth.ErrNonceStoreUnavailable):
		return codeNonceUnavailable, http.StatusServiceUnavailable
	case errors.Is(err, auth.ErrNonceEmpty):
		// Reachable only via a bug in this middleware (empty header
		// is caught earlier). Surface as misconfig.
		return codeNonceMisconfig, http.StatusBadRequest
	default:
		return codeNonceMisconfig, http.StatusInternalServerError
	}
}

func writeNonceRejection(w http.ResponseWriter, status int, body nonceRejectionBody) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
