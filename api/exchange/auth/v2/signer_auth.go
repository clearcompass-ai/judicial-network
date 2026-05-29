/*
FILE PATH:

	api/exchange/auth/v2/signer_auth.go

DESCRIPTION:

	SignerAuth is the HTTP middleware that authenticates exchange
	writes via mTLS (cert SAN URI -> caller DID) or via a v2
	Request body (signature over the SDK envelope + JN extension).

	Multi-tenant NonceStore routing
	───────────────────────────────
	Per-Destination NonceStore namespace isolation — the load-
	bearing security property pinned by the pre-v2
	TestNonceIsolation_AcrossDestinations — is preserved here.
	When a Request carries a non-empty Destination, replay
	reservation routes to nonceStores[destination]; the empty /
	unknown case falls back to nonceStore.

	The middleware reads the body ONCE and replays it to the
	downstream handler via http.Request.Body replacement, so
	handlers see the original bytes. Auth-failed requests get a
	401 with the error message; auth-passed requests flow through
	with WithSignerDID applied to the context.
*/
package v2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/clearcompass-ai/attesta/did"
	sdkauth "github.com/clearcompass-ai/attesta/exchange/auth"
)

// MTLSExtractor extracts a DID from the client cert's SAN URI.
// Used for the mTLS auth mode; nil disables it.
//
// Decoupled as an interface so this package doesn't pull JN's
// httpmw transitively, and so tests can install a stub.
type MTLSExtractor interface {
	ExtractDIDFromRequest(r *http.Request) string
}

// SignerAuthConfig configures SignerAuth. Every field is REQUIRED
// at production unless documented otherwise — the zero value is
// not a usable middleware.
type SignerAuthConfig struct {
	// Registry dispatches per-DID-method signature verification.
	// Populate with did.NewVerifierRegistry().Register("key",
	// verifier) and equivalents at boot.
	Registry *did.VerifierRegistry

	// AlgoID identifies which signature algorithm the JN-side
	// signed requests use. Pre-v2 was Ed25519 (envelope.SigAlgoEd25519
	// = 0x0002); the new field makes the choice explicit and admits
	// the PQ algorithms (envelope.SigAlgoMLDSA65 = 0x0007 etc.) once
	// the SDK admission dispatch lands (ledger#152 #4).
	AlgoID uint16

	// PerDestinationNonceStores maps Destination -> NonceStore.
	// Empty / unknown Destination falls back to FallbackNonceStore.
	PerDestinationNonceStores map[string]sdkauth.NonceStore

	// FallbackNonceStore is the per-process NonceStore for
	// requests with empty Destination or destinations not in
	// PerDestinationNonceStores. Required (the v1.34 SDK gate
	// rejects a nil NonceStore at VerifyRequest time unless
	// AllowNoReplayCheck is explicitly true; we never set that).
	FallbackNonceStore sdkauth.NonceStore

	// MTLSExtractor extracts the SAN URI DID. nil disables the
	// mTLS auth mode.
	MTLSExtractor MTLSExtractor

	// ExpectedDomain, if set, is enforced on every request. The
	// SDK rejects domain mismatches.
	ExpectedDomain string

	// ValidityWindow caps (ExpiresAt-IssuedAt). Zero -> SDK
	// default (1h max).
	ValidityWindow time.Duration
}

// SignerAuth is the HTTP middleware. Construct via NewSignerAuth.
type SignerAuth struct {
	cfg SignerAuthConfig
}

// NewSignerAuth constructs the middleware. Fails closed when any
// required field is missing — at boot, never at request time.
func NewSignerAuth(cfg SignerAuthConfig) (*SignerAuth, error) {
	if cfg.Registry == nil {
		return nil, fmt.Errorf("auth/v2: Registry required")
	}
	if cfg.AlgoID == 0 {
		return nil, fmt.Errorf("auth/v2: AlgoID required (envelope.SigAlgoEd25519 = 0x0002 etc.)")
	}
	if cfg.FallbackNonceStore == nil {
		return nil, fmt.Errorf("auth/v2: FallbackNonceStore required (the v1.34 SDK rejects a nil NonceStore at VerifyRequest time)")
	}
	return &SignerAuth{cfg: cfg}, nil
}

// Wrap returns an http.Handler that authenticates the request,
// attaches the caller DID to the request context via
// WithSignerDID, and forwards to next. Auth-failed requests get
// http.StatusUnauthorized.
func (sa *SignerAuth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signerDID, err := sa.authenticate(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := WithSignerDID(r.Context(), signerDID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate runs the two auth modes (mTLS first, then signed
// envelope) and returns the resolved signer DID on success.
func (sa *SignerAuth) authenticate(r *http.Request) (string, error) {
	// Mode A: mTLS - extract DID from client cert SAN.
	if sa.cfg.MTLSExtractor != nil {
		if did := sa.cfg.MTLSExtractor.ExtractDIDFromRequest(r); did != "" {
			return did, nil
		}
	}

	// Mode B: signed envelope in body.
	if r.Body == nil {
		return "", fmt.Errorf("auth/v2: no client cert and no request body")
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("auth/v2: read body: %w", err)
	}
	// Replay the body so the downstream handler sees it unchanged.
	r.Body = io.NopCloser(bytes.NewReader(body))

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("auth/v2: invalid signed request: %w", err)
	}
	if req.Envelope.DID == "" {
		return "", fmt.Errorf("auth/v2: missing envelope.did")
	}

	// Per-destination NonceStore routing.
	store := sa.nonceStoreFor(req.Destination)

	// SDK envelope verify with CanonicalBytes seam binds the JN
	// extension. SDK runs: field hygiene -> clock skew -> validity
	// window -> domain match -> nonce reserve -> signature.
	err = VerifyRequest(r.Context(), sa.cfg.Registry, &req, sa.cfg.AlgoID, store,
		VerifyOptions{
			ExpectedDomain: sa.cfg.ExpectedDomain,
			ValidityWindow: sa.cfg.ValidityWindow,
		})
	if err != nil {
		switch {
		case errors.Is(err, sdkauth.ErrEnvelopeNonceReused):
			return "", fmt.Errorf("auth/v2: nonce replayed")
		case errors.Is(err, sdkauth.ErrEnvelopeExpired),
			errors.Is(err, sdkauth.ErrEnvelopeNotYetValid):
			return "", fmt.Errorf("auth/v2: envelope outside validity window: %w", err)
		case errors.Is(err, sdkauth.ErrEnvelopeDomainMismatch):
			return "", fmt.Errorf("auth/v2: domain mismatch: %w", err)
		default:
			return "", fmt.Errorf("auth/v2: %w", err)
		}
	}

	return req.Envelope.DID, nil
}

// nonceStoreFor returns the NonceStore for a request. Per-tenant
// destinations route to PerDestinationNonceStores; empty / unknown
// falls back to FallbackNonceStore. Always returns a non-nil
// store (FallbackNonceStore is required at construction).
func (sa *SignerAuth) nonceStoreFor(destination string) sdkauth.NonceStore {
	if destination != "" {
		if s, ok := sa.cfg.PerDestinationNonceStores[destination]; ok && s != nil {
			return s
		}
	}
	return sa.cfg.FallbackNonceStore
}

// ──────────────────────────────────────────────────────────────────
// Signer-DID context plumbing (preserved from v1)
// ──────────────────────────────────────────────────────────────────

type signerDIDKey struct{}

// WithSignerDID attaches an authenticated signer DID to the context.
func WithSignerDID(ctx context.Context, did string) context.Context {
	return context.WithValue(ctx, signerDIDKey{}, did)
}

// SignerDIDFromContext retrieves the authenticated signer DID, or
// "" when none was attached.
func SignerDIDFromContext(ctx context.Context) string {
	did, _ := ctx.Value(signerDIDKey{}).(string)
	return did
}
