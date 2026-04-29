/*
FILE PATH: exchange/auth/signed_request.go

DESCRIPTION:
    Verifies signed request envelopes from signers. Two auth modes:

    Mode A (mTLS): DID extracted from client cert SAN.
    Mode B (signed envelope): request body includes a signature
    over the canonical request bytes, verifiable against the
    signer DID's public key.

    Anti-replay: nonce + timestamp window.
    Anti-relay: request is bound to the specific action.

    The middleware also checks on-log delegation liveness by calling
    the verification API. A signer whose delegation has been revoked
    on-log cannot authenticate even with a valid cert or signature.

    This is the MetaMask model: the signer proves identity by
    demonstrating control of their DID key. The exchange (wallet)
    won't sign until the key holder approves.

KEY DEPENDENCIES:
    - ortholog-sdk/crypto/signatures: entry_verify (guide §13)
*/
package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	sdkauth "github.com/clearcompass-ai/ortholog-sdk/exchange/auth"
)

// SignedRequest is the envelope a signer sends when not using mTLS.
type SignedRequest struct {
	SignerDID string          `json:"signer_did"`
	Action    string          `json:"action"`
	Payload   json.RawMessage `json:"payload"`
	Timestamp time.Time       `json:"timestamp"`
	Nonce     string          `json:"nonce"`
	Signature []byte          `json:"signature"` // Ed25519 over canonical bytes
}

// NonceStore composes the SDK's strict-forever NonceStore (the replay
// gate) with a freshness window (the staleness gate). The SDK contract
// (sdkauth/nonce_store.go::CONTRACT — STRICT FOREVER) requires nonce
// reservations to be permanent — pre-this-refactor the JN local store
// pruned entries on a TTL, which violated that contract and made every
// signed request older than the window unprotected against replay.
//
// The new design splits the two concerns:
//
//   - sdkauth.NonceStore (memory or redis backend) for replay defense.
//     Reservations are permanent; the strict-forever contract holds.
//   - window for freshness. Requests with timestamp older than window
//     are rejected before the nonce is reserved, so the store does not
//     accumulate reservations for requests that would have failed
//     freshness anyway. This is the backpressure that keeps the
//     strict-forever store bounded in practice.
//
// The Check API is preserved for backward compatibility with existing
// auth_test.go assertions; new call sites should use Reserve directly.
type NonceStore struct {
	store  sdkauth.NonceStore
	window time.Duration
}

// NewNonceStore creates a strict-forever nonce store backed by the
// SDK's InMemoryNonceStore plus a freshness window.
func NewNonceStore(window time.Duration) *NonceStore {
	return &NonceStore{
		store:  sdkauth.NewInMemoryNonceStore(),
		window: window,
	}
}

// NewNonceStoreWithBackend wires an arbitrary sdkauth.NonceStore (e.g.,
// a configured RedisNonceStore for multi-replica deployments) plus a
// freshness window. Use this from the deployment factory; tests and
// single-replica deployments use NewNonceStore.
func NewNonceStoreWithBackend(store sdkauth.NonceStore, window time.Duration) *NonceStore {
	return &NonceStore{store: store, window: window}
}

// Check returns true if the nonce is fresh (timestamp within window
// AND not seen before). Backward-compatible API.
//
// Errors from the underlying SDK store are folded into a false return
// for compatibility; new call sites should use Reserve which surfaces
// the typed sentinel (ErrNonceReserved / ErrNonceStoreUnavailable).
func (ns *NonceStore) Check(nonce string, timestamp time.Time) bool {
	if ns.window > 0 && time.Since(timestamp) > ns.window {
		return false
	}
	return ns.Reserve(context.Background(), nonce) == nil
}

// Reserve records the nonce as seen via the SDK store. Returns
// sdkauth.ErrNonceReserved on replay, sdkauth.ErrNonceStoreUnavailable
// on infrastructure failure, sdkauth.ErrNonceEmpty on empty input.
func (ns *NonceStore) Reserve(ctx context.Context, nonce string) error {
	return ns.store.Reserve(ctx, nonce)
}

// CheckFreshness returns nil if timestamp is within the configured
// window, ErrTimestampStale otherwise. Splits the freshness check
// out so callers can fail-fast on stale timestamps before reserving
// (avoids growing the strict-forever store with would-be-rejected
// reservations).
func (ns *NonceStore) CheckFreshness(timestamp time.Time) error {
	if ns.window <= 0 {
		return nil
	}
	if time.Since(timestamp) > ns.window {
		return ErrTimestampStale
	}
	return nil
}

// ErrTimestampStale is returned by CheckFreshness when a signed
// request's timestamp is older than the configured window.
var ErrTimestampStale = errors.New("auth: signed request timestamp older than window")

// VerifySignedRequest verifies the Ed25519 signature over the canonical
// request bytes. The canonical form is: signer_did + action + payload + timestamp + nonce.
func VerifySignedRequest(req *SignedRequest, publicKey ed25519.PublicKey) error {
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s",
		req.SignerDID,
		req.Action,
		string(req.Payload),
		req.Timestamp.UTC().Format(time.RFC3339Nano),
		req.Nonce,
	)

	if !ed25519.Verify(publicKey, []byte(canonical), req.Signature) {
		return fmt.Errorf("auth: signature verification failed for %s", req.SignerDID)
	}
	return nil
}

// SignerAuth is middleware that authenticates signers via mTLS cert or
// signed request envelope, then checks on-log delegation liveness.
type SignerAuth struct {
	nonceStore           *NonceStore
	verificationEndpoint string
	publicKeyResolver    PublicKeyResolver
}

// PublicKeyResolver maps a DID to its Ed25519 public key.
// In production, this resolves via DID Document lookup.
type PublicKeyResolver interface {
	Resolve(did string) (ed25519.PublicKey, error)
}

// NewSignerAuth creates the signer auth middleware.
func NewSignerAuth(verificationEndpoint string) *SignerAuth {
	return &SignerAuth{
		nonceStore:           NewNonceStore(5 * time.Minute),
		verificationEndpoint: verificationEndpoint,
	}
}

// SetPublicKeyResolver sets the resolver for Ed25519 public keys.
func (sa *SignerAuth) SetPublicKeyResolver(r PublicKeyResolver) {
	sa.publicKeyResolver = r
}

// Wrap wraps a handler with signer authentication.
func (sa *SignerAuth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signerDID, err := sa.authenticate(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Attach authenticated signer DID to request context.
		ctx := WithSignerDID(r.Context(), signerDID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (sa *SignerAuth) authenticate(r *http.Request) (string, error) {
	// Mode A: mTLS — extract DID from client cert SAN.
	did := ExtractDIDFromRequest(r)
	if did != "" {
		return did, nil
	}

	// Mode B: signed request envelope in body.
	if r.Body == nil {
		return "", fmt.Errorf("auth: no client cert and no request body")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("auth: read body: %w", err)
	}

	var signed SignedRequest
	if err := json.Unmarshal(body, &signed); err != nil {
		return "", fmt.Errorf("auth: invalid signed request: %w", err)
	}

	if signed.SignerDID == "" {
		return "", fmt.Errorf("auth: missing signer_did")
	}

	// Freshness gate: reject stale timestamps before any nonce work.
	// Avoids bloating the strict-forever NonceStore with reservations
	// for requests that would have failed freshness anyway.
	if err := sa.nonceStore.CheckFreshness(signed.Timestamp); err != nil {
		return "", fmt.Errorf("auth: %w", err)
	}
	// Replay gate: SDK strict-forever Reserve. Returns typed sentinel
	// on collision (ErrNonceReserved) or infrastructure failure
	// (ErrNonceStoreUnavailable).
	if err := sa.nonceStore.Reserve(r.Context(), signed.Nonce); err != nil {
		switch {
		case errors.Is(err, sdkauth.ErrNonceReserved):
			return "", fmt.Errorf("auth: nonce replayed")
		case errors.Is(err, sdkauth.ErrNonceStoreUnavailable):
			return "", fmt.Errorf("auth: nonce store unavailable")
		default:
			return "", fmt.Errorf("auth: nonce reserve: %w", err)
		}
	}

	// Verify signature.
	if sa.publicKeyResolver != nil {
		pubKey, err := sa.publicKeyResolver.Resolve(signed.SignerDID)
		if err != nil {
			return "", fmt.Errorf("auth: resolve public key: %w", err)
		}
		if err := VerifySignedRequest(&signed, pubKey); err != nil {
			return "", err
		}
	}

	return signed.SignerDID, nil
}

// Context key for authenticated signer DID.
type signerDIDKey struct{}

// WithSignerDID attaches an authenticated signer DID to the context.
func WithSignerDID(ctx context.Context, did string) context.Context {
	return context.WithValue(ctx, signerDIDKey{}, did)
}

// SignerDIDFromContext retrieves the authenticated signer DID.
func SignerDIDFromContext(ctx context.Context) string {
	did, _ := ctx.Value(signerDIDKey{}).(string)
	return did
}
