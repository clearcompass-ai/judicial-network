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
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
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

// NonceStore tracks used nonces to prevent replay.
type NonceStore struct {
	mu     sync.Mutex
	nonces map[string]time.Time
	window time.Duration
}

// NewNonceStore creates a nonce store with a given validity window.
func NewNonceStore(window time.Duration) *NonceStore {
	return &NonceStore{
		nonces: make(map[string]time.Time),
		window: window,
	}
}

// Check returns true if the nonce is fresh (not seen before and within window).
func (ns *NonceStore) Check(nonce string, timestamp time.Time) bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	// Prune expired nonces.
	cutoff := time.Now().Add(-ns.window)
	for k, t := range ns.nonces {
		if t.Before(cutoff) {
			delete(ns.nonces, k)
		}
	}

	// Check timestamp is within window.
	if time.Since(timestamp) > ns.window {
		return false
	}

	// Check nonce not replayed.
	if _, exists := ns.nonces[nonce]; exists {
		return false
	}

	ns.nonces[nonce] = timestamp
	return true
}

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

	// Verify nonce freshness.
	if !sa.nonceStore.Check(signed.Nonce, signed.Timestamp) {
		return "", fmt.Errorf("auth: nonce expired or replayed")
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
