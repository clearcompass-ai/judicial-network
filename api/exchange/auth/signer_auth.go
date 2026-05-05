/*
FILE PATH: api/exchange/auth/signer_auth.go

DESCRIPTION:

	SignerAuth middleware. Authenticates exchange writes via mTLS
	(cert SAN URI → caller DID) or via the SignedRequest envelope
	(Ed25519 signature + nonce + timestamp → caller DID).

	Multi-tenant nonce routing
	──────────────────────────
	Two constructors:

	  NewSignerAuth(endpoint):
	    Single-tenant. One in-memory NonceStore (5-minute freshness).
	    Used by tests + single-replica dev.

	  NewSignerAuthWithNonceStores(endpoint, perDestination, fallback):
	    Multi-tenant. SignedRequests with a populated Destination
	    route to perDestination[destination]; empty / unknown
	    destinations fall through to fallback. Production composes
	    this from NonceStoreConfig.BuildForExchange called once per
	    registered destination at boot — Redis backend gives
	    namespace isolation across replicas.

	Both expose the same Wrap(next) → http.Handler surface, so
	callers (api/exchange/server.go) pick the right constructor at
	boot and downstream wiring is unchanged.
*/
package auth

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	sdkauth "github.com/clearcompass-ai/attesta/exchange/auth"
)

// SignerAuth is middleware that authenticates signers via mTLS cert
// or signed request envelope, then checks on-log delegation liveness.
//
// nonceStores (optional) holds one NonceStore per destination DID.
// When a SignedRequest carries a non-empty Destination, authenticate
// looks up nonceStores[destination] and uses that for replay defence.
// Otherwise authenticate falls back to nonceStore.
type SignerAuth struct {
	nonceStore           *NonceStore
	nonceStores          map[string]*NonceStore // optional, by destination DID
	verificationEndpoint string
	publicKeyResolver    PublicKeyResolver
}

// PublicKeyResolver maps a DID to its Ed25519 public key. Production
// resolves via DID Document lookup.
type PublicKeyResolver interface {
	Resolve(did string) (ed25519.PublicKey, error)
}

// NewSignerAuth creates a single-tenant signer auth middleware. All
// SignedRequests share one in-memory NonceStore (5-minute freshness).
// Suitable for tests + single-replica dev deployments.
func NewSignerAuth(verificationEndpoint string) *SignerAuth {
	return &SignerAuth{
		nonceStore:           NewNonceStore(5 * time.Minute),
		verificationEndpoint: verificationEndpoint,
	}
}

// NewSignerAuthWithNonceStores creates the multi-tenant signer auth
// middleware. SignedRequests with a populated Destination route to
// nonceStores[destination] for replay defence; the rest fall back
// to fallback. fallback MUST be non-nil so requests with empty /
// unknown destinations always have a store to consult — when the
// caller passes nil, the constructor auto-allocates a 5-minute
// in-memory fallback.
func NewSignerAuthWithNonceStores(verificationEndpoint string, nonceStores map[string]*NonceStore, fallback *NonceStore) *SignerAuth {
	if fallback == nil {
		fallback = NewNonceStore(5 * time.Minute)
	}
	return &SignerAuth{
		nonceStore:           fallback,
		nonceStores:          nonceStores,
		verificationEndpoint: verificationEndpoint,
	}
}

// nonceStoreFor returns the per-request NonceStore. Routes to
// sa.nonceStores[destination] when populated; falls back to
// sa.nonceStore. Always returns a non-nil store.
func (sa *SignerAuth) nonceStoreFor(destination string) *NonceStore {
	if destination != "" {
		if s, ok := sa.nonceStores[destination]; ok && s != nil {
			return s
		}
	}
	return sa.nonceStore
}

// SetPublicKeyResolver sets the resolver for Ed25519 public keys.
func (sa *SignerAuth) SetPublicKeyResolver(r PublicKeyResolver) {
	sa.publicKeyResolver = r
}

// Wrap wraps a handler with signer authentication. Auth-failed
// requests get a 401 + the error message; auth-passed requests
// flow through with WithSignerDID applied to the context.
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

	// Per-destination NonceStore routing. Empty / unknown destination
	// falls back to the single-tenant store (sa.nonceStore).
	store := sa.nonceStoreFor(signed.Destination)

	// Freshness gate: reject stale timestamps before any nonce work.
	// Avoids bloating the strict-forever NonceStore with reservations
	// for requests that would have failed freshness anyway.
	if err := store.CheckFreshness(signed.Timestamp); err != nil {
		return "", fmt.Errorf("auth: %w", err)
	}
	// Replay gate: SDK strict-forever Reserve. Returns typed sentinel
	// on collision (ErrNonceReserved) or infrastructure failure
	// (ErrNonceStoreUnavailable).
	if err := store.Reserve(r.Context(), signed.Nonce); err != nil {
		switch {
		case errors.Is(err, sdkauth.ErrNonceReserved):
			return "", fmt.Errorf("auth: nonce replayed")
		case errors.Is(err, sdkauth.ErrNonceStoreUnavailable):
			return "", fmt.Errorf("auth: nonce store unavailable")
		default:
			return "", fmt.Errorf("auth: nonce reserve: %w", err)
		}
	}

	// Verify signature when a resolver is wired. The mode-A path
	// already returned above, so reaching here means we have a
	// SignedRequest envelope; without a resolver we accept on the
	// envelope's claimed signer (test paths only).
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
