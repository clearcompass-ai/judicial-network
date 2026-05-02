/*
FILE PATH: api/exchange/auth/multitenant_test.go

DESCRIPTION:
    Multi-tenant nonce-routing contract for SignerAuth.

    Pinned properties:
      1. NewSignerAuthWithNonceStores routes per-destination — a
         nonce burned on dst-A is still acceptable on dst-B.
      2. Empty / unknown Destination falls back to the single-tenant
         store; backward compat preserved.
      3. The fallback store is auto-allocated when the caller passes
         nil; the constructor never produces a zero-store SignerAuth.
      4. nonceStoreFor never returns nil.
      5. VerifySignedRequest canonical bytes include Destination iff
         it is non-empty — old single-tenant signatures still verify,
         and a request that was signed with one Destination cannot
         be replayed against another Destination because the verify
         step rejects the swap.
*/
package auth

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	sdkauth "github.com/clearcompass-ai/ortholog-sdk/exchange/auth"
)

// ─────────────────────────────────────────────────────────────────────
// Constructor + fallback semantics
// ─────────────────────────────────────────────────────────────────────

func TestNewSignerAuthWithNonceStores_NilFallback_AutoAllocates(t *testing.T) {
	sa := NewSignerAuthWithNonceStores("ep", nil, nil)
	if sa.nonceStore == nil {
		t.Error("constructor MUST auto-allocate fallback when nil supplied")
	}
}

func TestNonceStoreFor_FallsBackWhenDestinationEmpty(t *testing.T) {
	fallback := NewNonceStore(time.Minute)
	specific := NewNonceStore(time.Minute)
	sa := NewSignerAuthWithNonceStores("ep",
		map[string]*NonceStore{"did:web:dst": specific}, fallback)
	if got := sa.nonceStoreFor(""); got != fallback {
		t.Error("empty destination MUST route to fallback")
	}
	if got := sa.nonceStoreFor("did:web:unknown"); got != fallback {
		t.Error("unknown destination MUST route to fallback")
	}
	if got := sa.nonceStoreFor("did:web:dst"); got != specific {
		t.Error("known destination MUST route to its specific store")
	}
}

func TestNonceStoreFor_NeverReturnsNil(t *testing.T) {
	sa := NewSignerAuth("ep")
	for _, dst := range []string{"", "did:web:x", "did:web:y"} {
		if got := sa.nonceStoreFor(dst); got == nil {
			t.Errorf("nonceStoreFor(%q) returned nil", dst)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Canonical-bytes round-trip — old + new clients
// ─────────────────────────────────────────────────────────────────────

func makeSigningKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func signRequest(t *testing.T, priv ed25519.PrivateKey, req *SignedRequest) {
	t.Helper()
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s",
		req.SignerDID, req.Action, string(req.Payload),
		req.Timestamp.UTC().Format(time.RFC3339Nano), req.Nonce)
	if req.Destination != "" {
		canonical = canonical + "|" + req.Destination
	}
	req.Signature = ed25519.Sign(priv, []byte(canonical))
}

func TestVerifySignedRequest_BackwardCompat_EmptyDestinationVerifies(t *testing.T) {
	pub, priv := makeSigningKey(t)
	req := &SignedRequest{
		SignerDID: "did:key:z6Mki",
		Action:    "submit",
		Payload:   []byte(`{"x":1}`),
		Timestamp: time.Now().UTC(),
		Nonce:     "n1",
	}
	signRequest(t, priv, req)
	if err := VerifySignedRequest(req, pub); err != nil {
		t.Errorf("empty-destination request MUST verify; got %v", err)
	}
}

func TestVerifySignedRequest_DestinationBound(t *testing.T) {
	pub, priv := makeSigningKey(t)
	req := &SignedRequest{
		SignerDID:   "did:key:z6Mki",
		Action:      "submit",
		Destination: "did:web:state:tn:davidson",
		Payload:     []byte(`{"x":1}`),
		Timestamp:   time.Now().UTC(),
		Nonce:       "n1",
	}
	signRequest(t, priv, req)
	if err := VerifySignedRequest(req, pub); err != nil {
		t.Errorf("destination-bound request MUST verify; got %v", err)
	}
	// Swap destination AFTER signing — verification MUST reject.
	req.Destination = "did:web:state:tn:shelby"
	if err := VerifySignedRequest(req, pub); err == nil {
		t.Error("swapped destination MUST reject; canonical bytes changed")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Per-destination namespace isolation
// ─────────────────────────────────────────────────────────────────────

// TestNonceIsolation_AcrossDestinations is the load-bearing
// multi-tenant invariant: a nonce reserved on dst-A MUST NOT collide
// with the same nonce on dst-B. Without this, two co-tenant
// destinations would race each other's nonce space.
func TestNonceIsolation_AcrossDestinations(t *testing.T) {
	storeA := NewNonceStore(time.Minute)
	storeB := NewNonceStore(time.Minute)
	sa := NewSignerAuthWithNonceStores("ep",
		map[string]*NonceStore{
			"did:web:state:tn:davidson": storeA,
			"did:web:state:tn:shelby":   storeB,
		}, NewNonceStore(time.Minute))

	// Reserve nonce on dst-A.
	if err := sa.nonceStoreFor("did:web:state:tn:davidson").
		Reserve(t.Context(), "shared-nonce"); err != nil {
		t.Fatalf("reserve on A: %v", err)
	}
	// Same nonce on dst-A → replay rejected.
	err := sa.nonceStoreFor("did:web:state:tn:davidson").
		Reserve(t.Context(), "shared-nonce")
	if !errors.Is(err, sdkauth.ErrNonceReserved) {
		t.Errorf("replay on same destination MUST reject; got %v", err)
	}
	// Same nonce on dst-B → accepted (distinct namespace).
	if err := sa.nonceStoreFor("did:web:state:tn:shelby").
		Reserve(t.Context(), "shared-nonce"); err != nil {
		t.Errorf("same nonce on different destination MUST succeed; got %v", err)
	}
}
