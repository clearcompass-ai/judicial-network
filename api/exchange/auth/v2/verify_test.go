package v2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/did"
	sdkauth "github.com/baseproof/baseproof/exchange/auth"
)

// ─────────────────────────────────────────────────────────────────────
// Shared test helpers — used by verify_test.go and signer_auth_test.go.
// ─────────────────────────────────────────────────────────────────────

// ed25519StubVerifier is a SignatureVerifier (did.SignatureVerifier
// shape) that delegates to a single Ed25519 public key. Used to
// register a verifier for the "key" method in tests without
// pulling did:key's full multicodec parsing — sufficient because
// the SDK envelope verify just calls registry.Verify with the
// expected pubkey already bound by DID identity.
type ed25519StubVerifier struct {
	pub ed25519.PublicKey
}

func (v *ed25519StubVerifier) Verify(_ context.Context, _ string, message, sig []byte, algoID uint16) error {
	if algoID != envelope.SigAlgoEd25519 {
		return errors.New("ed25519StubVerifier: wrong algoID")
	}
	if !ed25519.Verify(v.pub, message, sig) {
		return errors.New("ed25519StubVerifier: bad signature")
	}
	return nil
}

func newRegistryEd25519(t *testing.T, pub ed25519.PublicKey) *did.VerifierRegistry {
	t.Helper()
	reg := did.NewVerifierRegistry()
	if err := reg.Register("key", &ed25519StubVerifier{pub: pub}); err != nil {
		t.Fatalf("registry.Register: %v", err)
	}
	return reg
}

// memNonceStore is a process-local strict-forever store — same
// semantics as the SDK's InMemoryNonceStore but local so tests
// don't share state.
type memNonceStore struct {
	mu       sync.Mutex
	reserved map[string]struct{}
}

func newMemNonceStore() *memNonceStore {
	return &memNonceStore{reserved: map[string]struct{}{}}
}

func (s *memNonceStore) Reserve(_ context.Context, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.reserved[nonce]; ok {
		return sdkauth.ErrNonceReserved
	}
	s.reserved[nonce] = struct{}{}
	return nil
}

// signedReq builds a Request whose Signature verifies against the
// passed Ed25519 private key. Convenience for the verify tests.
func signedReq(t *testing.T, sk ed25519.PrivateKey, env sdkauth.SignedRequestEnvelope, action, destination string) *Request {
	t.Helper()
	r := &Request{Envelope: env, Action: action, Destination: destination}
	signing, err := r.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	hash := sha256.Sum256(signing)
	r.Signature = ed25519.Sign(sk, hash[:])
	return r
}

// genKey is shorthand for an Ed25519 keypair generated against
// crypto/rand.
func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// ─────────────────────────────────────────────────────────────────────
// VERIFY TESTS
// ─────────────────────────────────────────────────────────────────────

// TestVerifyRequest_HappyPath is the baseline: a properly-signed
// Request verifies cleanly under the SDK envelope gate + the v2
// extension.
func TestVerifyRequest_HappyPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)
	req := signedReq(t, priv, validEnvelope(now), "create_filing", "did:web:exch:davidson")

	err := VerifyRequest(
		context.Background(),
		newRegistryEd25519(t, pub),
		req,
		envelope.SigAlgoEd25519,
		newMemNonceStore(),
		VerifyOptions{
			ExpectedDomain: "api.example.com",
			ExpectedAction: "create_filing",
			Now:            func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestVerifyRequest_ActionMismatch_Fails pins ExpectedAction
// enforcement: a request meant for endpoint X must not pass
// verification at endpoint Y, even with a perfect signature.
func TestVerifyRequest_ActionMismatch_Fails(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)
	req := signedReq(t, priv, validEnvelope(now), "create_filing", "")

	err := VerifyRequest(
		context.Background(),
		newRegistryEd25519(t, pub),
		req,
		envelope.SigAlgoEd25519,
		newMemNonceStore(),
		VerifyOptions{
			ExpectedAction: "amend_filing", // mismatch
			Now:            func() time.Time { return now },
		},
	)
	if !errors.Is(err, ErrActionMismatch) {
		t.Fatalf("want ErrActionMismatch, got %v", err)
	}
}

// TestVerifyRequest_NonceReplayed_FailsAtSDK pins replay detection:
// the second submission of the same envelope's nonce produces
// ErrEnvelopeNonceReused from the SDK.
func TestVerifyRequest_NonceReplayed_FailsAtSDK(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)
	req := signedReq(t, priv, validEnvelope(now), "create_filing", "")
	store := newMemNonceStore()

	if err := VerifyRequest(
		context.Background(),
		newRegistryEd25519(t, pub),
		req,
		envelope.SigAlgoEd25519,
		store,
		VerifyOptions{Now: func() time.Time { return now }},
	); err != nil {
		t.Fatalf("first verify: %v", err)
	}

	err := VerifyRequest(
		context.Background(),
		newRegistryEd25519(t, pub),
		req,
		envelope.SigAlgoEd25519,
		store,
		VerifyOptions{Now: func() time.Time { return now }},
	)
	if !errors.Is(err, sdkauth.ErrEnvelopeNonceReused) {
		t.Fatalf("want ErrEnvelopeNonceReused, got %v", err)
	}
}

// TestVerifyRequest_DomainMismatch_FailsAtSDK pins the SDK's
// ExpectedDomain enforcement still runs under v2.
func TestVerifyRequest_DomainMismatch_FailsAtSDK(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)
	req := signedReq(t, priv, validEnvelope(now), "create_filing", "")

	err := VerifyRequest(
		context.Background(),
		newRegistryEd25519(t, pub),
		req,
		envelope.SigAlgoEd25519,
		newMemNonceStore(),
		VerifyOptions{
			ExpectedDomain: "other.example.com", // mismatch
			Now:            func() time.Time { return now },
		},
	)
	if !errors.Is(err, sdkauth.ErrEnvelopeDomainMismatch) {
		t.Fatalf("want ErrEnvelopeDomainMismatch, got %v", err)
	}
}

// TestVerifyRequest_ValidityWindowExceeded_FailsAtSDK pins the
// SDK's MaxValidityWindow ceiling. An envelope spanning >1h is
// rejected at the SDK gate before any signature work — the gate
// fires inside sdkauth.VerifyRequest via validateFields().
//
// We don't need a real signature here; the wide-window check fires
// before signature verification. Pass arbitrary bytes for
// req.Signature to confirm the gate's order.
func TestVerifyRequest_ValidityWindowExceeded_FailsAtSDK(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, _ := genKey(t)
	env := validEnvelope(now)
	env.ExpiresAt = env.IssuedAt.Add(sdkauth.MaxValidityWindow + time.Minute)
	req := &Request{Envelope: env, Action: "create_filing", Signature: []byte("dummy")}

	err := VerifyRequest(
		context.Background(),
		newRegistryEd25519(t, pub),
		req,
		envelope.SigAlgoEd25519,
		newMemNonceStore(),
		VerifyOptions{Now: func() time.Time { return now }},
	)
	if !errors.Is(err, sdkauth.ErrEnvelopeValidityTooWide) {
		t.Fatalf("want ErrEnvelopeValidityTooWide, got %v", err)
	}
}

// TestVerifyRequest_TamperedSignature_Fails pins the most basic
// security property: a flipped bit in the signature fails verify.
func TestVerifyRequest_TamperedSignature_Fails(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)
	req := signedReq(t, priv, validEnvelope(now), "create_filing", "")
	req.Signature[0] ^= 0xff // tamper

	err := VerifyRequest(
		context.Background(),
		newRegistryEd25519(t, pub),
		req,
		envelope.SigAlgoEd25519,
		newMemNonceStore(),
		VerifyOptions{Now: func() time.Time { return now }},
	)
	if err == nil {
		t.Fatal("verify accepted tampered signature")
	}
	if strings.Contains(err.Error(), "ErrActionMismatch") {
		t.Errorf("wrong failure surface; got %v", err)
	}
}

// TestVerifyRequest_DestinationTampered_Fails pins the swap-replay
// defense: changing Destination between sign and verify produces
// different SigningBytes, so the stored signature fails verify.
func TestVerifyRequest_DestinationTampered_Fails(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)
	req := signedReq(t, priv, validEnvelope(now), "create_filing", "did:web:exch:davidson")
	req.Destination = "did:web:exch:shelby" // tamper after signing

	err := VerifyRequest(
		context.Background(),
		newRegistryEd25519(t, pub),
		req,
		envelope.SigAlgoEd25519,
		newMemNonceStore(),
		VerifyOptions{Now: func() time.Time { return now }},
	)
	if err == nil {
		t.Fatal("verify accepted destination-tampered request")
	}
}

// TestVerifyRequest_ActionTampered_Fails pins the cross-endpoint
// replay defense at the cryptographic layer (companion to
// ExpectedAction's policy-layer check).
func TestVerifyRequest_ActionTampered_Fails(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)
	req := signedReq(t, priv, validEnvelope(now), "create_filing", "")
	req.Action = "amend_filing" // tamper after signing

	err := VerifyRequest(
		context.Background(),
		newRegistryEd25519(t, pub),
		req,
		envelope.SigAlgoEd25519,
		newMemNonceStore(),
		VerifyOptions{Now: func() time.Time { return now }},
	)
	if err == nil {
		t.Fatal("verify accepted action-tampered request")
	}
}

// TestVerifyRequest_NilRequest_Fails pins the defensive guard.
func TestVerifyRequest_NilRequest_Fails(t *testing.T) {
	err := VerifyRequest(
		context.Background(),
		newRegistryEd25519(t, nil),
		nil, envelope.SigAlgoEd25519, newMemNonceStore(), VerifyOptions{})
	if err == nil {
		t.Fatal("nil Request must error")
	}
}
