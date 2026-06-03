package v2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	sdkauth "github.com/baseproof/baseproof/exchange/auth"
)

// stubMTLSExtractor returns a fixed DID, simulating a successful
// SAN URI extraction. The zero value (empty DID) simulates a
// request that doesn't carry a client cert.
type stubMTLSExtractor struct {
	did string
}

func (s stubMTLSExtractor) ExtractDIDFromRequest(_ *http.Request) string {
	return s.did
}

// nextEchoHandler is a downstream handler that surfaces the
// authenticated signer DID on the response.
func nextEchoHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, SignerDIDFromContext(r.Context()))
	})
}

// signRequestBody returns a JSON body for a Request signed under sk.
func signRequestBody(t *testing.T, sk ed25519.PrivateKey, env sdkauth.SignedRequestEnvelope, action, destination string) []byte {
	t.Helper()
	r := signedReq(t, sk, env, action, destination)
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return body
}

// ─────────────────────────────────────────────────────────────────────
// CONSTRUCTOR DISCIPLINE
// ─────────────────────────────────────────────────────────────────────

func TestNewSignerAuth_RejectsNilRegistry(t *testing.T) {
	_, err := NewSignerAuth(SignerAuthConfig{
		AlgoID:             envelope.SigAlgoEd25519,
		FallbackNonceStore: newMemNonceStore(),
	})
	if err == nil || !strings.Contains(err.Error(), "Registry") {
		t.Fatalf("want Registry-required error, got %v", err)
	}
}

func TestNewSignerAuth_RejectsZeroAlgoID(t *testing.T) {
	pub, _ := genKey(t)
	_, err := NewSignerAuth(SignerAuthConfig{
		Registry:           newRegistryEd25519(t, pub),
		FallbackNonceStore: newMemNonceStore(),
	})
	if err == nil || !strings.Contains(err.Error(), "AlgoID") {
		t.Fatalf("want AlgoID-required error, got %v", err)
	}
}

// TestNewSignerAuth_RejectsNilFallbackNonceStore pins the v1.34 SDK
// contract: nil NonceStore would fail at VerifyRequest time. We
// surface the misconfig at boot instead.
func TestNewSignerAuth_RejectsNilFallbackNonceStore(t *testing.T) {
	pub, _ := genKey(t)
	_, err := NewSignerAuth(SignerAuthConfig{
		Registry: newRegistryEd25519(t, pub),
		AlgoID:   envelope.SigAlgoEd25519,
	})
	if err == nil || !strings.Contains(err.Error(), "FallbackNonceStore") {
		t.Fatalf("want FallbackNonceStore-required error, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// MTLS PATH
// ─────────────────────────────────────────────────────────────────────

func TestSignerAuth_MTLSExtractor_BypassesEnvelope(t *testing.T) {
	pub, _ := genKey(t)
	sa, err := NewSignerAuth(SignerAuthConfig{
		Registry:           newRegistryEd25519(t, pub),
		AlgoID:             envelope.SigAlgoEd25519,
		FallbackNonceStore: newMemNonceStore(),
		MTLSExtractor:      stubMTLSExtractor{did: "did:web:trusted.example"},
	})
	if err != nil {
		t.Fatalf("NewSignerAuth: %v", err)
	}
	wrapped := sa.Wrap(nextEchoHandler(t))

	// No body, no cert in test — but the stub extractor returns a
	// DID, simulating a cert match. Auth should succeed.
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, httptest.NewRequest("POST", "/anything", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("mTLS path: status %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	if got := rr.Body.String(); got != "did:web:trusted.example" {
		t.Errorf("signer DID in ctx = %q, want did:web:trusted.example", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// SIGNED ENVELOPE PATH
// ─────────────────────────────────────────────────────────────────────

func TestSignerAuth_SignedEnvelope_HappyPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)
	sa, err := NewSignerAuth(SignerAuthConfig{
		Registry:           newRegistryEd25519(t, pub),
		AlgoID:             envelope.SigAlgoEd25519,
		FallbackNonceStore: newMemNonceStore(),
		// No MTLSExtractor — forces the envelope path.
		ExpectedDomain: "api.example.com",
	})
	if err != nil {
		t.Fatalf("NewSignerAuth: %v", err)
	}
	wrapped := sa.Wrap(nextEchoHandler(t))

	body := signRequestBody(t, priv, validEnvelope(now), "create_filing", "")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, httptest.NewRequest("POST", "/anything", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body=%q", rr.Code, rr.Body.String())
	}
	expected := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	if got := rr.Body.String(); got != expected {
		t.Errorf("ctx DID = %q, want %q", got, expected)
	}
}

func TestSignerAuth_BadSignature_Returns401(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)
	sa, _ := NewSignerAuth(SignerAuthConfig{
		Registry:           newRegistryEd25519(t, pub),
		AlgoID:             envelope.SigAlgoEd25519,
		FallbackNonceStore: newMemNonceStore(),
	})
	wrapped := sa.Wrap(nextEchoHandler(t))

	body := signRequestBody(t, priv, validEnvelope(now), "create_filing", "")
	var req Request
	_ = json.Unmarshal(body, &req)
	req.Signature[0] ^= 0xff
	tampered, _ := json.Marshal(req)

	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, httptest.NewRequest("POST", "/anything", bytes.NewReader(tampered)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rr.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// PER-DESTINATION NONCE STORE ROUTING — load-bearing security
// property preserved from pre-v2.
// ─────────────────────────────────────────────────────────────────────

// TestSignerAuth_NonceIsolation_AcrossDestinations is the
// load-bearing pin: same envelope nonce reserved on Destination A
// must NOT be observed as reserved on Destination B. Carries the
// pre-v2 TestNonceIsolation_AcrossDestinations contract forward
// into the v2 wire shape.
func TestSignerAuth_NonceIsolation_AcrossDestinations(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)

	storeA := newMemNonceStore()
	storeB := newMemNonceStore()
	storeFallback := newMemNonceStore()
	sa, _ := NewSignerAuth(SignerAuthConfig{
		Registry: newRegistryEd25519(t, pub),
		AlgoID:   envelope.SigAlgoEd25519,
		PerDestinationNonceStores: map[string]sdkauth.NonceStore{
			"did:web:exch:davidson": storeA,
			"did:web:exch:shelby":   storeB,
		},
		FallbackNonceStore: storeFallback,
	})
	wrapped := sa.Wrap(nextEchoHandler(t))

	// Send same envelope nonce + same Action under Destination A — succeeds.
	envA := validEnvelope(now)
	envA.Nonce = "shared-nonce"
	bodyA := signRequestBody(t, priv, envA, "create_filing", "did:web:exch:davidson")
	rrA := httptest.NewRecorder()
	wrapped.ServeHTTP(rrA, httptest.NewRequest("POST", "/x", bytes.NewReader(bodyA)))
	if rrA.Code != http.StatusOK {
		t.Fatalf("first dst-A: status %d, body=%q", rrA.Code, rrA.Body.String())
	}

	// Same nonce, Destination B (signed under B). Different
	// SigningBytes (Destination changes them) so we sign a fresh
	// envelope, but the SDK nonce is the SAME string — and storeB
	// is a different store, so reservation succeeds.
	envB := validEnvelope(now)
	envB.Nonce = "shared-nonce"
	bodyB := signRequestBody(t, priv, envB, "create_filing", "did:web:exch:shelby")
	rrB := httptest.NewRecorder()
	wrapped.ServeHTTP(rrB, httptest.NewRequest("POST", "/x", bytes.NewReader(bodyB)))
	if rrB.Code != http.StatusOK {
		t.Fatalf("first dst-B: status %d, body=%q (per-Destination isolation broken)",
			rrB.Code, rrB.Body.String())
	}

	// Replay first request under dst-A — must fail (replayed in storeA).
	rrA2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rrA2, httptest.NewRequest("POST", "/x", bytes.NewReader(bodyA)))
	if rrA2.Code != http.StatusUnauthorized {
		t.Fatalf("replay dst-A: status %d, want 401", rrA2.Code)
	}
}

// TestSignerAuth_EmptyDestination_RoutesToFallback pins the
// single-tenant fallback path.
func TestSignerAuth_EmptyDestination_RoutesToFallback(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)

	fallback := newMemNonceStore()
	perTenant := map[string]sdkauth.NonceStore{
		"did:web:exch:davidson": newMemNonceStore(),
	}
	sa, _ := NewSignerAuth(SignerAuthConfig{
		Registry:                  newRegistryEd25519(t, pub),
		AlgoID:                    envelope.SigAlgoEd25519,
		PerDestinationNonceStores: perTenant,
		FallbackNonceStore:        fallback,
	})
	wrapped := sa.Wrap(nextEchoHandler(t))

	body := signRequestBody(t, priv, validEnvelope(now), "create_filing", "")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, httptest.NewRequest("POST", "/x", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("empty dst: status %d, body=%q", rr.Code, rr.Body.String())
	}
	// Replay → fallback rejects.
	rr2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rr2, httptest.NewRequest("POST", "/x", bytes.NewReader(body)))
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("replay through fallback: status %d, want 401", rr2.Code)
	}
}

// TestSignerAuth_UnknownDestination_RoutesToFallback pins what
// happens when a Request specifies a Destination that has no entry
// in PerDestinationNonceStores — fall through, do NOT silently
// accept.
func TestSignerAuth_UnknownDestination_RoutesToFallback(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)

	fallback := newMemNonceStore()
	sa, _ := NewSignerAuth(SignerAuthConfig{
		Registry:                  newRegistryEd25519(t, pub),
		AlgoID:                    envelope.SigAlgoEd25519,
		PerDestinationNonceStores: map[string]sdkauth.NonceStore{},
		FallbackNonceStore:        fallback,
	})
	wrapped := sa.Wrap(nextEchoHandler(t))

	body := signRequestBody(t, priv, validEnvelope(now), "create_filing", "did:web:exch:unknown")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, httptest.NewRequest("POST", "/x", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("unknown dst: status %d, want 200 (fallback)", rr.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BODY PASSTHROUGH — downstream handlers see original bytes.
// ─────────────────────────────────────────────────────────────────────

func TestSignerAuth_PreservesBodyForDownstream(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)

	bodyCh := make(chan []byte, 1)
	echoBody := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodyCh <- b
	})

	sa, _ := NewSignerAuth(SignerAuthConfig{
		Registry:           newRegistryEd25519(t, pub),
		AlgoID:             envelope.SigAlgoEd25519,
		FallbackNonceStore: newMemNonceStore(),
	})
	wrapped := sa.Wrap(echoBody)

	body := signRequestBody(t, priv, validEnvelope(now), "create_filing", "")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, httptest.NewRequest("POST", "/x", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	got := <-bodyCh
	if !bytes.Equal(got, body) {
		t.Fatalf("downstream body differs from original\n  want %s\n  got  %s", body, got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// CONCURRENT REPLAY — sanity under race.
// ─────────────────────────────────────────────────────────────────────

func TestSignerAuth_ConcurrentReplay_ExactlyOneSucceeds(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)

	sa, _ := NewSignerAuth(SignerAuthConfig{
		Registry:           newRegistryEd25519(t, pub),
		AlgoID:             envelope.SigAlgoEd25519,
		FallbackNonceStore: newMemNonceStore(),
	})
	wrapped := sa.Wrap(nextEchoHandler(t))

	body := signRequestBody(t, priv, validEnvelope(now), "create_filing", "")
	const N = 16
	var wg sync.WaitGroup
	codes := make(chan int, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, httptest.NewRequest("POST", "/x", bytes.NewReader(body)))
			codes <- rr.Code
		}()
	}
	wg.Wait()
	close(codes)
	var ok, unauth int
	for c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusUnauthorized:
			unauth++
		}
	}
	if ok != 1 {
		t.Errorf("OK count = %d, want exactly 1", ok)
	}
	if unauth != N-1 {
		t.Errorf("Unauthorized count = %d, want %d", unauth, N-1)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Sanity: SDK error class surfaces through unauth message.
// ─────────────────────────────────────────────────────────────────────

func TestSignerAuth_NonceReplay_MessageMentionsNonce(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv := genKey(t)

	sa, _ := NewSignerAuth(SignerAuthConfig{
		Registry:           newRegistryEd25519(t, pub),
		AlgoID:             envelope.SigAlgoEd25519,
		FallbackNonceStore: newMemNonceStore(),
	})
	wrapped := sa.Wrap(nextEchoHandler(t))

	body := signRequestBody(t, priv, validEnvelope(now), "create_filing", "")
	// First request succeeds.
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, httptest.NewRequest("POST", "/x", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("first: status %d", rr.Code)
	}
	rr2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rr2, httptest.NewRequest("POST", "/x", bytes.NewReader(body)))
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("replay: status %d, want 401", rr2.Code)
	}
	if !strings.Contains(rr2.Body.String(), "nonce") {
		t.Errorf("error message must mention nonce; got %q", rr2.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────
// Compile-time confirmation that v2 satisfies the basic
// signing-bytes flow used elsewhere (sanity check).
// ─────────────────────────────────────────────────────────────────────

func TestSigningBytes_HashStable(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	req := &Request{Envelope: validEnvelope(now), Action: "x"}
	first, _ := req.SigningBytes()
	second, _ := req.SigningBytes()
	if h1, h2 := sha256.Sum256(first), sha256.Sum256(second); !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash drift across identical SigningBytes() calls")
	}
}

// silencer to keep imports honest.
var _ = errors.Is
