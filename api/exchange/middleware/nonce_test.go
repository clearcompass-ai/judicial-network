/*
FILE PATH: api/exchange/middleware/nonce_test.go

COVERAGE:
    Every code path in nonce.go: missing header, default vs custom
    header name, replay rejection, store-unavailable surfacing,
    misconfig classification, scope namespacing, panics on nil/empty
    constructor inputs, and downstream-handler isolation on rejection.
*/
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/exchange/auth"
)

// ─── Helpers ────────────────────────────────────────────────────────

// stubStore lets tests pin the Reserve outcome (custom error or
// success) and asserts on the keys reserved.
type stubStore struct {
	mu       sync.Mutex
	reserved map[string]struct{}
	err      error
}

func newStubStore() *stubStore {
	return &stubStore{reserved: make(map[string]struct{})}
}

func (s *stubStore) Reserve(_ context.Context, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if _, ok := s.reserved[nonce]; ok {
		return auth.ErrNonceReserved
	}
	s.reserved[nonce] = struct{}{}
	return nil
}

func (s *stubStore) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.reserved))
	for k := range s.reserved {
		out = append(out, k)
	}
	return out
}

func nonceOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// ─── Happy path: fresh nonce passes ─────────────────────────────────

func TestNonce_FreshNonce_Passes(t *testing.T) {
	store := newStubStore()
	h := NewNonceMiddleware(NonceConfig{Store: store, Scope: "sealed-read"}, nonceOK())

	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Header.Set(DefaultNonceHeader, "abc123")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	keys := store.keys()
	if len(keys) != 1 || keys[0] != "sealed-read::abc123" {
		t.Errorf("keys = %v, want [sealed-read::abc123]", keys)
	}
}

// ─── Custom header overrides DefaultNonceHeader ─────────────────────

func TestNonce_CustomHeader(t *testing.T) {
	store := newStubStore()
	h := NewNonceMiddleware(NonceConfig{
		Store: store, Scope: "key-rotate", HeaderName: "X-My-Nonce",
	}, nonceOK())

	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Header.Set("X-My-Nonce", "n42")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if keys := store.keys(); len(keys) != 1 || keys[0] != "key-rotate::n42" {
		t.Errorf("keys = %v", keys)
	}
}

// ─── Missing header → 400 nonce_missing ────────────────────────────

func TestNonce_MissingHeader_400(t *testing.T) {
	store := newStubStore()
	h := NewNonceMiddleware(NonceConfig{Store: store, Scope: "sealed-read"}, nonceOK())

	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	var rb nonceRejectionBody
	_ = json.Unmarshal(w.Body.Bytes(), &rb)
	if rb.Code != string(codeNonceMissing) {
		t.Errorf("Code = %q, want %q", rb.Code, codeNonceMissing)
	}
	if rb.Scope != "sealed-read" {
		t.Errorf("Scope = %q", rb.Scope)
	}
}

// ─── Replay → 409 nonce_replayed ────────────────────────────────────

func TestNonce_Replay_409(t *testing.T) {
	store := newStubStore()
	h := NewNonceMiddleware(NonceConfig{Store: store, Scope: "sealed-read"}, nonceOK())

	first := httptest.NewRequest(http.MethodPost, "/x", nil)
	first.Header.Set(DefaultNonceHeader, "n1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, first)
	if w.Code != http.StatusOK {
		t.Fatalf("first status = %d", w.Code)
	}

	second := httptest.NewRequest(http.MethodPost, "/x", nil)
	second.Header.Set(DefaultNonceHeader, "n1")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, second)
	if w2.Code != http.StatusConflict {
		t.Fatalf("replay status = %d, want 409", w2.Code)
	}
	var rb nonceRejectionBody
	_ = json.Unmarshal(w2.Body.Bytes(), &rb)
	if rb.Code != string(codeNonceReplayed) {
		t.Errorf("Code = %q", rb.Code)
	}
}

// ─── Store unavailable → 503 nonce_store_unavailable ───────────────

func TestNonce_StoreUnavailable_503(t *testing.T) {
	store := &stubStore{reserved: map[string]struct{}{}, err: auth.ErrNonceStoreUnavailable}
	h := NewNonceMiddleware(NonceConfig{Store: store, Scope: "x"}, nonceOK())

	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Header.Set(DefaultNonceHeader, "n")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	var rb nonceRejectionBody
	_ = json.Unmarshal(w.Body.Bytes(), &rb)
	if rb.Code != string(codeNonceUnavailable) {
		t.Errorf("Code = %q", rb.Code)
	}
}

// ─── Empty-nonce error from store classifies as misconfig 400 ─────

func TestNonce_StoreEmptyNonceError_400Misconfig(t *testing.T) {
	store := &stubStore{reserved: map[string]struct{}{}, err: auth.ErrNonceEmpty}
	h := NewNonceMiddleware(NonceConfig{Store: store, Scope: "x"}, nonceOK())
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Header.Set(DefaultNonceHeader, "n")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", w.Code)
	}
	var rb nonceRejectionBody
	_ = json.Unmarshal(w.Body.Bytes(), &rb)
	if rb.Code != string(codeNonceMisconfig) {
		t.Errorf("Code = %q", rb.Code)
	}
}

// ─── Unknown store error → 500 nonce_misconfig ────────────────────

func TestNonce_UnknownStoreError_500(t *testing.T) {
	store := &stubStore{reserved: map[string]struct{}{}, err: errors.New("weird")}
	h := NewNonceMiddleware(NonceConfig{Store: store, Scope: "x"}, nonceOK())
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Header.Set(DefaultNonceHeader, "n")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", w.Code)
	}
	var rb nonceRejectionBody
	_ = json.Unmarshal(w.Body.Bytes(), &rb)
	if rb.Code != string(codeNonceMisconfig) {
		t.Errorf("Code = %q", rb.Code)
	}
}

// ─── Scope namespacing: same nonce across scopes does NOT collide ──

func TestNonce_DistinctScopes_NoCollision(t *testing.T) {
	store := newStubStore()
	hA := NewNonceMiddleware(NonceConfig{Store: store, Scope: "scope-a"}, nonceOK())
	hB := NewNonceMiddleware(NonceConfig{Store: store, Scope: "scope-b"}, nonceOK())

	for _, h := range []http.Handler{hA, hB} {
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		r.Header.Set(DefaultNonceHeader, "n42") // same nonce
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d (same nonce reused under distinct scope must pass)", w.Code)
		}
	}
	// Two distinct scope-prefixed entries.
	keys := store.keys()
	if len(keys) != 2 {
		t.Errorf("keys = %d, want 2 — distinct scopes must namespace separately", len(keys))
	}
	hasA, hasB := false, false
	for _, k := range keys {
		if strings.HasPrefix(k, "scope-a::") {
			hasA = true
		}
		if strings.HasPrefix(k, "scope-b::") {
			hasB = true
		}
	}
	if !hasA || !hasB {
		t.Errorf("missing one of {scope-a,scope-b}: %v", keys)
	}
}

// ─── Constructor panics on programmer errors ──────────────────────

func TestNewNonceMiddleware_NilStore_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil store")
		}
	}()
	_ = NewNonceMiddleware(NonceConfig{Scope: "x"}, nonceOK())
}

func TestNewNonceMiddleware_EmptyScope_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on empty scope")
		}
	}()
	_ = NewNonceMiddleware(NonceConfig{Store: newStubStore()}, nonceOK())
}

func TestNewNonceMiddleware_NilNext_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil next")
		}
	}()
	_ = NewNonceMiddleware(NonceConfig{Store: newStubStore(), Scope: "x"}, nil)
}

// ─── Rejected request never calls next ─────────────────────────────

func TestNonce_Rejected_NeverCallsNext(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	h := NewNonceMiddleware(NonceConfig{Store: newStubStore(), Scope: "x"}, next)
	r := httptest.NewRequest(http.MethodPost, "/x", nil) // missing header
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if called {
		t.Error("downstream must NOT be called when rejected")
	}
}

// ─── classifyNonceError covers every typed branch ─────────────────

func TestClassifyNonceError_AllBranches(t *testing.T) {
	cases := []struct {
		err    error
		code   nonceCode
		status int
	}{
		{auth.ErrNonceReserved, codeNonceReplayed, http.StatusConflict},
		{auth.ErrNonceStoreUnavailable, codeNonceUnavailable, http.StatusServiceUnavailable},
		{auth.ErrNonceEmpty, codeNonceMisconfig, http.StatusBadRequest},
		{errors.New("other"), codeNonceMisconfig, http.StatusInternalServerError},
	}
	for _, c := range cases {
		gotCode, gotStatus := classifyNonceError(c.err)
		if gotCode != c.code || gotStatus != c.status {
			t.Errorf("classify(%v) = (%q,%d), want (%q,%d)",
				c.err, gotCode, gotStatus, c.code, c.status)
		}
	}
}
