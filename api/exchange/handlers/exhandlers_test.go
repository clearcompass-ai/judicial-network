package handlers

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clearcompass-ai/judicial-network/api/exchange/index"
	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

// -------------------------------------------------------------------------
// Mock KeyStore — implements full keystore.KeyStore interface
// -------------------------------------------------------------------------

type mockKS struct {
	keys map[string]*keystore.KeyInfo
	priv map[string]ed25519.PrivateKey
}

func newMockKS() *mockKS {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &mockKS{
		keys: map[string]*keystore.KeyInfo{
			"did:web:test:judge": {DID: "did:web:test:judge", KeyID: "k1", PublicKey: pub, Purpose: "signing"},
		},
		priv: map[string]ed25519.PrivateKey{
			"did:web:test:judge": priv,
		},
	}
}

func (m *mockKS) Sign(did string, data []byte) ([]byte, error) {
	priv := m.priv[did]
	if priv == nil {
		return nil, http.ErrNotSupported
	}
	return ed25519.Sign(priv, data), nil
}

func (m *mockKS) Generate(did, purpose string) (*keystore.KeyInfo, error) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	info := &keystore.KeyInfo{DID: did, KeyID: "gen", PublicKey: pub, Purpose: purpose}
	m.keys[did] = info
	m.priv[did] = priv
	return info, nil
}

func (m *mockKS) Rotate(did string, tier int) (*keystore.KeyInfo, error) {
	return m.Generate(did, "signing")
}

func (m *mockKS) PublicKey(did string) (ed25519.PublicKey, error) {
	info := m.keys[did]
	if info == nil {
		return nil, http.ErrNotSupported
	}
	return info.PublicKey, nil
}

func (m *mockKS) List() []*keystore.KeyInfo {
	var out []*keystore.KeyInfo
	for _, v := range m.keys {
		out = append(out, v)
	}
	return out
}

func (m *mockKS) Destroy(did string) error {
	delete(m.keys, did)
	delete(m.priv, did)
	return nil
}

func (m *mockKS) ExportForEscrow(did string) (ed25519.PrivateKey, error) {
	priv := m.priv[did]
	if priv == nil {
		return nil, http.ErrNotSupported
	}
	return priv, nil
}

var _ keystore.KeyStore = (*mockKS)(nil)

// -------------------------------------------------------------------------
// Mock operator
// -------------------------------------------------------------------------

func mockOperator(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"position": 42})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testDeps(t *testing.T) *Dependencies {
	t.Helper()
	op := mockOperator(t)
	return &Dependencies{
		OperatorEndpoint:      op.URL,
		ArtifactStoreEndpoint: "http://localhost:0",
		KeyStore:              newMockKS(),
		Index:                 index.NewLogIndex(),
		ExchangeDID:           "did:web:test-exchange",
	}
}

// -------------------------------------------------------------------------
// EntryBuildHandler
// -------------------------------------------------------------------------

func TestBuildHandler_RootEntity(t *testing.T) {
	h := NewEntryBuildHandler(testDeps(t))
	body, _ := json.Marshal(BuildRequest{
		Builder:       "root_entity",
		SignerDID:     "did:web:test",
		DomainPayload: json.RawMessage(`{"docket":"2027-CR-001"}`),
	})
	req := httptest.NewRequest("POST", "/v1/build", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestBuildHandler_UnknownBuilder_400(t *testing.T) {
	h := NewEntryBuildHandler(testDeps(t))
	body, _ := json.Marshal(BuildRequest{Builder: "nonexistent", SignerDID: "did:web:test"})
	req := httptest.NewRequest("POST", "/v1/build", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestBuildHandler_InvalidJSON_400(t *testing.T) {
	h := NewEntryBuildHandler(testDeps(t))
	req := httptest.NewRequest("POST", "/v1/build", bytes.NewReader([]byte("{")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// -------------------------------------------------------------------------
// EntrySignHandler
// -------------------------------------------------------------------------

func TestSignHandler_Success(t *testing.T) {
	h := NewEntrySignHandler(testDeps(t))
	body, _ := json.Marshal(SignRequest{EntryBytes: []byte("test"), SignerDID: "did:web:test:judge"})
	req := httptest.NewRequest("POST", "/v1/sign", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

// -------------------------------------------------------------------------
// EntryFullHandler
// -------------------------------------------------------------------------

func TestFullHandler_RoundTrip(t *testing.T) {
	h := NewEntryFullHandler(testDeps(t))
	body, _ := json.Marshal(BuildRequest{
		Builder:       "root_entity",
		SignerDID:     "did:web:test:judge",
		DomainPayload: json.RawMessage(`{"docket":"2027-CR-002"}`),
	})
	req := httptest.NewRequest("POST", "/v1/build-sign-submit", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

// -------------------------------------------------------------------------
// EntryStatusHandler
// -------------------------------------------------------------------------

func TestStatusHandler(t *testing.T) {
	h := NewEntryStatusHandler(testDeps(t))
	req := httptest.NewRequest("GET", "/v1/entries/sha256:abc/status", nil)
	req.SetPathValue("hash", "sha256:abc")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

// -------------------------------------------------------------------------
// KeyListHandler + DIDListHandler
// -------------------------------------------------------------------------

func TestKeyListHandler(t *testing.T) {
	h := NewKeyListHandler(testDeps(t))
	req := httptest.NewRequest("GET", "/v1/keys", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestDIDListHandler(t *testing.T) {
	h := NewDIDListHandler(testDeps(t))
	req := httptest.NewRequest("GET", "/v1/dids", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

// -------------------------------------------------------------------------
// writeJSON + writeError
// -------------------------------------------------------------------------

func TestWriteJSON_ContentType(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestWriteError_Format(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "bad")
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "bad" {
		t.Errorf("error = %q", resp["error"])
	}
}
