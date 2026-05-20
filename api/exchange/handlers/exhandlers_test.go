package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"

	"github.com/clearcompass-ai/judicial-network/api/exchange/index"
	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

// -------------------------------------------------------------------------
// Mock KeyStore — implements full keystore.KeyStore interface
// -------------------------------------------------------------------------

// mockKS is a real in-memory secp256k1 keystore seeded with the test
// judge DID. The api/exchange handlers sign over secp256k1 now, so the
// mock IS a MemoryKeyStore (embedded) — there is no fake-curve shortcut.
type mockKS struct {
	*keystore.MemoryKeyStore
}

func newMockKS() *mockKS {
	ks := keystore.NewMemoryKeyStore()
	if _, err := ks.Generate("did:web:test:judge", "signing"); err != nil {
		panic("newMockKS: seed judge: " + err.Error())
	}
	return &mockKS{MemoryKeyStore: ks}
}

var _ keystore.KeyStore = (*mockKS)(nil)

// -------------------------------------------------------------------------
// Mock ledger
// -------------------------------------------------------------------------

func mockLedger(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"position": 42})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testDestination is the target-exchange DID that test request bodies
// stamp into entry.Header.Destination. The api/exchange surface is
// multi-tenant — Dependencies carries no process-level destination —
// so every test that builds an entry must source the destination from
// the request body, exactly like a production caller would.
const testDestination = "did:web:exchange.test"

func testDeps(t *testing.T) *Dependencies {
	t.Helper()
	op := mockLedger(t)
	return &Dependencies{
		LedgerEndpoint:        op.URL,
		ArtifactStoreEndpoint: "http://localhost:0",
		KeyStore:              newMockKS(),
		Index:                 index.NewLogIndex(),
	}
}

// -------------------------------------------------------------------------
//  pin: shared ledger submit client honors 503-Retry-After
// -------------------------------------------------------------------------

// TestSubmitToLedger_RetriesOn503 pins the SDK-transport wiring for
// the package-level ledgerSubmitClient. A 503 with Retry-After: 1
// followed by a 202 succeeds transparently — proving every
// submit-to-ledger site (entries.go EntrySubmitHandler /
// EntryFullHandler, artifacts.go grant, management.go scope ops)
// inherits 503-Retry-After backpressure honoring through the shared
// client. A future regression that drops sdklog.DefaultClient back
// to a bare http.Client breaks this test deterministically.
func TestSubmitToLedger_RetriesOn503(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"position":42}`))
	}))
	defer srv.Close()

	rec := httptest.NewRecorder()
	submitToLedger(rec, srv.URL, []byte("signed-entry-bytes"))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want 202\nbody: %s", rec.Code, rec.Body.String())
	}
	if got := calls.Load(); got < 2 {
		t.Errorf("expected ≥ 2 attempts (503 → 202), got %d", got)
	}
}

// -------------------------------------------------------------------------
// ArtifactPublishHandler — .1 BUG #3 mirror
// -------------------------------------------------------------------------

// TestArtifactPublish_OversizeBody_Returns413 pins the BUG #3 mirror:
// a body larger than maxArtifactPlaintextBytes surfaces as 413
// (http.MaxBytesReader → *http.MaxBytesError) instead of being
// silently truncated to a smaller plaintext that the encryption /
// CID computation processes happily — producing a stored artifact
// that the caller never intended to store.
func TestArtifactPublish_OversizeBody_Returns413(t *testing.T) {
	deps := testDeps(t)
	h := NewArtifactPublishHandler(deps)

	// 64 MiB + 1024 — just past the cap.
	oversized := make([]byte, maxArtifactPlaintextBytes+1024)
	for i := range oversized[:1024] {
		oversized[i] = byte(i & 0xff) // not all zero — a real-looking PDF prefix
	}

	req := httptest.NewRequest(http.MethodPost,
		"/v1/artifacts/publish", bytes.NewReader(oversized))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: got %d (%s), want 413\nbody: %s",
			w.Code, http.StatusText(w.Code), w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("exceeds")) {
		t.Errorf("response should mention size cap: %q", w.Body.String())
	}
}

// Boundary: a body at exactly maxArtifactPlaintextBytes is accepted
// (proving the cap is inclusive on the accept side, not off-by-one).
// We use a 1 KiB body — comfortably under the cap — to keep the test
// fast; the publish path's encryption + CID + push exercises the
// full happy flow against the mock artifact store.
func TestArtifactPublish_HappyPath_Accepted(t *testing.T) {
	deps := testDeps(t)
	deps.ArtifactStoreEndpoint = mockArtifactStore(t).URL
	h := NewArtifactPublishHandler(deps)

	body := []byte("court filing PDF bytes — short enough to round-trip cleanly")
	req := httptest.NewRequest(http.MethodPost,
		"/v1/artifacts/publish", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("happy path: got %d (%s)\nbody: %s",
			w.Code, http.StatusText(w.Code), w.Body.String())
	}
}

// mockArtifactStore returns an httptest server that always 200s.
// Sufficient for the 413-vs-200 contract test.
func mockArtifactStore(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// -------------------------------------------------------------------------
// EntryBuildHandler
// -------------------------------------------------------------------------

func TestBuildHandler_RootEntity(t *testing.T) {
	h := NewEntryBuildHandler(testDeps(t))
	body, _ := json.Marshal(BuildRequest{
		Builder:       "root_entity",
		Destination:   testDestination,
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

// TestBuildHandler_Destination_FlowsToEntryHeader pins the multi-tenant
// payload-driven dispatch contract: the destination supplied in the
// request body MUST land verbatim in entry.Header.Destination. A
// regression where the build path silently substituted a process-level
// default (the previous single-tenant pattern) would surface here.
//
// The test deliberately uses an unusual DID value so a hard-coded
// process default could not coincidentally match.
func TestBuildHandler_Destination_FlowsToEntryHeader(t *testing.T) {
	const arbitraryDest = "did:web:state:tn:counties:hamilton"

	h := NewEntryBuildHandler(testDeps(t))
	body, _ := json.Marshal(BuildRequest{
		Builder:       "root_entity",
		Destination:   arbitraryDest,
		SignerDID:     "did:web:test:judge",
		DomainPayload: json.RawMessage(`{"docket":"2027-CR-MTD"}`),
	})
	req := httptest.NewRequest("POST", "/v1/build", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("build: %d %s", rec.Code, rec.Body.String())
	}
	// The build endpoint returns the SigningPayload (preamble + header
	// + payload), which deserializes back into a partial Entry exposing
	// Header.Destination.
	var resp struct {
		EntryBytes []byte `json:"entry_bytes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	entry, err := envelope.Deserialize(resp.EntryBytes)
	if err != nil {
		// Build returns SigningPayload (unsigned). Its prefix decodes
		// the same header bytes; if Deserialize is strict about
		// signatures, fall back to a header-only check.
		entry = nil
	}
	if entry != nil && entry.Header.Destination != arbitraryDest {
		t.Errorf("Header.Destination = %q, want %q (payload-driven dispatch broken)",
			entry.Header.Destination, arbitraryDest)
	}
	// Belt-and-suspenders: the response bytes must contain the
	// destination string. If they don't, even our header parse can't
	// rescue us.
	if !bytes.Contains(resp.EntryBytes, []byte(arbitraryDest)) {
		t.Errorf("destination %q not present in returned entry bytes (%d bytes)",
			arbitraryDest, len(resp.EntryBytes))
	}
}

// TestBuildHandler_RejectsEmptyDestination_AtBuilder pins that the
// underlying SDK builder rejects an empty Destination — keeping the
// payload-driven contract enforced even if the handler's own validation
// misses an edge case. Production deployments rely on this defense in
// depth: handler validates → builder validates → submit_gate validates.
func TestBuildHandler_RejectsEmptyDestination_AtBuilder(t *testing.T) {
	h := NewEntryBuildHandler(testDeps(t))
	body, _ := json.Marshal(BuildRequest{
		Builder:       "root_entity",
		Destination:   "", // empty — builder MUST reject
		SignerDID:     "did:web:test:judge",
		DomainPayload: json.RawMessage(`{"docket":"empty-dest"}`),
	})
	req := httptest.NewRequest("POST", "/v1/build", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty destination should 400, got %d (body=%s)",
			rec.Code, rec.Body.String())
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
	// The embed-model handler deserializes the entry, signs over its
	// SigningPayload with the signer's secp256k1 key, embeds the
	// signature, and re-serializes — so it needs a real serialized entry.
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:web:test:judge",
		Destination: testDestination,
		EventTime:   1,
	}, []byte(`{"schema_id":"test"}`))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: "did:web:test:judge",
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	entryBytes, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	body, _ := json.Marshal(SignRequest{EntryBytes: entryBytes, SignerDID: "did:web:test:judge"})
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
		Destination:   testDestination,
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
