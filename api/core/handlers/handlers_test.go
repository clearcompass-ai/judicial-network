package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/internal/testutil"
)

// ═════════════════════════════════════════════════════════════════════
// Mock OperatorQueryAPI
// ═════════════════════════════════════════════════════════════════════

// mockQueryAPI satisfies sdklog.OperatorQueryAPI.
type mockQueryAPI struct {
	entries map[uint64]types.EntryWithMetadata
}

func (m *mockQueryAPI) ScanFromPosition(startPos uint64, count int) ([]types.EntryWithMetadata, error) {
	entry, ok := m.entries[startPos]
	if !ok {
		return nil, nil
	}
	return []types.EntryWithMetadata{entry}, nil
}

func (m *mockQueryAPI) QueryBySignerDID(did string) ([]types.EntryWithMetadata, error) {
	return nil, nil
}

func (m *mockQueryAPI) QueryByCosignatureOf(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
	return nil, nil
}

func (m *mockQueryAPI) QueryByTargetRoot(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
	return nil, nil
}

func (m *mockQueryAPI) QueryBySchemaRef(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
	return nil, nil
}

// Compile-time check.
var _ sdklog.OperatorQueryAPI = (*mockQueryAPI)(nil)

// ═════════════════════════════════════════════════════════════════════
// Test helpers
// ═════════════════════════════════════════════════════════════════════

func buildTestEntry(t *testing.T) []byte {
	t.Helper()
	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:exchange.test",
		SignerDID: "did:web:courts.test.gov",
		Payload:   []byte(`{"docket":"2027-CR-0001"}`),
	})
	if err != nil {
		t.Fatalf("build test entry: %v", err)
	}
	signed := testutil.SignEntry(t, entry, testutil.GenerateSigningKey(t))
	return envelope.Serialize(signed)
}

func emptyDeps() *Dependencies {
	return &Dependencies{
		LogQueries: map[string]sdklog.OperatorQueryAPI{},
	}
}

func depsWithLog(logID string, entries map[uint64]types.EntryWithMetadata) *Dependencies {
	return &Dependencies{
		LogQueries: map[string]sdklog.OperatorQueryAPI{
			logID: &mockQueryAPI{entries: entries},
		},
	}
}

// ═════════════════════════════════════════════════════════════════════
// operatorFetcher adapter
// ═════════════════════════════════════════════════════════════════════

func TestOperatorFetcher_Fetch_Success(t *testing.T) {
	raw := buildTestEntry(t)
	pos := types.LogPosition{LogDID: "test", Sequence: 42}

	mock := &mockQueryAPI{
		entries: map[uint64]types.EntryWithMetadata{
			42: {CanonicalBytes: raw, Position: pos},
		},
	}

	fetcher := &operatorFetcher{query: mock, logDID: "test"}
	result, err := fetcher.Fetch(pos)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result == nil {
		t.Fatal("result nil")
	}
	if result.Position.Sequence != 42 {
		t.Errorf("position = %d, want 42", result.Position.Sequence)
	}
}

func TestOperatorFetcher_Fetch_NotFound(t *testing.T) {
	mock := &mockQueryAPI{entries: map[uint64]types.EntryWithMetadata{}}
	fetcher := &operatorFetcher{query: mock, logDID: "test"}

	_, err := fetcher.Fetch(types.LogPosition{LogDID: "test", Sequence: 999})
	if err == nil {
		t.Fatal("expected error for missing entry")
	}
}

// ═════════════════════════════════════════════════════════════════════
// VerifyOriginHandler — error paths
// ═════════════════════════════════════════════════════════════════════

func TestVerifyOrigin_InvalidPosition(t *testing.T) {
	handler := NewVerifyOriginHandler(emptyDeps())

	req := httptest.NewRequest("GET", "/v1/verify/origin/test-log/abc", nil)
	req.SetPathValue("logID", "test-log")
	req.SetPathValue("pos", "abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestVerifyOrigin_UnknownLog(t *testing.T) {
	handler := NewVerifyOriginHandler(emptyDeps())

	req := httptest.NewRequest("GET", "/v1/verify/origin/nonexistent/42", nil)
	req.SetPathValue("logID", "nonexistent")
	req.SetPathValue("pos", "42")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ═════════════════════════════════════════════════════════════════════
// VerifyAuthorityHandler — error paths
// ═════════════════════════════════════════════════════════════════════

func TestVerifyAuthority_InvalidPosition(t *testing.T) {
	handler := NewVerifyAuthorityHandler(emptyDeps())

	req := httptest.NewRequest("GET", "/v1/verify/authority/test-log/xyz", nil)
	req.SetPathValue("logID", "test-log")
	req.SetPathValue("pos", "xyz")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestVerifyAuthority_UnknownLog(t *testing.T) {
	handler := NewVerifyAuthorityHandler(emptyDeps())

	req := httptest.NewRequest("GET", "/v1/verify/authority/missing/1", nil)
	req.SetPathValue("logID", "missing")
	req.SetPathValue("pos", "1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ═════════════════════════════════════════════════════════════════════
// VerifyDelegationHandler — error paths
// ═════════════════════════════════════════════════════════════════════

func TestVerifyDelegation_InvalidPosition(t *testing.T) {
	handler := NewVerifyDelegationHandler(emptyDeps())

	req := httptest.NewRequest("GET", "/v1/verify/delegation/test-log/bad", nil)
	req.SetPathValue("logID", "test-log")
	req.SetPathValue("pos", "bad")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestVerifyDelegation_UnknownLog(t *testing.T) {
	handler := NewVerifyDelegationHandler(emptyDeps())

	req := httptest.NewRequest("GET", "/v1/verify/delegation/missing/1", nil)
	req.SetPathValue("logID", "missing")
	req.SetPathValue("pos", "1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ═════════════════════════════════════════════════════════════════════
// VerifyCrossLogHandler — missing witness keys
// ═════════════════════════════════════════════════════════════════════

func TestVerifyCrossLog_MissingWitnessKeys(t *testing.T) {
	deps := &Dependencies{
		WitnessKeys:   map[string][]types.WitnessPublicKey{},
		WitnessQuorum: map[string]int{},
	}
	handler := NewVerifyCrossLogHandler(deps)

	body, _ := json.Marshal(map[string]any{
		"source_log_did": "did:web:unknown",
		"proof":          map[string]any{},
	})

	req := httptest.NewRequest("POST", "/v1/verify/cross-log", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestVerifyCrossLog_InvalidBody(t *testing.T) {
	deps := &Dependencies{}
	handler := NewVerifyCrossLogHandler(deps)

	req := httptest.NewRequest("POST", "/v1/verify/cross-log", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ═════════════════════════════════════════════════════════════════════
// VerifyFraudProofHandler — error paths
// ═════════════════════════════════════════════════════════════════════

func TestVerifyFraudProof_UnknownLog(t *testing.T) {
	handler := NewVerifyFraudProofHandler(emptyDeps())

	body, _ := json.Marshal(map[string]any{
		"log_did":    "did:web:nonexistent",
		"commitment": map[string]any{},
	})

	req := httptest.NewRequest("POST", "/v1/verify/fraud-proof", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestVerifyFraudProof_InvalidBody(t *testing.T) {
	handler := NewVerifyFraudProofHandler(emptyDeps())

	req := httptest.NewRequest("POST", "/v1/verify/fraud-proof", bytes.NewReader([]byte("{")))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ═════════════════════════════════════════════════════════════════════
// VerifyBatchHandler — error paths
// ═════════════════════════════════════════════════════════════════════

func TestVerifyBatch_UnknownLog(t *testing.T) {
	handler := NewVerifyBatchHandler(emptyDeps())

	req := httptest.NewRequest("GET", "/v1/verify/batch/missing/1,2,3", nil)
	req.SetPathValue("logID", "missing")
	req.SetPathValue("positions", "1,2,3")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ═════════════════════════════════════════════════════════════════════
// Response format
// ═════════════════════════════════════════════════════════════════════

func TestWriteJSON_Format(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var parsed map[string]string
	json.NewDecoder(w.Body).Decode(&parsed)
	if parsed["status"] != "ok" {
		t.Errorf("status = %q, want ok", parsed["status"])
	}
}

func TestWriteError_Format(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "invalid input")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}

	var parsed map[string]string
	json.NewDecoder(w.Body).Decode(&parsed)
	if parsed["error"] != "invalid input" {
		t.Errorf("error = %q, want 'invalid input'", parsed["error"])
	}
}
