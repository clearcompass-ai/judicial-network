// FILE PATH: api/verification/handlers/verify_consistency_test.go
//
// Tests for Phase 8 /v1/verify/consistency endpoint. Verifies
// the JN-side request validation; the cryptographic check is
// exercised end-to-end in tests/contracts/ against a real
// Ledger tile API. These tests cover:
//
//  1. Empty body → 400.
//  2. Missing tile_base_url → 400 with a clear message.
//  3. Invalid hex root_hash → 400.
//  4. Wrong-length root_hash (not 32 bytes) → 400.
//  5. old > new tree size → 200 with consistent=false (SDK
//     rejects; we surface the cryptographic verdict).
//  6. Valid request shape with an unreachable tile_base_url →
//     200 with consistent=false (fetch error bubbles up
//     through verifier.VerifyConsistency).
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifyConsistency_EmptyBody_400(t *testing.T) {
	h := NewVerifyConsistencyHandler(&Dependencies{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/verify/consistency",
		bytes.NewBufferString("")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body should 400, got %d", rec.Code)
	}
}

func TestVerifyConsistency_MissingTileBaseURL_400(t *testing.T) {
	h := NewVerifyConsistencyHandler(&Dependencies{})
	body := mustJSONbytes(t, map[string]any{
		"source_log_did": "did:test",
		"old_head":       map[string]any{"tree_size": 1, "root_hash": "01" + strings.Repeat("00", 31)},
		"new_head":       map[string]any{"tree_size": 2, "root_hash": "02" + strings.Repeat("00", 31)},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/verify/consistency",
		bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing tile_base_url should 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "tile_base_url required") {
		t.Errorf("error message missing 'tile_base_url required': %s", rec.Body.String())
	}
}

func TestVerifyConsistency_InvalidHexRoot_400(t *testing.T) {
	h := NewVerifyConsistencyHandler(&Dependencies{})
	body := mustJSONbytes(t, map[string]any{
		"source_log_did": "did:test",
		"old_head":       map[string]any{"tree_size": 1, "root_hash": "ZZZZ"},
		"new_head":       map[string]any{"tree_size": 2, "root_hash": "02" + strings.Repeat("00", 31)},
		"tile_base_url":  "https://ledger.example",
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/verify/consistency",
		bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid hex should 400, got %d", rec.Code)
	}
}

func TestVerifyConsistency_WrongLengthRoot_400(t *testing.T) {
	h := NewVerifyConsistencyHandler(&Dependencies{})
	body := mustJSONbytes(t, map[string]any{
		"source_log_did": "did:test",
		"old_head":       map[string]any{"tree_size": 1, "root_hash": "0102"}, // 2 bytes
		"new_head":       map[string]any{"tree_size": 2, "root_hash": "02" + strings.Repeat("00", 31)},
		"tile_base_url":  "https://ledger.example",
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/verify/consistency",
		bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short root_hash should 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "must be 32 bytes") {
		t.Errorf("error message missing length hint: %s", rec.Body.String())
	}
}

func TestVerifyConsistency_OldGreaterThanNew_ConsistentFalse(t *testing.T) {
	h := NewVerifyConsistencyHandler(&Dependencies{})
	body := mustJSONbytes(t, map[string]any{
		"source_log_did": "did:test",
		"old_head":       map[string]any{"tree_size": 100, "root_hash": "01" + strings.Repeat("00", 31)},
		"new_head":       map[string]any{"tree_size": 50, "root_hash": "02" + strings.Repeat("00", 31)},
		"tile_base_url":  "https://ledger.example",
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/verify/consistency",
		bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("size-order check should yield 200 with consistent=false, got %d", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if c, _ := resp["consistent"].(bool); c {
		t.Fatalf("old>new should report consistent=false; got %v", resp)
	}
}

func TestVerifyConsistency_UnreachableTileURL_ConsistentFalse(t *testing.T) {
	h := NewVerifyConsistencyHandler(&Dependencies{})
	body := mustJSONbytes(t, map[string]any{
		"source_log_did": "did:test",
		"old_head":       map[string]any{"tree_size": 1, "root_hash": "01" + strings.Repeat("00", 31)},
		"new_head":       map[string]any{"tree_size": 2, "root_hash": "02" + strings.Repeat("00", 31)},
		"tile_base_url":  "http://127.0.0.1:1/never-resolves",
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/verify/consistency",
		bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("unreachable tile URL should yield 200 with consistent=false, got %d", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if c, _ := resp["consistent"].(bool); c {
		t.Fatalf("unreachable tile URL should report consistent=false; got %v", resp)
	}
}

// mustJSONbytes is a test-only helper that fails the test on a
// marshal error and returns the wire bytes.
func mustJSONbytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}
