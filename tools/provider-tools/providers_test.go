/*
FILE PATH:
    tools/providers/providers_test.go

DESCRIPTION:
    Unit tests for provider tools HTTP handlers. Tests API key enforcement,
    routing correctness, and degraded behavior when DB is unavailable.
    No Postgres required — tests verify the handler contract, not DB queries.

KEY ARCHITECTURAL DECISIONS:
    - No Postgres: DB is nil. All query endpoints return 503.
    - API key enforcement tested: missing key → 401.
    - Health endpoint always works regardless of DB state.
*/
package providers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// -------------------------------------------------------------------------
// 1) Test server construction
// -------------------------------------------------------------------------

func testProviderServer(t *testing.T) *Server {
	t.Helper()
	cfg := common.DefaultConfig()
	cfg.ProviderAPIKeyHeader = "X-API-Key"
	verify := common.NewVerifyClient("http://localhost:0")
	return NewServer(cfg, verify, nil) // nil DB
}

func doProviderRequest(t *testing.T, handler http.Handler, method, path string, body any, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// -------------------------------------------------------------------------
// 2) API key enforcement
// -------------------------------------------------------------------------

func TestSearch_NoAPIKey_Returns401(t *testing.T) {
	s := testProviderServer(t)
	w := doProviderRequest(t, s.Handler(), "GET", "/v1/records/search?q=test", nil, "")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestGetRecord_NoAPIKey_Returns401(t *testing.T) {
	s := testProviderServer(t)
	w := doProviderRequest(t, s.Handler(), "GET", "/v1/records/2027-CR-001", nil, "")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestBackgroundCheck_NoAPIKey_Returns401(t *testing.T) {
	s := testProviderServer(t)
	w := doProviderRequest(t, s.Handler(), "POST", "/v1/background-check",
		map[string]any{"subject_did": "did:web:test"}, "")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// -------------------------------------------------------------------------
// 3) DB unavailable → 503
// -------------------------------------------------------------------------

func TestSearch_NoDB_Returns503(t *testing.T) {
	s := testProviderServer(t)
	w := doProviderRequest(t, s.Handler(), "GET", "/v1/records/search?q=test", nil, "test-key")

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestGetRecord_NoDB_Returns503(t *testing.T) {
	s := testProviderServer(t)
	w := doProviderRequest(t, s.Handler(), "GET", "/v1/records/2027-CR-001", nil, "test-key")

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestListDocuments_NoDB_Returns503(t *testing.T) {
	s := testProviderServer(t)
	w := doProviderRequest(t, s.Handler(), "GET", "/v1/records/2027-CR-001/documents", nil, "test-key")

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestBackgroundCheck_NoDB_Returns503(t *testing.T) {
	s := testProviderServer(t)
	w := doProviderRequest(t, s.Handler(), "POST", "/v1/background-check",
		map[string]any{"subject_did": "did:web:test"}, "test-key")

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

// -------------------------------------------------------------------------
// 4) Background check: validation
// -------------------------------------------------------------------------

func TestBackgroundCheck_MissingSubject_Returns400(t *testing.T) {
	s := testProviderServer(t)
	w := doProviderRequest(t, s.Handler(), "POST", "/v1/background-check",
		map[string]any{}, "test-key")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// -------------------------------------------------------------------------
// 5) Health
// -------------------------------------------------------------------------

func TestHealthz_AlwaysOK(t *testing.T) {
	s := testProviderServer(t)
	w := doProviderRequest(t, s.Handler(), "GET", "/healthz", nil, "")
	// Healthz does not require API key.
	if w.Code != http.StatusOK {
		t.Errorf("healthz = %d, want 200", w.Code)
	}
}
