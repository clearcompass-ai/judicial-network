/*
FILE PATH:
    tools/courts/courts_test.go

DESCRIPTION:
    Unit tests for court tools HTTP handlers. Uses a mock exchange server
    that accepts build-sign-submit requests and returns synthetic positions.
    No Postgres required — read endpoints return 503 (correct degraded behavior).

KEY ARCHITECTURAL DECISIONS:
    - Mock exchange via httptest.NewServer: tests the full HTTP round-trip
      from handler → ExchangeClient → mock server → response parsing.
    - No Postgres: DB is nil. Read endpoints correctly return 503.
    - Auth tested via X-Signer-DID header (sandbox mode).
*/
package courts

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// -------------------------------------------------------------------------
// 1) Mock exchange
// -------------------------------------------------------------------------

func mockExchange(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var seq atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/build-sign-submit" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		pos := seq.Add(1)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"position":       pos,
			"canonical_hash": "sha256:test",
		})
	}))

	t.Cleanup(srv.Close)
	return srv, &seq
}

func testServer(t *testing.T) (*Server, *atomic.Int64) {
	t.Helper()
	mock, seq := mockExchange(t)
	cfg := common.DefaultConfig()
	cfg.CasesLogDID = "did:web:test:cases"
	cfg.OfficersLogDID = "did:web:test:officers"
	cfg.CourtDID = "did:web:test"

	exchange := common.NewExchangeClient(mock.URL)
	verify := common.NewVerifyClient("http://localhost:0") // not used in write tests
	s := NewServer(cfg, exchange, verify, nil)              // nil DB
	return s, seq
}

func doRequest(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
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
	req.Header.Set("X-Signer-DID", "did:web:test:judge")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// -------------------------------------------------------------------------
// 2) Cases: create
// -------------------------------------------------------------------------

func TestCreateCase_Success(t *testing.T) {
	s, _ := testServer(t)
	w := doRequest(t, s.Handler(), "POST", "/v1/cases", map[string]any{
		"docket_number": "2027-CR-001",
		"case_type":     "criminal",
	})

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["docket_number"] != "2027-CR-001" {
		t.Errorf("docket_number = %v", resp["docket_number"])
	}
	if resp["log_position"] == nil {
		t.Error("log_position must be set")
	}
}

func TestCreateCase_MissingFields(t *testing.T) {
	s, _ := testServer(t)
	w := doRequest(t, s.Handler(), "POST", "/v1/cases", map[string]any{})

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreateCase_NoAuth(t *testing.T) {
	s, _ := testServer(t)
	req := httptest.NewRequest("POST", "/v1/cases", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	// No X-Signer-DID header.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// -------------------------------------------------------------------------
// 3) Cases: read (DB nil → 503)
// -------------------------------------------------------------------------

func TestGetCase_NoDB_Returns503(t *testing.T) {
	s, _ := testServer(t)
	w := doRequest(t, s.Handler(), "GET", "/v1/cases/2027-CR-001", nil)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (no DB)", w.Code)
	}
}

func TestGetTimeline_NoDB_Returns503(t *testing.T) {
	s, _ := testServer(t)
	w := doRequest(t, s.Handler(), "GET", "/v1/cases/2027-CR-001/timeline", nil)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

// -------------------------------------------------------------------------
// 4) Officers: create delegation
// -------------------------------------------------------------------------

func TestCreateOfficer_Success(t *testing.T) {
	s, _ := testServer(t)
	w := doRequest(t, s.Handler(), "POST", "/v1/officers", map[string]any{
		"delegate_did": "did:web:test:judge-smith",
		"role":         "judge",
		"division":     "criminal",
		"scope_limit":  []string{"order", "judgment"},
	})

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body: %s", w.Code, w.Body.String())
	}
}

func TestCreateOfficer_MissingFields(t *testing.T) {
	s, _ := testServer(t)
	w := doRequest(t, s.Handler(), "POST", "/v1/officers", map[string]any{})

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// -------------------------------------------------------------------------
// 5) Docket: publish
// -------------------------------------------------------------------------

func TestPublishDocket_Success(t *testing.T) {
	s, _ := testServer(t)
	w := doRequest(t, s.Handler(), "POST", "/v1/docket", map[string]any{
		"date": "2027-04-17",
		"assignments": []map[string]any{
			{"judge_did": "did:web:test:judge", "courtrooms": []string{"4A"}},
		},
	})

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body: %s", w.Code, w.Body.String())
	}
}

func TestPublishDocket_NoAssignments(t *testing.T) {
	s, _ := testServer(t)
	w := doRequest(t, s.Handler(), "POST", "/v1/docket", map[string]any{
		"date":        "2027-04-17",
		"assignments": []map[string]any{},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// -------------------------------------------------------------------------
// 6) Health
// -------------------------------------------------------------------------

func TestHealthz(t *testing.T) {
	s, _ := testServer(t)
	w := doRequest(t, s.Handler(), "GET", "/healthz", nil)

	if w.Code != http.StatusOK {
		t.Errorf("healthz = %d, want 200", w.Code)
	}
}

// -------------------------------------------------------------------------
// 7) Exchange sequence increments
// -------------------------------------------------------------------------

func TestMultipleSubmissions_SequenceIncrements(t *testing.T) {
	s, _ := testServer(t)

	for i := 0; i < 3; i++ {
		w := doRequest(t, s.Handler(), "POST", "/v1/cases", map[string]any{
			"docket_number": "2027-CR-00" + string(rune('1'+i)),
			"case_type":     "criminal",
		})
		if w.Code != http.StatusCreated {
			t.Fatalf("iteration %d: status = %d", i, w.Code)
		}

		var resp map[string]any
		json.NewDecoder(w.Body).Decode(&resp)
		pos := resp["log_position"].(float64)
		if pos != float64(i+1) {
			t.Errorf("iteration %d: position = %v, want %d", i, pos, i+1)
		}
	}
}
