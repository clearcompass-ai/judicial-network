/*
FILE PATH: api/judicial/parties_query_test.go

DESCRIPTION:
    Validation contracts for the read-side party queries (list +
    find-by-binding-id). Both require X-Parties-Log-DID + signer_did
    query param.
*/
package judicial

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// partyBindingListHandler
// ─────────────────────────────────────────────────────────────────────

func TestPartyBindingList_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/parties/bindings?signer_did="+testClerk, nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestPartyBindingList_MissingSignerDID_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/judicial/parties/bindings", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestPartyBindingList_MissingHeader_500(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/parties/bindings?signer_did="+testClerk, nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (missing X-Parties-Log-DID)", rec.Code)
	}
}

func TestPartyBindingList_UnknownLog_500(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{LogQueries: nil})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/parties/bindings?signer_did="+testClerk, nil)
	req.Header.Set("X-Parties-Log-DID", "did:web:not-registered")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// partyBindingFindHandler
// ─────────────────────────────────────────────────────────────────────

func TestPartyBindingFind_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/parties/bindings/by-id/p-001?signer_did="+testClerk, nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestPartyBindingFind_MissingSignerDID_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/parties/bindings/by-id/p-001", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestPartyBindingFind_UnknownLog_500(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{LogQueries: nil})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/parties/bindings/by-id/p-001?signer_did="+testClerk, nil)
	req.Header.Set("X-Parties-Log-DID", "did:web:not-registered")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}
