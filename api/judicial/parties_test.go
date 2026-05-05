/*
FILE PATH: api/judicial/parties_test.go

DESCRIPTION:

	Validation contracts for partyBindingCreate, partyBindingUpdate,
	partyCaseLink. Sealed-binding tests live in parties_sealed_test.go;
	query tests live in parties_query_test.go.
*/
package judicial

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testPartiesLog = "did:web:state:tn:davidson:parties"

// ─────────────────────────────────────────────────────────────────────
// partyBindingCreateHandler
// ─────────────────────────────────────────────────────────────────────

func TestPartyBindingCreate_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, partyBindingCreateRequest{
		Destination: testDestination, BindingID: "p-001",
		PartyClass: "plaintiff", CaseRef: "2026-CV-001",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/parties/bindings", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestPartyBindingCreate_EmptyDestination_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, partyBindingCreateRequest{
		BindingID: "p-001", PartyClass: "plaintiff", CaseRef: "2026-CV-001",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/parties/bindings", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestPartyBindingCreate_HappyPath(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, partyBindingCreateRequest{
		Destination: testDestination, BindingID: "p-001",
		PartyClass: "plaintiff", PartyName: "ACME Industries",
		CaseRef: "2026-CV-001",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/parties/bindings", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPartyBindingCreate_EmptyBindingID_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, partyBindingCreateRequest{
		Destination: testDestination,
		PartyClass:  "plaintiff", CaseRef: "2026-CV-001",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/parties/bindings", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// partyBindingUpdateHandler
// ─────────────────────────────────────────────────────────────────────

func TestPartyBindingUpdate_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, partyBindingUpdateRequest{
		Destination: testDestination, BindingLogDID: testPartiesLog, NewStatus: "withdrawn",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/judicial/parties/bindings/100/status", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestPartyBindingUpdate_BadSeq_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, partyBindingUpdateRequest{
		Destination: testDestination, BindingLogDID: testPartiesLog, NewStatus: "withdrawn",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/judicial/parties/bindings/notanumber/status", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestPartyBindingUpdate_HappyPath(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, partyBindingUpdateRequest{
		Destination: testDestination, BindingLogDID: testPartiesLog, NewStatus: "withdrawn",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/judicial/parties/bindings/100/status", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBuildResponse(t, rec.Body.Bytes())
	if resp.Header.SignerDID != testClerk {
		t.Errorf("SignerDID = %q, want %q", resp.Header.SignerDID, testClerk)
	}
}

// ─────────────────────────────────────────────────────────────────────
// partyCaseLinkHandler
// ─────────────────────────────────────────────────────────────────────

func TestPartyCaseLink_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, partyCaseLinkRequest{
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog, CaseRootSeq: 100,
		BindingLogDID: testPartiesLog, BindingSeq: 1,
		BindingID:     "p-001",
		PartiesLogDID: testPartiesLog,
		PartyClass:    "plaintiff",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/parties/case-links", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestPartyCaseLink_HappyPath(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, partyCaseLinkRequest{
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog, CaseRootSeq: 100,
		BindingLogDID: testPartiesLog, BindingSeq: 1,
		BindingID:     "p-001",
		PartiesLogDID: testPartiesLog,
		PartyClass:    "plaintiff",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/parties/case-links", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPartyCaseLink_MissingPartiesLog_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, partyCaseLinkRequest{
		Destination: testDestination,
		BindingID:   "p-001", PartyClass: "plaintiff",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/parties/case-links", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
