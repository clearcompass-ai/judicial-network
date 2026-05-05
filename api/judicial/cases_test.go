/*
FILE PATH: api/judicial/cases_test.go

DESCRIPTION:

	Coverage for the simpler cases.* handlers (initiate, amend,
	lookup, transfer division, transfer county stub). The artifact-
	bearing handlers (filings, actions) are tested in
	cases_filings_test.go where the artifact stack lives.
*/
package judicial

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/types"
)

const (
	testJudge       = "did:web:state:tn:davidson:judge-mcclendon"
	testClerk       = "did:web:state:tn:davidson:clerk"
	testDestination = "did:web:state:tn:davidson"
	testCasesLog    = "did:web:state:tn:davidson:cases"
)

// withCaller installs a caller-DID resolver for the duration of the
// test and uninstalls it on cleanup.
func withCaller(t *testing.T, did string) {
	t.Helper()
	SetCallerDIDResolver(func(*http.Request) string { return did })
	t.Cleanup(func() { SetCallerDIDResolver(nil) })
}

func newTestHandler(deps Dependencies) http.Handler {
	return BuildHandler(ServerConfig{Deps: deps})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func decodeBuildResponse(t *testing.T, body []byte) buildResponse {
	t.Helper()
	var resp buildResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode buildResponse: %v body=%s", err, body)
	}
	return resp
}

// ─────────────────────────────────────────────────────────────────────
// caseInitiateHandler
// ─────────────────────────────────────────────────────────────────────

func TestCaseInitiate_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseInitiateRequest{
		Destination: testDestination, DocketNumber: "2026-CV-001", CaseType: "civil",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestCaseInitiate_MalformedJSON_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases",
		bytes.NewReader([]byte("{not json")))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCaseInitiate_EmptyDestination_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseInitiateRequest{DocketNumber: "2026-CV-001", CaseType: "civil"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "destination required") {
		t.Errorf("body should mention destination required: %s", rec.Body.String())
	}
}

func TestCaseInitiate_EmptyDocket_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseInitiateRequest{
		Destination: testDestination, CaseType: "civil",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// TestCaseInitiate_HappyPath pins the load-bearing contract: signer
// is sourced from the auth context, NEVER from the request body.
func TestCaseInitiate_HappyPath(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseInitiateRequest{
		Destination: testDestination, DocketNumber: "2026-CV-001",
		CaseType: "civil", FiledDate: "2026-05-01",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBuildResponse(t, rec.Body.Bytes())
	if resp.Header.Destination != testDestination {
		t.Errorf("Destination drift: %q", resp.Header.Destination)
	}
	if resp.Header.SignerDID != testClerk {
		t.Errorf("SignerDID = %q, want %q (must come from auth context, not body)",
			resp.Header.SignerDID, testClerk)
	}
}

// ─────────────────────────────────────────────────────────────────────
// caseAmendHandler
// ─────────────────────────────────────────────────────────────────────

func TestCaseAmend_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseAmendRequest{
		Destination: testDestination, CaseRootLogDID: testCasesLog,
		AmendmentType: "status_change", NewStatus: "closed",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases/100/amend", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestCaseAmend_BadCaseRootSeq_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseAmendRequest{
		Destination: testDestination, CaseRootLogDID: testCasesLog,
		AmendmentType: "status_change", NewStatus: "closed",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases/notanumber/amend", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCaseAmend_HappyPath(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseAmendRequest{
		Destination: testDestination, CaseRootLogDID: testCasesLog,
		AmendmentType: "status_change", NewStatus: "closed",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases/100/amend", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBuildResponse(t, rec.Body.Bytes())
	if resp.Header.SignerDID != testClerk {
		t.Errorf("SignerDID drift: %q", resp.Header.SignerDID)
	}
}

// ─────────────────────────────────────────────────────────────────────
// caseTransferDivisionHandler
// ─────────────────────────────────────────────────────────────────────

func TestCaseTransferDivision_HappyPath(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseTransferDivisionRequest{
		Destination: testDestination, CaseRootLogDID: testCasesLog,
		TargetDivision: "family", Reason: "consolidation",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/cases/100/transfer/division", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBuildResponse(t, rec.Body.Bytes())
	if resp.Header.SignerDID != testJudge {
		t.Errorf("SignerDID = %q, want %q", resp.Header.SignerDID, testJudge)
	}
}

// ─────────────────────────────────────────────────────────────────────
// caseLookupHandler
// ─────────────────────────────────────────────────────────────────────

func TestCaseLookup_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/judicial/cases/2026-CV-001", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestCaseLookup_UnknownLogDID_500(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{LogQueries: nil})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/judicial/cases/2026-CV-001", nil)
	req.Header.Set("X-Cases-Log-DID", "did:web:not-registered")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// caseTransferCountyHandler — 501 carve-out for C5
// ─────────────────────────────────────────────────────────────────────

func TestCaseTransferCounty_NotImplemented(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/cases/100/transfer/county", bytes.NewReader([]byte("{}")))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "C5") {
		t.Errorf("body should reference future-commit carve-out: %s", rec.Body.String())
	}
}

func TestPathSeq_Variants(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/judicial/cases/42", nil)
	r.SetPathValue("caseRootSeq", "42")
	if got, ok := pathSeq(r, "caseRootSeq"); !ok || got != 42 {
		t.Errorf("numeric path: got %d, %t", got, ok)
	}
	r.SetPathValue("caseRootSeq", "notanumber")
	if _, ok := pathSeq(r, "caseRootSeq"); ok {
		t.Error("non-numeric path should return ok=false")
	}
}

func TestLogPositionRef_RoundTrip(t *testing.T) {
	in := logPositionRef{LogDID: "did:web:cases", Sequence: 12345}
	out := in.toLogPosition()
	if out != (types.LogPosition{LogDID: in.LogDID, Sequence: in.Sequence}) {
		t.Errorf("toLogPosition drift: %+v", out)
	}
}
