/*
FILE PATH: api/judicial/cases_filings_test.go

DESCRIPTION:

	Coverage for caseFilingHandler and caseActionHandler — the
	artifact-bearing cases.* handlers. Validation contracts pinned
	here; full happy-path tests through the artifact stack land in
	C4 alongside the artifact handlers themselves.
*/
package judicial

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// caseFilingHandler — validation contracts
// ─────────────────────────────────────────────────────────────────────

func TestCaseFiling_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseFilingRequest{
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog,
		DocumentType:   "motion",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/cases/100/filings", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestCaseFiling_EmptyDestination_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseFilingRequest{
		CaseRootLogDID: testCasesLog,
		DocumentType:   "motion",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/cases/100/filings", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCaseFiling_BadCaseRootSeq_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseFilingRequest{
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog,
		DocumentType:   "motion",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/cases/notanumber/filings", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCaseFiling_MissingCaseLogDID_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseFilingRequest{
		Destination:  testDestination,
		DocumentType: "motion",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/cases/100/filings", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCaseFiling_BadPlaintextBase64_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseFilingRequest{
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog,
		DocumentType:   "motion",
		PlaintextB64:   "not!!base64",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/cases/100/filings", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// caseActionHandler — validation contracts
// ─────────────────────────────────────────────────────────────────────

func TestCaseAction_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseActionRequest{
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog,
		ActionType:     "ruling",
		Description:    "motion granted",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/cases/100/actions", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestCaseAction_EmptyDestination_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseActionRequest{
		CaseRootLogDID: testCasesLog,
		ActionType:     "ruling",
		Description:    "motion granted",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/cases/100/actions", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCaseAction_BadPlaintextBase64_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseActionRequest{
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog,
		ActionType:     "ruling",
		Description:    "motion granted",
		PlaintextB64:   "not!!base64",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/cases/100/actions", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
