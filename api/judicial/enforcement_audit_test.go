/*
FILE PATH: api/judicial/enforcement_audit_test.go

DESCRIPTION:

	Validation contracts for the audit / compliance enforcement
	handlers (expunge, evidence-access, compliance). Full happy-path
	coverage on artifact-bearing routes (expunge, evidence-access)
	lands in C4 alongside the artifact stack fixtures.
*/
package judicial

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// expungeHandler
// ─────────────────────────────────────────────────────────────────────

func TestExpunge_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, expungeRequest{
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog,
		CaseRootSeq:    100,
		ScopeLogDID:    testScopeLog, ScopeSeq: 1,
		Authority: "TCA 40-32-101",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/enforcement/expunge", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestExpunge_EmptyDestination_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, expungeRequest{
		CaseRootLogDID: testCasesLog,
		CaseRootSeq:    100,
		ScopeLogDID:    testScopeLog, ScopeSeq: 1,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/enforcement/expunge", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestExpunge_BadCID_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, expungeRequest{
		Destination: testDestination, CaseRootLogDID: testCasesLog,
		CaseRootSeq: 100, ScopeLogDID: testScopeLog, ScopeSeq: 1,
		Authority:    "TCA 40-32-101",
		ArtifactCIDs: []string{"not-a-valid-cid"},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/enforcement/expunge", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// evidenceAccessHandler — validation contracts
// ─────────────────────────────────────────────────────────────────────

func TestEvidenceAccess_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, evidenceAccessRequest{
		Destination: testDestination,
		ArtifactCID: "Qm123",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/enforcement/evidence-access", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestEvidenceAccess_MissingDestination_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, evidenceAccessRequest{
		ArtifactCID: "Qm123",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/enforcement/evidence-access", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestEvidenceAccess_BadArtifactCID_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, evidenceAccessRequest{
		Destination: testDestination,
		ArtifactCID: "not!!a!!cid",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/enforcement/evidence-access", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// complianceHandler
// ─────────────────────────────────────────────────────────────────────

func TestCompliance_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/enforcement/compliance?log_did="+testCasesLog+"&seq=1", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestCompliance_MissingQueryParams_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/judicial/enforcement/compliance", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCompliance_BadSeq_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/enforcement/compliance?log_did="+testCasesLog+"&seq=notanumber", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
