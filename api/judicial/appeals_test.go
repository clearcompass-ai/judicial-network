/*
FILE PATH: api/judicial/appeals_test.go

DESCRIPTION:
    Validation contracts for the appellate handlers. Cross-log
    handlers (file appeal, mandate reverse, transfer record) are
    501 stubs until C5; this file pins their auth + 501 wire shape.
*/
package judicial

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testAppealLog   = "did:web:state:tn:coa:cases"
	testCOADest     = "did:web:state:tn:coa"
)

// ─────────────────────────────────────────────────────────────────────
// appealDecisionHandler
// ─────────────────────────────────────────────────────────────────────

func TestAppealDecision_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, appealDecisionRequest{
		Destination: testCOADest, AppealCaseLogDID: testAppealLog,
		Outcome: "affirm",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/appeals/decisions", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAppealDecision_EmptyDestination_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, appealDecisionRequest{
		AppealCaseLogDID: testAppealLog,
		Outcome:          "affirm",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/appeals/decisions", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAppealDecision_BadOpinionBase64_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, appealDecisionRequest{
		Destination: testCOADest, AppealCaseLogDID: testAppealLog,
		Outcome: "affirm", OpinionPlaintextB64: "not!!base64",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/appeals/decisions", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// appealMandateAffirmHandler
// ─────────────────────────────────────────────────────────────────────

func TestMandateAffirm_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, appealMandateAffirmRequest{
		Destination:           testDestination,
		LowerCourtCaseLogDID:  testCasesLog,
		LowerCourtCaseSeq:     100,
		LowerCourtScopeLogDID: testDestination,
		LowerCourtScopeSeq:    1,
		AppellateDecisionLogDID: testAppealLog,
		AppellateDecisionSeq:    99,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/appeals/mandates/affirm", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMandateAffirm_HappyPath(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, appealMandateAffirmRequest{
		Destination:           testDestination,
		LowerCourtCaseLogDID:  testCasesLog,
		LowerCourtCaseSeq:     100,
		LowerCourtScopeLogDID: testDestination,
		LowerCourtScopeSeq:    1,
		AppellateDecisionLogDID: testAppealLog,
		AppellateDecisionSeq:    99,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/appeals/mandates/affirm", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBuildResponse(t, rec.Body.Bytes())
	if resp.Header.SignerDID != testJudge {
		t.Errorf("SignerDID = %q, want %q", resp.Header.SignerDID, testJudge)
	}
	if resp.Header.Destination != testDestination {
		t.Errorf("Destination drift: %q", resp.Header.Destination)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Cross-log stubs (501 carve-outs for C5)
// ─────────────────────────────────────────────────────────────────────

func TestAppealInitiate_NotImplemented(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/appeals/initiations", bytes.NewReader([]byte("{}")))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "C5") {
		t.Errorf("body should reference C5 carve-out: %s", rec.Body.String())
	}
}

func TestMandateReverse_NotImplemented(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/appeals/mandates/reverse", bytes.NewReader([]byte("{}")))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

func TestRecordTransfer_NotImplemented(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/appeals/records/transfer", bytes.NewReader([]byte("{}")))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

// All cross-log stubs require auth — pinned here so adding a new stub
// later doesn't accidentally drop the 401 layer.
func TestCrossLogStubs_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	for _, path := range []string{
		"/v1/judicial/appeals/initiations",
		"/v1/judicial/appeals/mandates/reverse",
		"/v1/judicial/appeals/records/transfer",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte("{}")))
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", path, rec.Code)
		}
	}
}
