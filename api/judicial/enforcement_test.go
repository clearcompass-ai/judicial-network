/*
FILE PATH: api/judicial/enforcement_test.go

DESCRIPTION:
    Validation contracts for sealing, unsealing, cosignature,
    sealing-status. Expungement / evidence-access / compliance
    tests live in enforcement_audit_test.go.
*/
package judicial

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testScopeLog = "did:web:state:tn:davidson:scope"

// ─────────────────────────────────────────────────────────────────────
// sealHandler
// ─────────────────────────────────────────────────────────────────────

func TestSeal_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, sealRequest{
		Destination: testDestination, CaseRootLogDID: testCasesLog,
		CaseRootSeq: 100, ScopeLogDID: testScopeLog, ScopeSeq: 1,
		OrderType: "seal", Authority: "TCA 10-7-503", Reason: "ongoing investigation",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/enforcement/seal", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestSeal_EmptyDestination_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, sealRequest{
		CaseRootLogDID: testCasesLog,
		CaseRootSeq:    100, ScopeLogDID: testScopeLog, ScopeSeq: 1,
		OrderType: "seal",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/enforcement/seal", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestSeal_HappyPath(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, sealRequest{
		Destination: testDestination, CaseRootLogDID: testCasesLog,
		CaseRootSeq: 100, ScopeLogDID: testScopeLog, ScopeSeq: 1,
		OrderType: "seal", Authority: "TCA 10-7-503",
		Reason: "ongoing investigation",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/enforcement/seal", bytes.NewReader(body))
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
// unsealHandler
// ─────────────────────────────────────────────────────────────────────

func TestUnseal_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, unsealRequest{
		Destination: testDestination, CaseRootLogDID: testCasesLog,
		CaseRootSeq: 100, ScopeLogDID: testScopeLog, ScopeSeq: 1,
		Reason: "investigation closed",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/enforcement/unseal", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestUnseal_HappyPath(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, unsealRequest{
		Destination: testDestination, CaseRootLogDID: testCasesLog,
		CaseRootSeq: 100, ScopeLogDID: testScopeLog, ScopeSeq: 1,
		Reason: "investigation closed",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/enforcement/unseal", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────
// unsealCosignatureHandler
// ─────────────────────────────────────────────────────────────────────

func TestUnsealCosignature_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, unsealCosignatureRequest{
		Destination:     testDestination,
		UnsealingLogDID: testCasesLog,
		UnsealingSeq:    101,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/enforcement/unseal/cosignature", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestUnsealCosignature_HappyPath(t *testing.T) {
	const cosignerDID = "did:web:state:tn:davidson:judge-grayson"
	withCaller(t, cosignerDID)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, unsealCosignatureRequest{
		Destination:     testDestination,
		UnsealingLogDID: testCasesLog,
		UnsealingSeq:    101,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/enforcement/unseal/cosignature", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBuildResponse(t, rec.Body.Bytes())
	if resp.Header.SignerDID != cosignerDID {
		t.Errorf("SignerDID = %q, want %q", resp.Header.SignerDID, cosignerDID)
	}
}

func TestUnsealCosignature_MissingFields_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, unsealCosignatureRequest{Destination: testDestination})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/enforcement/unseal/cosignature", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// sealingStatusHandler
// ─────────────────────────────────────────────────────────────────────

func TestSealingStatus_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/enforcement/sealing-status?log_did="+testCasesLog+"&seq=1", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestSealingStatus_MissingQueryParams_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/judicial/enforcement/sealing-status", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestSealingStatus_BadSeq_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/enforcement/sealing-status?log_did="+testCasesLog+"&seq=notanumber", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
