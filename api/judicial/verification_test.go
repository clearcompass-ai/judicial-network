/*
FILE PATH: api/judicial/verification_test.go

DESCRIPTION:
    Validation contracts for the read-side verification handlers
    (case-status, enforcement-status, filing-delegation, custody-chain).
*/
package judicial

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// case-status
// ─────────────────────────────────────────────────────────────────────

func TestVerifyCaseStatus_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/verification/case-status?log_did="+testCasesLog+"&seq=1", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyCaseStatus_MissingParams_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/judicial/verification/case-status", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestVerifyCaseStatus_BadSeq_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/verification/case-status?log_did="+testCasesLog+"&seq=notanumber", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// enforcement-status
// ─────────────────────────────────────────────────────────────────────

func TestVerifyEnforcement_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/verification/enforcement-status?log_did="+testCasesLog+"&seq=1", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyEnforcement_MissingParams_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/judicial/verification/enforcement-status", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// filing-delegation
// ─────────────────────────────────────────────────────────────────────

func TestVerifyFilingDelegation_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, verifyFilingDelegationRequest{
		DelegationPointers: []logPositionRef{{LogDID: testCasesLog, Sequence: 1}},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/verification/filing-delegation", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyFilingDelegation_EmptyPointers_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, verifyFilingDelegationRequest{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/verification/filing-delegation", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// custody-chain
// ─────────────────────────────────────────────────────────────────────

func TestVerifyCustodyChain_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/verification/custody-chain?artifact_cid=Qm123&log_did="+testCasesLog, nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyCustodyChain_MissingParams_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/judicial/verification/custody-chain", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestVerifyCustodyChain_UnknownLog_500(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/verification/custody-chain?artifact_cid=Qm123&log_did=did:web:not-registered", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// background-check
// ─────────────────────────────────────────────────────────────────────

func TestVerifyBackgroundCheck_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/verification/background-check?party_did=did:web:party", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyBackgroundCheck_MissingPartyDID_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/verification/background-check", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestVerifyBackgroundCheck_MissingHeader_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/verification/background-check?party_did=did:web:party", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (missing X-Cases-Log-DID)", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// key-attestation — 501 stub
// ─────────────────────────────────────────────────────────────────────

func TestVerifyKeyAttestation_NotImplemented(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/verification/key-attestation", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "C6") {
		t.Errorf("body should mark the C6 carve-out: %s", rec.Body.String())
	}
}

func TestVerifyKeyAttestation_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/verification/key-attestation", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// appeal-chain
// ─────────────────────────────────────────────────────────────────────

func TestVerifyAppealChain_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, verifyAppealChainRequest{Steps: []byte(`[]`)})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/verification/appeal-chain", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyAppealChain_MissingDeps_500(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, verifyAppealChainRequest{Steps: []byte(`[]`)})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/verification/appeal-chain", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (BLSVerifier missing)", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// cross-log-proof
// ─────────────────────────────────────────────────────────────────────

func TestVerifyCrossLogProof_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, crossLogProofRequest{
		Proof: []byte(`{}`), SourceLogDID: testCasesLog,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/verification/cross-log-proof", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyCrossLogProof_MissingFields_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{BLSVerifier: stubBLS{}})
	body := mustJSON(t, crossLogProofRequest{Proof: []byte(`{}`)})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/verification/cross-log-proof", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
