/*
FILE PATH: api/judicial/verification_test.go

DESCRIPTION:

	Validation contracts for the read-side verification handlers
	(case-status, enforcement-status, filing-delegation, custody-chain).
*/
package judicial

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/types"
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

// TestVerifyCrossLogProof_CallerSuppliedNetworkID exercises the
// cross-trust-boundary path where the caller hands the API a
// completely external source log (witness keys, quorum, AND
// network_id). Dependencies.WitnessNetwork is empty (the
// production buildJudicialDeps default); without the
// source_network_id_hex request override the handler would
// 400-out before any verification could run.
//
// This pins the regression that surfaced in code review: making
// WitnessNetwork required at lookup time blocked the documented
// caller-supplied path. The fix routes the handler through
// resolveSourceNetworkID, which prefers the request override and
// falls back to the deps map only when present.
func TestVerifyCrossLogProof_CallerSuppliedNetworkID(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{
		BLSVerifier:    stubBLS{},
		WitnessNetwork: map[string]cosign.NetworkID{}, // empty deps map — caller MUST supply
	})
	// Build a minimum proof so we get past the proof-shape gate.
	// The verifier will reject this proof (it's all zeros) but we
	// only care that we got to the verifier, not before.
	proofJSON := mustJSON(t, types.CrossLogProof{})
	hexNID := strings.Repeat("ab", 32) // 64-char lowercase hex, non-zero
	body := mustJSON(t, crossLogProofRequest{
		Proof:                proofJSON,
		SourceLogDID:         "did:web:external:trust:boundary",
		SourceWitnessKeysB64: []string{base64.StdEncoding.EncodeToString(make([]byte, 96))},
		SourceWitnessQuorum:  1,
		SourceNetworkIDHex:   hexNID,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/verification/cross-log-proof", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	// We expect the handler to PROCEED past key/quorum/network
	// validation and reach VerifyCrossLogProof, which will return
	// `verified: false` for this synthetic proof. 200 OK with a
	// `verified` field in the body is the success-path signal that
	// the gate did NOT 400 us out before crypto.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (handler must reach verifier when "+
			"caller supplies all source-side material); body = %s",
			rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := resp["verified"]; !ok {
		t.Errorf("response missing `verified` field; got %v", resp)
	}
}

// TestVerifyCrossLogProof_RejectsMalformedNetworkID rejects a
// SourceNetworkIDHex that isn't 64 lowercase hex chars. Pins the
// resolveSourceNetworkID input-validation contract.
func TestVerifyCrossLogProof_RejectsMalformedNetworkID(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{BLSVerifier: stubBLS{}})
	body := mustJSON(t, crossLogProofRequest{
		Proof:              []byte(`{}`),
		SourceLogDID:       "did:web:external",
		SourceNetworkIDHex: "not-hex",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/verification/cross-log-proof", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
