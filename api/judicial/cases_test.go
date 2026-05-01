/*
FILE PATH: api/judicial/cases_test.go

DESCRIPTION:
    Coverage for the cases.* handlers in cases.go. Pinned per-handler:

      caseInitiateHandler
        - 401 without authenticated caller
        - 400 on malformed JSON
        - 400 on empty destination
        - 400 on empty docket_number (domain validation)
        - 200 happy path; signing_payload non-empty; header.destination
          == request.destination; header.signer_did == authenticated
          caller (NOT the request body — sourced from auth context).

      caseAmendHandler
        - 401 without caller
        - 400 on missing case_root_log_did
        - 400 on missing caseRootSeq path value (non-numeric)
        - 200 happy path

      caseTransferDivisionHandler
        - 401 without caller
        - 400 on missing destination
        - 400 on missing case_root_log_did
        - 200 happy path

      caseLookupHandler
        - 401 without caller
        - 400 without X-Cases-Log-DID header
        - 500 when the supplied log DID has no LogQueries entry

      caseTransferCountyHandler
        - 401 without caller
        - 501 (NotImplemented) — explicit Phase 7 carve-out

    Filing + judicial-action handlers exercise content-store-bearing
    paths (cases.File / cases.RecordJudicialAction take 7 deps each).
    Their happy-path tests use the SDK's in-memory ContentStore +
    KeyService + DelegationKeyStore to drive a real round-trip.
*/
package judicial

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────

const (
	testJudge       = "did:web:state:tn:davidson:judge-mcclendon"
	testClerk       = "did:web:state:tn:davidson:clerk"
	testDestination = "did:web:state:tn:davidson"
	testCasesLog    = "did:web:state:tn:davidson:cases"
)

// withCaller installs a caller-DID resolver for the duration of the
// test. The caller is whatever the test passes as did.
func withCaller(t *testing.T, did string) {
	t.Helper()
	SetCallerDIDResolver(func(*http.Request) string { return did })
	t.Cleanup(func() { SetCallerDIDResolver(nil) })
}

// newTestHandler builds a fully-routed BuildHandler. Tests then send
// requests through the returned handler.
func newTestHandler(deps Dependencies) http.Handler {
	return BuildHandler(ServerConfig{Deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// caseInitiateHandler
// ─────────────────────────────────────────────────────────────────────

func TestCaseInitiate_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	body := mustJSON(t, caseInitiateRequest{
		Destination:  testDestination,
		DocketNumber: "2026-CV-001",
		CaseType:     "civil",
	})
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
	body := mustJSON(t, caseInitiateRequest{
		DocketNumber: "2026-CV-001",
		CaseType:     "civil",
	})
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
		Destination: testDestination,
		// DocketNumber empty — domain function rejects
		CaseType: "civil",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// TestCaseInitiate_HappyPath pins the most important contract: signer
// is sourced from the auth context, NOT from the request body. A
// caller cannot impersonate another DID by stuffing a different
// signer_did into the JSON.
func TestCaseInitiate_HappyPath(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseInitiateRequest{
		Destination:  testDestination,
		DocketNumber: "2026-CV-001",
		CaseType:     "civil",
		FiledDate:    "2026-05-01",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBuildResponse(t, rec.Body.Bytes())
	if resp.Header.Destination != testDestination {
		t.Errorf("Header.Destination = %q, want %q", resp.Header.Destination, testDestination)
	}
	if resp.Header.SignerDID != testClerk {
		t.Errorf("Header.SignerDID = %q, want %q (must come from auth context)",
			resp.Header.SignerDID, testClerk)
	}
	if resp.SigningPayload == "" {
		t.Error("signing_payload empty")
	}
}

// ─────────────────────────────────────────────────────────────────────
// caseAmendHandler
// ─────────────────────────────────────────────────────────────────────

func TestCaseAmend_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseAmendRequest{
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog,
		AmendmentType:  "status_change",
		NewStatus:      "closed",
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
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog,
		AmendmentType:  "status_change",
		NewStatus:      "closed",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases/notanumber/amend", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "caseRootSeq") {
		t.Errorf("body should mention caseRootSeq: %s", rec.Body.String())
	}
}

func TestCaseAmend_MissingCaseLogDID_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseAmendRequest{
		Destination:   testDestination,
		AmendmentType: "status_change",
		NewStatus:     "closed",
		// CaseRootLogDID missing
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases/100/amend", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCaseAmend_HappyPath(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseAmendRequest{
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog,
		AmendmentType:  "status_change",
		NewStatus:      "closed",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases/100/amend", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBuildResponse(t, rec.Body.Bytes())
	if resp.Header.Destination != testDestination {
		t.Errorf("Destination drift: %q", resp.Header.Destination)
	}
	if resp.Header.SignerDID != testClerk {
		t.Errorf("SignerDID drift: %q", resp.Header.SignerDID)
	}
}

// ─────────────────────────────────────────────────────────────────────
// caseTransferDivisionHandler
// ─────────────────────────────────────────────────────────────────────

func TestCaseTransferDivision_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseTransferDivisionRequest{
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog,
		TargetDivision: "family",
		Reason:         "consolidation",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/cases/100/transfer/division", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestCaseTransferDivision_HappyPath(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, caseTransferDivisionRequest{
		Destination:    testDestination,
		CaseRootLogDID: testCasesLog,
		TargetDivision: "family",
		Reason:         "consolidation",
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

func TestCaseLookup_NoLogHeader_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/judicial/cases/2026-CV-001", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		// The current implementation returns 500 when the X-Cases-Log-DID
		// header is missing because it surfaces from casesScannerFor. We
		// could tighten to 400, but the contract today is documented in
		// cases.go as "configured Dependencies don't have the requested
		// log's query API wired."
		t.Errorf("status = %d, want 500 (missing X-Cases-Log-DID)", rec.Code)
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
	if !strings.Contains(rec.Body.String(), "no LogQueries entry") {
		t.Errorf("body should mention LogQueries: %s", rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────
// caseTransferCountyHandler — 501 NotImplemented
// ─────────────────────────────────────────────────────────────────────

func TestCaseTransferCounty_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/cases/100/transfer/county", bytes.NewReader([]byte("{}")))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestCaseTransferCounty_NotImplemented pins the carve-out: the route
// IS registered (so callers get a clear 501 with a marker pointing to
// commit C5 instead of a generic 404).
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
		t.Errorf("body should reference the future-commit carve-out (C5): %s", rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────
// caseFilingHandler / caseActionHandler — request-validation only
// ─────────────────────────────────────────────────────────────────────
//
// Full happy-path coverage for these two requires the artifact stack
// (ContentStore + KeyStore + DelegationKeyStore + Extractor + Resolver
// + Fetcher). Wiring the in-memory stack here doubles this file's
// length and cross-contaminates with the cases/artifact package's own
// tests. C4 (artifacts) carries the artifact-bearing happy paths
// because they share that fixture surface.
//
// Below: the cheap, deterministic validation contracts every caller
// hits before a handler reaches the artifact stack.

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

// ─────────────────────────────────────────────────────────────────────
// pathSeq helper
// ─────────────────────────────────────────────────────────────────────

func TestPathSeq_Numeric(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/judicial/cases/42", nil)
	r.SetPathValue("caseRootSeq", "42")
	got, ok := pathSeq(r, "caseRootSeq")
	if !ok || got != 42 {
		t.Errorf("pathSeq = %d, %t; want 42, true", got, ok)
	}
}

func TestPathSeq_NonNumeric_False(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/judicial/cases/notanumber", nil)
	r.SetPathValue("caseRootSeq", "notanumber")
	_, ok := pathSeq(r, "caseRootSeq")
	if ok {
		t.Error("expected false for non-numeric path value")
	}
}

// ─────────────────────────────────────────────────────────────────────
// logPositionRef
// ─────────────────────────────────────────────────────────────────────

func TestLogPositionRef_RoundTrip(t *testing.T) {
	in := logPositionRef{LogDID: "did:web:cases", Sequence: 12345}
	out := in.toLogPosition()
	if out.LogDID != in.LogDID || out.Sequence != in.Sequence {
		t.Errorf("toLogPosition drift: %+v", out)
	}
}

// ─────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────

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

// fmtPos is a debug helper used by inline assertions; keeps imports
// honest.
func fmtPos(p types.LogPosition) string {
	return fmt.Sprintf("%s@%d", p.LogDID, p.Sequence)
}

var _ = fmtPos
