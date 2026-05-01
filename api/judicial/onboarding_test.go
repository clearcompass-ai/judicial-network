/*
FILE PATH: api/judicial/onboarding_test.go

DESCRIPTION:
    Validation contracts for onboarding handlers. Schema adoption
    has happy-path; the three bootstrap-script-driven endpoints are
    501 stubs (validated for auth + status).
*/
package judicial

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSchemaAdopt_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, schemaAdoptRequest{
		Destination: testDestination, SourceSchemaLogDID: testCasesLog, SourceSchemaSeq: 1,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/onboarding/schema-adoption", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestSchemaAdopt_EmptyDestination_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, schemaAdoptRequest{
		SourceSchemaLogDID: testCasesLog, SourceSchemaSeq: 1,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/onboarding/schema-adoption", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestSchemaAdopt_MissingSourceLog_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, schemaAdoptRequest{Destination: testDestination})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/onboarding/schema-adoption", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 501 stubs
// ─────────────────────────────────────────────────────────────────────

func TestCourtProvision_NotImplemented(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/onboarding/court-provision", bytes.NewReader([]byte("{}")))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "bootstrap-script-driven") {
		t.Errorf("body should mention bootstrap-script: %s", rec.Body.String())
	}
}

func TestAnchorRegistration_NotImplemented(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/onboarding/anchor-registration", bytes.NewReader([]byte("{}")))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

func TestMigrateRecords_NotImplemented(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/onboarding/migrate-records", bytes.NewReader([]byte("{}")))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

// All 501 stubs require auth — pinned so future regressions don't drop
// the layer accidentally.
func TestOnboardingStubs_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	for _, path := range []string{
		"/v1/judicial/onboarding/court-provision",
		"/v1/judicial/onboarding/anchor-registration",
		"/v1/judicial/onboarding/migrate-records",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte("{}")))
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", path, rec.Code)
		}
	}
}
