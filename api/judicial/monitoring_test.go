/*
FILE PATH: api/judicial/monitoring_test.go

DESCRIPTION:
    Validation contracts for monitoring handlers (blob-availability,
    delegation-health, anchor-freshness stub).
*/
package judicial

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/storage"

	"github.com/clearcompass-ai/judicial-network/monitoring"
)

// stubBLS satisfies cosign.BLSAggregateVerifier for tests that need a
// non-nil verifier on Dependencies.
type stubBLS struct{}

func (stubBLS) VerifyBLSAggregate(_ []byte, _ []byte, sigBytes [][]byte, _ [][]byte) ([]bool, error) {
	out := make([]bool, len(sigBytes))
	for i := range out {
		out[i] = true
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────
// blob-availability
// ─────────────────────────────────────────────────────────────────────

func TestMonBlobAvail_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, monBlobAvailRequest{Backend: "gcs"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/monitoring/blob-availability", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMonBlobAvail_NoContentStore_500(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, monBlobAvailRequest{Backend: "gcs"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/monitoring/blob-availability", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestMonBlobAvail_BadCID_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{ContentStore: stubContent{}})
	body := mustJSON(t, monBlobAvailRequest{
		Backend: "gcs", ExpectedPresent: []string{"not!!cid"},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/monitoring/blob-availability", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// delegation-health
// ─────────────────────────────────────────────────────────────────────

func TestMonDelegationHealth_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, monDelegationHealthRequest{
		LocalLogDID: testCasesLog, OfficersLogDID: testCasesLog,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/monitoring/delegation-health", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMonDelegationHealth_MissingFields_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, monDelegationHealthRequest{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/monitoring/delegation-health", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestMonDelegationHealth_UnknownLog_500(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, monDelegationHealthRequest{
		LocalLogDID: "did:web:not-registered", OfficersLogDID: testCasesLog,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/monitoring/delegation-health", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// anchor-freshness — wired in Priority 2 (see topology_test.go for
// the wired-path 503/400 contracts). Auth gate test stays here.
// ─────────────────────────────────────────────────────────────────────

func TestMonAnchorFreshness_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/monitoring/anchor-freshness", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// stubContent satisfies storage.ContentStore for tests that just
// need a non-nil store reference.
type stubContent struct{}

func (stubContent) Push(_ storage.CID, _ []byte) error  { return nil }
func (stubContent) Fetch(_ storage.CID) ([]byte, error) { return nil, nil }
func (stubContent) Pin(_ storage.CID) error             { return nil }
func (stubContent) Exists(_ storage.CID) (bool, error)  { return false, nil }
func (stubContent) Delete(_ storage.CID) error          { return nil }

// silence unused-import warnings if monitoring is referenced only in
// fixtures.
var _ = monitoring.MonitorResult{}
