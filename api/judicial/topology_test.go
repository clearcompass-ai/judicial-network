/*
FILE PATH: api/judicial/topology_test.go

DESCRIPTION:

	Validation contracts for the wired topology handlers (Priority 2):

	  POST /v1/judicial/topology/publish-anchor
	  GET  /v1/judicial/topology/anchor-chain

	Pinned:
	  - 401 on no caller (auth gate runs first)
	  - 503 when Dependencies.TreeHeadClient is nil — the dep is
	    configured via witness operational config; an unconfigured
	    binary surfaces 503 with the reason
	  - 503 on anchor-chain when Hierarchy is nil
	  - 400 on missing required body / query fields when configured
*/
package judicial

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/judicial-network/topology"
)

// stubTreeHeadClient returns a real *witness.TreeHeadClient pointed at
// an empty StaticEndpoints. Production tests would point it at an
// httptest stub, but for these contract tests we just need a non-nil
// value so the 503 unconfigured-gate doesn't trip.
func stubTreeHeadClient() *witness.TreeHeadClient {
	endpoints := &witness.StaticEndpoints{
		Ledgers:   map[string]string{},
		Witnesses: map[string][]string{},
	}
	return witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())
}

// ─────────────────────────────────────────────────────────────────────
// publish-anchor
// ─────────────────────────────────────────────────────────────────────

func TestTopologyPublishAnchor_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/topology/publish-anchor",
		bytes.NewReader([]byte(`{"destination":"x","source_log_did":"y"}`)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestTopologyPublishAnchor_NoTreeHeadClient_503(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/topology/publish-anchor",
		bytes.NewReader([]byte(`{"destination":"x","source_log_did":"y"}`)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "TreeHeadClient") {
		t.Errorf("body should mention TreeHeadClient; got %q", rec.Body.String())
	}
}

func TestTopologyPublishAnchor_MissingFields_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{TreeHeadClient: stubTreeHeadClient()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/topology/publish-anchor",
		bytes.NewReader([]byte(`{}`)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// anchor-chain
// ─────────────────────────────────────────────────────────────────────

func TestTopologyAnchorChain_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/topology/anchor-chain?court_did=did:web:x", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestTopologyAnchorChain_NoTreeHeadClient_503(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/topology/anchor-chain?court_did=did:web:x", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "TreeHeadClient") {
		t.Errorf("body should mention TreeHeadClient; got %q", rec.Body.String())
	}
}

func TestTopologyAnchorChain_NoHierarchy_503(t *testing.T) {
	withCaller(t, testJudge)
	// TreeHeadClient set but Hierarchy still nil → second 503.
	h := newTestHandler(Dependencies{TreeHeadClient: stubTreeHeadClient()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/topology/anchor-chain?court_did=did:web:x", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Hierarchy") {
		t.Errorf("body should mention Hierarchy; got %q", rec.Body.String())
	}
}

func TestTopologyAnchorChain_MissingCourtDID_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{
		TreeHeadClient: stubTreeHeadClient(),
		Hierarchy:      topology.NewHierarchy(),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/topology/anchor-chain", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestTopologyAnchorChain_HappyPath_200(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{
		TreeHeadClient: stubTreeHeadClient(),
		Hierarchy:      topology.NewHierarchy(),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/topology/anchor-chain?court_did=did:web:state:tn:davidson",
		nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────
// monitoring/anchor-freshness
// ─────────────────────────────────────────────────────────────────────

func TestMonAnchorFreshness_NoTreeHeadClient_503(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/monitoring/anchor-freshness?local_log_did=x&parent_log_did=y&ledger_signer_did=z",
		nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "TreeHeadClient") {
		t.Errorf("body should mention TreeHeadClient; got %q", rec.Body.String())
	}
}

func TestMonAnchorFreshness_MissingParams_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{TreeHeadClient: stubTreeHeadClient()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/judicial/monitoring/anchor-freshness", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
