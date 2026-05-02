/*
FILE PATH: api/judicial/delegation_topology_test.go

DESCRIPTION:
    Validation contracts for the delegation + topology stub
    handlers. Each route is auth-gated (401 without a caller) and
    returns 501 with the operational reasoning attached when called
    by an authenticated user.
*/
package judicial

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// table-driven: each entry is (route, method) — the contract is
// uniform across the five stubs.
var stubRoutes = []struct {
	method string
	path   string
	hint   string // substring expected in 501 body
}{
	{http.MethodPost, "/v1/judicial/delegation/issue", "BuildContext"},
	{http.MethodPost, "/v1/judicial/delegation/revoke", "BuildContext"},
	{http.MethodPost, "/v1/judicial/delegation/succeed", "BuildContext"},
	{http.MethodPost, "/v1/judicial/topology/publish-anchor", "TreeHeadClient"},
	{http.MethodGet, "/v1/judicial/topology/anchor-chain", "TreeHeadClient"},
}

func TestDelegationTopologyStubs_NoCaller_401(t *testing.T) {
	for _, tc := range stubRoutes {
		t.Run(tc.path, func(t *testing.T) {
			h := newTestHandler(Dependencies{})
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
		})
	}
}

func TestDelegationTopologyStubs_NotImplemented_WithReason(t *testing.T) {
	for _, tc := range stubRoutes {
		t.Run(tc.path, func(t *testing.T) {
			withCaller(t, testJudge)
			h := newTestHandler(Dependencies{})
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotImplemented {
				t.Errorf("status = %d, want 501", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tc.hint) {
				t.Errorf("body should mention %q (operational reasoning); got %s",
					tc.hint, rec.Body.String())
			}
		})
	}
}
