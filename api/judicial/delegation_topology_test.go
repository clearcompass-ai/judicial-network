/*
FILE PATH: api/judicial/delegation_topology_test.go

DESCRIPTION:

	Validation contracts for the delegation 501 stubs + the
	Priority-2 topology wiring.

	Delegation routes (3) remain 501 because they need a process-
	scoped BuildContext. Topology routes (2) are now wired with
	Dependencies.TreeHeadClient (+ Hierarchy for anchor-chain) and
	surface 503 when those deps are nil instead of 501.
*/
package judicial

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubRoutes covers the still-501 delegation routes only. Topology
// routes have moved to topology_test.go since their contract is
// now 503-when-unconfigured rather than 501-by-design.
var stubRoutes = []struct {
	method string
	path   string
	hint   string
}{
	{http.MethodPost, "/v1/judicial/delegation/issue", "BuildContext"},
	{http.MethodPost, "/v1/judicial/delegation/revoke", "BuildContext"},
	{http.MethodPost, "/v1/judicial/delegation/succeed", "BuildContext"},
}

func TestDelegationStubs_NoCaller_401(t *testing.T) {
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

func TestDelegationStubs_NotImplemented_WithReason(t *testing.T) {
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
				t.Errorf("body should mention %q; got %s",
					tc.hint, rec.Body.String())
			}
		})
	}
}
