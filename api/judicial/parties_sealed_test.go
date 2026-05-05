/*
FILE PATH: api/judicial/parties_sealed_test.go

DESCRIPTION:

	Validation contracts for the sealed-binding handler. The
	artifact-bearing happy path lands in C4 alongside the artifact
	stack fixtures.
*/
package judicial

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPartySealed_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, partyBindingSealedRequest{
		Destination: testDestination,
		VendorDID:   "did:web:vendor:plaintiff",
		RealDID:     "did:web:real:plaintiff",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/parties/bindings/sealed", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestPartySealed_MissingFields_400(t *testing.T) {
	withCaller(t, testClerk)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, partyBindingSealedRequest{
		Destination: testDestination,
		// VendorDID + RealDID missing
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/parties/bindings/sealed", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
