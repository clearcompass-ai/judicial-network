package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// stubSigVerifier is a no-op attestation.SignatureVerifier — enough to get the
// handler past its 503 wiring guard in the error-path tests below. (The crypto
// path itself is covered by verification.CheckCosignatureWithVerifier's tests.)
type stubSigVerifier struct{}

func (stubSigVerifier) Verify(_ context.Context, _ string, _, _ []byte, _ uint16) error { return nil }

func wiredCosigDeps() *Dependencies {
	return &Dependencies{
		SignatureVerifier: stubSigVerifier{},
		Registry:          jurisdiction.NewRegistry(),
	}
}

func cosigRequest(logID, pos string) *http.Request {
	req := httptest.NewRequest("GET", "/v1/verify/cosignature/"+logID+"/"+pos, nil)
	req.SetPathValue("logID", logID)
	req.SetPathValue("pos", pos)
	return req
}

// TestVerifyCosignature_503WhenUnwired pins the wiring guard: the read-side
// crypto cosignature check is unavailable unless BOTH the SignatureVerifier and
// the jurisdiction Registry are wired (it needs the verifier for crypto and the
// registry for the per-destination cosignature policy).
func TestVerifyCosignature_503WhenUnwired(t *testing.T) {
	cases := map[string]*Dependencies{
		"both nil":     {},
		"nil verifier": {Registry: jurisdiction.NewRegistry()},
		"nil registry": {SignatureVerifier: stubSigVerifier{}},
	}
	for name, deps := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			NewVerifyCosignatureHandler(deps).ServeHTTP(w, cosigRequest("test-log", "5"))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("want 503, got %d (%s)", w.Code, w.Body.String())
			}
		})
	}
}

func TestVerifyCosignature_InvalidPosition(t *testing.T) {
	w := httptest.NewRecorder()
	NewVerifyCosignatureHandler(wiredCosigDeps()).ServeHTTP(w, cosigRequest("test-log", "abc"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestVerifyCosignature_UnknownLog(t *testing.T) {
	w := httptest.NewRecorder()
	NewVerifyCosignatureHandler(wiredCosigDeps()).ServeHTTP(w, cosigRequest("nonexistent", "42"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d (%s)", w.Code, w.Body.String())
	}
}
