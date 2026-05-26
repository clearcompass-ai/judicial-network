package handlers

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestLedgerSubmitClientFor_FallsBackToDefault pins the chokepoint
// behaviour: when Dependencies.LedgerSubmitClient is nil, the
// package-level defaultLedgerSubmitClient is used. Matches the
// pre-mTLS test posture so existing tests keep passing.
func TestLedgerSubmitClientFor_FallsBackToDefault(t *testing.T) {
	got := ledgerSubmitClientFor(&Dependencies{})
	if got != defaultLedgerSubmitClient {
		t.Fatalf("expected default client when Dependencies.LedgerSubmitClient is nil, got %p", got)
	}
}

// TestLedgerSubmitClientFor_UsesInjectedClient pins the production
// behaviour: when Dependencies.LedgerSubmitClient is non-nil (the
// mTLS-enabled client wired from main.go), every submit-to-ledger
// call routes through it. This is the seam that finally consumes
// the previously-dead LedgerCert / LedgerKey / LedgerCA fields.
func TestLedgerSubmitClientFor_UsesInjectedClient(t *testing.T) {
	custom := &http.Client{}
	got := ledgerSubmitClientFor(&Dependencies{LedgerSubmitClient: custom})
	if got != custom {
		t.Fatalf("expected injected client, got %p (want %p)", got, custom)
	}
}

// TestSubmitToLedger_RoutesThroughInjectedClient is the end-to-end
// pin: when Dependencies.LedgerSubmitClient is set, submitToLedger
// actually dispatches via that client (not the package default).
// Regressions that re-introduce a hard-coded package client will
// break this deterministically.
func TestSubmitToLedger_RoutesThroughInjectedClient(t *testing.T) {
	var custom atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		custom.Add(1)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"position":1}`))
	}))
	defer srv.Close()

	injected := &http.Client{}
	deps := &Dependencies{LedgerEndpoint: srv.URL, LedgerSubmitClient: injected}

	rec := httptest.NewRecorder()
	submitToLedger(rec, deps, []byte("signed"))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rec.Code, rec.Body.String())
	}
	if got := custom.Load(); got != 1 {
		t.Errorf("expected 1 hit via injected client, got %d", got)
	}
}
