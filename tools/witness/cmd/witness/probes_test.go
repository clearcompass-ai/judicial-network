/*
FILE PATH: tools/cmd/witness/probes_test.go

DESCRIPTION:

	Probe surface contract for the witness daemon:
	  1. /healthz always 200 (liveness).
	  2. /readyz 200 when ANY configured ledger is reachable;
	     503 when all are down.
	  3. /metrics serves the Prometheus registry.
	  4. Unknown paths 404 (no /v1/* by design).
*/
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newWitnessProbes(t *testing.T, ledgerOK bool) (*probeHandlers, func()) {
	t.Helper()
	op := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		if ledgerOK {
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, "down", http.StatusServiceUnavailable)
		}
	}))
	cfg := Config{
		Ledgers: map[string]string{"did:web:test": op.URL},
	}
	return newProbeHandlers(cfg), op.Close
}

func hit(h http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	h.ServeHTTP(rec, req)
	return rec
}

func TestWitnessProbes_Healthz_AlwaysOK(t *testing.T) {
	p, cleanup := newWitnessProbes(t, false)
	defer cleanup()
	rec := hit(p.Handler(), http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestWitnessProbes_Readyz_LedgerReachable_200(t *testing.T) {
	p, cleanup := newWitnessProbes(t, true)
	defer cleanup()
	rec := hit(p.Handler(), http.MethodGet, "/readyz")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestWitnessProbes_Readyz_AllLedgersDown_503(t *testing.T) {
	p, cleanup := newWitnessProbes(t, false)
	defer cleanup()
	rec := hit(p.Handler(), http.MethodGet, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestWitnessProbes_Readyz_NoLedgers_503(t *testing.T) {
	p := newProbeHandlers(Config{Ledgers: map[string]string{}})
	rec := hit(p.Handler(), http.MethodGet, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (empty ledgers)", rec.Code)
	}
}

func TestWitnessProbes_Metrics_Reachable(t *testing.T) {
	p, cleanup := newWitnessProbes(t, true)
	defer cleanup()
	// Drive a counter so the registry has something to render.
	p.metrics.Wrap(func() string { return "/test" }, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/test", nil))

	rec := hit(p.Handler(), http.MethodGet, "/metrics")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "jn_http_") {
		t.Errorf("metrics body missing jn_http_*: %s",
			rec.Body.String()[:minInt(len(rec.Body.String()), 200)])
	}
}

func TestWitnessProbes_UnknownPath_404(t *testing.T) {
	p, cleanup := newWitnessProbes(t, true)
	defer cleanup()
	rec := hit(p.Handler(), http.MethodGet, "/v1/judicial/cases")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
