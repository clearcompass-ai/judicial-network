/*
FILE PATH: tools/cmd/aggregator/probes_test.go

DESCRIPTION:

	Pins the aggregator binary's probe HTTP surface:
	  1. /healthz returns 200 unconditionally (liveness).
	  2. /readyz returns 200 when both DB ping + ledger /healthz
	     succeed; 503 when either fails (readiness).
	  3. /metrics serves the Prometheus registry.
	  4. Unknown paths return 404 — the aggregator has no
	     /v1/* routes by design.
*/
package main

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	common "github.com/baseproof/tooling/libs/clitools"
)

// stubDB satisfies dbProber. errOnPing controls whether the
// readyz check sees a healthy DB.
type stubDB struct{ errOnPing error }

func (s stubDB) PingContext(_ context.Context) error { return s.errOnPing }

func newProbes(t *testing.T, dbErr error, ledgerOK bool) (*probeHandlers, func()) {
	t.Helper()
	op := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		if !ledgerOK {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	p := newProbeHandlers(stubDB{errOnPing: dbErr}, op.URL, nil) // plain-http test server → bare client
	return p, op.Close
}

func hit(h http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	h.ServeHTTP(rec, req)
	return rec
}

// ─────────────────────────────────────────────────────────────────────
// /healthz
// ─────────────────────────────────────────────────────────────────────

func TestProbes_Healthz_AlwaysOK(t *testing.T) {
	p, cleanup := newProbes(t, errors.New("db down"), false)
	defer cleanup()
	rec := hit(p.Handler(), http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (liveness ignores upstream health)", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want ok", rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────
// /readyz
// ─────────────────────────────────────────────────────────────────────

func TestProbes_Readyz_HappyPath(t *testing.T) {
	p, cleanup := newProbes(t, nil, true)
	defer cleanup()
	rec := hit(p.Handler(), http.MethodGet, "/readyz")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestProbes_Readyz_DBDown_503(t *testing.T) {
	p, cleanup := newProbes(t, errors.New("conn refused"), true)
	defer cleanup()
	rec := hit(p.Handler(), http.MethodGet, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "database unreachable") {
		t.Errorf("body should mention database; got %q", rec.Body.String())
	}
}

func TestProbes_Readyz_LedgerDown_503(t *testing.T) {
	p, cleanup := newProbes(t, nil, false)
	defer cleanup()
	rec := hit(p.Handler(), http.MethodGet, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ledger") {
		t.Errorf("body should mention ledger; got %q", rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────
// /metrics
// ─────────────────────────────────────────────────────────────────────

func TestProbes_Metrics_Reachable(t *testing.T) {
	p, cleanup := newProbes(t, nil, true)
	defer cleanup()
	rec := hit(p.Handler(), http.MethodGet, "/metrics")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	// Empty registry returns empty body — that's expected; we
	// just confirm the endpoint is mounted and the registry is
	// reachable. Drive a counter increment to put something in
	// the body.
	p.metrics.Wrap(func() string { return "/test" }, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/test", nil))

	rec = hit(p.Handler(), http.MethodGet, "/metrics")
	if !strings.Contains(rec.Body.String(), "jn_http_") {
		t.Errorf("metrics body missing jn_http_*: %s",
			rec.Body.String()[:minLen(len(rec.Body.String()), 200)])
	}
}

// ─────────────────────────────────────────────────────────────────────
// Unknown paths
// ─────────────────────────────────────────────────────────────────────

func TestProbes_UnknownPath_404(t *testing.T) {
	p, cleanup := newProbes(t, nil, true)
	defer cleanup()
	rec := hit(p.Handler(), http.MethodGet, "/v1/judicial/cases")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (aggregator has no /v1/* routes)", rec.Code)
	}
}

func minLen(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FUNCTIONAL: the /readyz ledger client must verify a privately-signed ledger
// against the configured CA and present no client cert (the open-HTTPS posture).
// Regression guard: the probe used a bare http.Client (system roots), so the
// aggregator scanned fine yet /readyz 503'd on x509 against the run CA.
func TestLedgerProbeHTTPClient_ServerVerifyReachesPrivateLedger(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := ledgerProbeHTTPClient(common.Config{LedgerURL: srv.URL, LedgerCAFile: caFile})
	if err != nil {
		t.Fatalf("ledgerProbeHTTPClient: %v", err)
	}
	resp, err := c.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("CA-pinned probe GET failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// The OLD bare-client behaviour (system roots) MUST be rejected.
	if _, err := (&http.Client{}).Get(srv.URL + "/healthz"); err == nil {
		t.Fatal("bare client accepted a privately-signed ledger — the probe bug")
	}
}

// http endpoint → a plain client (no TLS material needed).
func TestLedgerProbeHTTPClient_PlaintextEndpoint(t *testing.T) {
	c, err := ledgerProbeHTTPClient(common.Config{LedgerURL: "http://ledger:8092"})
	if err != nil {
		t.Fatalf("ledgerProbeHTTPClient: %v", err)
	}
	if c == nil {
		t.Fatal("nil client for plaintext endpoint")
	}
}
