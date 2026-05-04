/*
FILE PATH: api/observability_test.go

DESCRIPTION:
    Composer-side smoke tests for Phase 15 observability wiring.
    The middleware primitives have unit tests in
    api/middleware/observability/; tests here pin that NewServer
    actually mounts /metrics + applies the wrapper stack to /v1/*.

    Pinned:
      1. /metrics endpoint is reachable, unauthenticated, and emits
         the canonical jn_http_* metric names.
      2. A /v1/* request increments the matching counter.
      3. Every response carries an X-Request-ID header even when
         the underlying handler short-circuits (e.g., 401 on no
         auth wired).
      4. The metrics endpoint stays reachable when the global rate
         limiter is exhausted on /v1/* — same rationale as /healthz.
*/
package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clearcompass-ai/judicial-network/api/middleware/observability"
)

func TestObservability_MetricsEndpoint_Reachable(t *testing.T) {
	srv := mustComposer(t)
	// Generate at least one sample so the registry has counters
	// with non-zero label sets to render. An empty registry's
	// scrape body is empty bytes.
	srv.Handler().ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/v1/verify/origin/did:web:x/1", nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "jn_http_") {
		t.Errorf("metrics body missing jn_http_* metrics: %q", body[:min(len(body), 200)])
	}
}

func TestObservability_RequestCounted(t *testing.T) {
	srv := mustComposer(t)
	// Drive a /v1/* request to generate a sample.
	srv.Handler().ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/v1/verify/origin/did:web:x/1", nil))

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	// The counter must show at least one entry for /v1/verify.
	if !strings.Contains(string(body), `jn_http_requests_total{`) {
		t.Errorf("metrics body missing requests_total samples: %s",
			body[:min(len(body), 400)])
	}
	if !strings.Contains(string(body), `route="/v1/verify"`) {
		t.Errorf("missing /v1/verify label in metrics: %s",
			body[:min(len(body), 400)])
	}
}

func TestObservability_RequestID_OnEarlyReturn(t *testing.T) {
	// /v1/judicial/cases with no auth resolver wired returns 401.
	// The X-Request-ID header MUST still be present.
	srv := mustComposer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases",
		strings.NewReader("{}"))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get(observability.HeaderRequestID); len(got) != 32 {
		t.Errorf("X-Request-ID missing on 401 response; got %q (len %d)", got, len(got))
	}
}

func TestObservability_MetricsReachableWhenRateLimited(t *testing.T) {
	srv, err := NewServer(Config{
		Addr:        ":0",
		GlobalRPS:   0.0001,
		GlobalBurst: 1, // rate-limit /v1/* almost immediately
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Burn the global bucket on /v1/*.
	srv.Handler().ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/v1/verify/origin/did:web:x/1", nil))
	srv.Handler().ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/v1/verify/origin/did:web:x/1", nil))

	// /metrics MUST still be 200 — it bypasses the rate limiter.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("metrics under rate-limit: got %d, want 200", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// /readyz (Priority 3)
// ─────────────────────────────────────────────────────────────────────

func TestReadyz_NoChecks_200(t *testing.T) {
	// Default mustComposer config has no ReadyzChecks → /readyz is
	// 200 by design ("nothing to check, process is up").
	srv := mustComposer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (no checks)", rec.Code)
	}
}

func TestReadyz_AllPass_200(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv, err := NewServer(Config{
		Addr: ":0",
		ReadyzChecks: []observability.ReadyCheck{
			observability.CheckHTTPGet("operator", upstream.URL),
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"operator":"ok"`) {
		t.Errorf("body should mention operator:ok; got %s", rec.Body.String())
	}
}

func TestReadyz_OneFails_503(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer upstream.Close()

	srv, err := NewServer(Config{
		Addr: ":0",
		ReadyzChecks: []observability.ReadyCheck{
			observability.CheckHTTPGet("operator", upstream.URL),
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (operator unhealthy)", rec.Code)
	}
}
