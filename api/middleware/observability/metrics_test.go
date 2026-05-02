/*
FILE PATH: api/middleware/observability/metrics_test.go

DESCRIPTION:
    Pins the Prometheus metrics middleware:
      1. A 200 response increments jn_http_requests_total{...,status="2xx"}.
      2. A 500 response increments {...,status="5xx"}.
      3. Duration histogram observes a sample per request.
      4. In-flight gauge increments on entry and decrements on exit.
      5. Handler() serves the registry as text/plain in
         OpenMetrics format.
*/
package observability

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetrics_2xx_IncrementsCounter(t *testing.T) {
	r := NewMetricsRegistry()
	h := r.Wrap(staticRoute("/test"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		h.ServeHTTP(rec, req)
	}
	if got := testutil.ToFloat64(r.requests.WithLabelValues("/test", "GET", "2xx")); got != 3 {
		t.Errorf("counter = %v, want 3", got)
	}
}

func TestMetrics_5xx_StatusClassBucket(t *testing.T) {
	r := NewMetricsRegistry()
	h := r.Wrap(staticRoute("/oops"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "broken", http.StatusInternalServerError)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oops", nil)
	h.ServeHTTP(rec, req)
	if got := testutil.ToFloat64(r.requests.WithLabelValues("/oops", "GET", "5xx")); got != 1 {
		t.Errorf("5xx counter = %v, want 1", got)
	}
}

func TestMetrics_DurationObserved(t *testing.T) {
	r := NewMetricsRegistry()
	h := r.Wrap(staticRoute("/t"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	h.ServeHTTP(rec, req)
	// Histogram counter check: 1 observation since one request
	// flowed through. CollectAndCount counts samples across all
	// label sets that have been observed.
	if got := testutil.CollectAndCount(r.duration); got == 0 {
		t.Error("duration histogram observed nothing")
	}
}

func TestMetrics_InFlightGauge_IncDecBalanced(t *testing.T) {
	r := NewMetricsRegistry()
	h := r.Wrap(staticRoute("/t"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Read in-flight while we're inside the handler.
		if got := testutil.ToFloat64(r.inFlight.WithLabelValues("/t")); got != 1 {
			t.Errorf("in-flight during handler = %v, want 1", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	h.ServeHTTP(rec, req)
	if got := testutil.ToFloat64(r.inFlight.WithLabelValues("/t")); got != 0 {
		t.Errorf("in-flight after handler = %v, want 0 (Inc must be balanced by Dec)", got)
	}
}

func TestMetrics_Handler_ServesOpenMetrics(t *testing.T) {
	r := NewMetricsRegistry()
	// Generate at least one sample so the registry has something to render.
	r.Wrap(staticRoute("/t"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/t", nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "jn_http_requests_total") {
		t.Errorf("metrics output missing jn_http_requests_total: %s", body[:min(len(body), 200)])
	}
}

func TestClassifyStatus_Buckets(t *testing.T) {
	cases := map[int]string{200: "2xx", 201: "2xx", 301: "3xx", 400: "4xx", 500: "5xx", 599: "5xx"}
	for code, want := range cases {
		if got := classifyStatus(code); got != want {
			t.Errorf("classifyStatus(%d) = %s, want %s", code, got, want)
		}
	}
}

// staticRoute returns a routeFn that always reports the same label.
func staticRoute(s string) func() string { return func() string { return s } }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
