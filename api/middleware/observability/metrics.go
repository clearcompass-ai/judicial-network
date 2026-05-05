/*
FILE PATH: api/middleware/observability/metrics.go

DESCRIPTION:

	Prometheus metrics middleware. Emits the RED triad (Rate /
	Errors / Duration) plus an in-flight gauge per route. Labels
	are kept minimal + bounded:

	  route   — the matched mux pattern (low-cardinality; dozens)
	  method  — HTTP verb (small fixed set)
	  status  — class bucket "2xx" / "4xx" / "5xx" / etc.
	            Using the class instead of the raw code keeps
	            cardinality bounded against a handler that returns
	            arbitrary status codes.

	Caller DID is deliberately NOT a label — that would explode
	cardinality at 10M/day across thousands of distinct callers.
	Per-caller telemetry belongs in structured logs (logger.go).

	/metrics is mounted by the composer outside the auth + rate-
	limit + body-size wrappers so Prometheus scrapers can always
	reach it (the same rationale as /healthz).
*/
package observability

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsRegistry bundles the Prometheus collectors. One instance
// per process; created at boot and shared across every middleware
// wrapper.
type MetricsRegistry struct {
	registry *prometheus.Registry

	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight *prometheus.GaugeVec
}

// NewMetricsRegistry constructs an isolated Prometheus registry +
// the standard JN counters / histogram / gauge. Tests instantiate
// their own registry to avoid global-state collisions; production
// uses one process-wide instance.
//
// The histogram buckets target API-level latencies: 1ms-1s
// covers the 99th percentile of healthy API calls; longer tails
// land in the +Inf bucket.
func NewMetricsRegistry() *MetricsRegistry {
	r := &MetricsRegistry{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "jn_http_requests_total",
				Help: "Total HTTP requests handled, labelled by route + method + status class.",
			},
			[]string{"route", "method", "status"},
		),
		duration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "jn_http_request_duration_seconds",
				Help:    "HTTP request duration, labelled by route + method.",
				Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			[]string{"route", "method"},
		),
		inFlight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "jn_http_in_flight_requests",
				Help: "Currently in-flight HTTP requests, labelled by route.",
			},
			[]string{"route"},
		),
	}
	r.registry.MustRegister(r.requests, r.duration, r.inFlight)
	return r
}

// Handler returns the /metrics scraper handler. Mount on the
// composer outside of auth + rate-limit so Prometheus can always
// reach it.
func (r *MetricsRegistry) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// Wrap returns middleware that records the RED triad + in-flight
// gauge for every request through next. The route label is read
// from the supplied routeFn — typically a closure that returns
// the static route this handler is mounted at (e.g. "/v1/judicial").
// Using a closure rather than r.URL.Path keeps cardinality bounded
// (request paths with sequence numbers / DIDs would otherwise
// explode the label space).
func (r *MetricsRegistry) Wrap(routeFn func() string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		route := routeFn()
		r.inFlight.WithLabelValues(route).Inc()
		defer r.inFlight.WithLabelValues(route).Dec()

		rec := newStatusRecorder(w)
		start := time.Now()
		next.ServeHTTP(rec, req)
		elapsed := time.Since(start).Seconds()

		statusClass := classifyStatus(rec.status)
		r.requests.WithLabelValues(route, req.Method, statusClass).Inc()
		r.duration.WithLabelValues(route, req.Method).Observe(elapsed)
	})
}

// statusRecorder wraps http.ResponseWriter to capture the status
// code for the metrics label without buffering the body. Default
// to 200 because Go's stdlib treats an unwritten WriteHeader as
// 200 OK.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func newStatusRecorder(w http.ResponseWriter) *statusRecorder {
	return &statusRecorder{ResponseWriter: w, status: http.StatusOK}
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// classifyStatus collapses raw codes into the class bucket
// ("2xx" / "4xx" / "5xx") to keep label cardinality bounded.
// 1xx and 3xx are uncommon enough to share their own buckets.
func classifyStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	}
	return strconv.Itoa(code)
}
