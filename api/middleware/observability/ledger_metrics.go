/*
FILE PATH: api/middleware/observability/ledger_metrics.go

DESCRIPTION:

	Prometheus collectors specific to the JN→ledger submit path.
	Distinct from the inbound HTTP RED metrics in metrics.go: these
	measure the OUTBOUND latency of the ledger submit, plus the
	circuit-breaker state, so ledgers can attribute tail-latency
	outliers + 503s to the ledger side rather than the JN side.

	Three collectors:

	  jn_ledger_submit_total{result}
	    Counter. result ∈ {ok, error, circuit_open}.

	  jn_ledger_submit_duration_seconds
	    Histogram of submit duration. Same buckets as the inbound
	    latency histogram so dashboards can plot p99 ledger
	    latency next to p99 inbound latency.

	  jn_ledger_submit_breaker_state{state}
	    Gauge. Set to 1 when the breaker is in the labelled state,
	    0 otherwise. Three label values: closed / open / half_open.

	LedgerSubmitMetrics registers all three with the supplied
	*MetricsRegistry's Prometheus registry so /metrics serves them
	alongside the inbound jn_http_* metrics.
*/
package observability

import (
	"github.com/prometheus/client_golang/prometheus"
)

// LedgerSubmitMetrics bundles the ledger-submit collectors.
// One instance per process; share via MetricsRegistry.
type LedgerSubmitMetrics struct {
	requests *prometheus.CounterVec
	duration prometheus.Histogram
	breaker  *prometheus.GaugeVec
}

// NewLedgerSubmitMetrics registers + returns the ledger-submit
// collectors using the supplied MetricsRegistry's underlying
// Prometheus registry.
func NewLedgerSubmitMetrics(r *MetricsRegistry) *LedgerSubmitMetrics {
	m := &LedgerSubmitMetrics{
		requests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "jn_ledger_submit_total",
				Help: "Total ledger submit attempts, labelled by outcome (ok / error / circuit_open).",
			},
			[]string{"result"},
		),
		duration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "jn_ledger_submit_duration_seconds",
				Help:    "Ledger submit duration including SDK retry-after handling.",
				Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
		),
		breaker: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "jn_ledger_submit_breaker_state",
				Help: "Circuit breaker state for the ledger submit path (1 = current state, 0 = not).",
			},
			[]string{"state"},
		),
	}
	r.registry.MustRegister(m.requests, m.duration, m.breaker)
	// Initialise breaker label set so /metrics emits all three
	// values from the start (avoids "missing label" gaps in
	// dashboards).
	for _, s := range []string{"closed", "open", "half_open"} {
		m.breaker.WithLabelValues(s).Set(0)
	}
	m.breaker.WithLabelValues("closed").Set(1) // initial state
	return m
}

// Observe records one ledger-submit outcome. Pass:
//
//	durationSeconds  end-to-end submit latency
//	result           "ok" / "error" / "circuit_open"
//	breakerState     "closed" / "open" / "half_open" — emitted by
//	                 reliability.Breaker.State(); call sites pass it
//	                 in directly so this package doesn't depend on
//	                 reliability.
func (m *LedgerSubmitMetrics) Observe(durationSeconds float64, result, breakerState string) {
	m.requests.WithLabelValues(result).Inc()
	m.duration.Observe(durationSeconds)
	for _, s := range []string{"closed", "open", "half_open"} {
		if s == breakerState {
			m.breaker.WithLabelValues(s).Set(1)
		} else {
			m.breaker.WithLabelValues(s).Set(0)
		}
	}
}
