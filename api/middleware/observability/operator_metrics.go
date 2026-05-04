/*
FILE PATH: api/middleware/observability/operator_metrics.go

DESCRIPTION:
    OTel-backed instruments specific to the JN→operator submit path.
    Distinct from the inbound HTTP RED metrics in metrics.go: these
    measure the OUTBOUND latency of the operator submit, plus the
    circuit-breaker state, so operators can attribute tail-latency
    outliers + 503s to the operator side rather than the JN side.

    Three instruments:

      jn_operator_submit_total{result}
        Counter. result ∈ {ok, error, circuit_open}.
        Wire form ends in "_total" via the OTel→Prom suffix rule.

      jn_operator_submit_duration_seconds
        Histogram of submit duration. Same buckets as the inbound
        latency histogram so dashboards can plot p99 operator
        latency next to p99 inbound latency.

      jn_operator_submit_breaker_state{state}
        Observable gauge. Set to 1 when the breaker is in the
        labelled state, 0 otherwise. Three label values: closed /
        open / half_open. Implemented as an Int64ObservableGauge
        with a callback that emits 1 for the current state and 0
        for the others — preserves the exclusive-1 wire shape that
        existing dashboards depend on.

    NewOperatorSubmitMetrics registers all three on the supplied
    *MetricsRegistry's MeterProvider so /metrics serves them
    alongside the inbound jn_http_* metrics.
*/
package observability

import (
	"context"
	"fmt"
	"sync/atomic"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// breakerStateClosed / breakerStateOpen / breakerStateHalfOpen are
// the legal label values for the breaker gauge. Stored as constants
// so the Observe + callback implementations agree on the exact
// strings — a typo on either side would silently emit no signal.
const (
	breakerStateClosed   = "closed"
	breakerStateOpen     = "open"
	breakerStateHalfOpen = "half_open"
)

// breakerStates is the iteration order used by the observable
// callback when emitting the per-state gauge. Order doesn't
// affect semantics; pinned for test determinism.
var breakerStates = [...]string{
	breakerStateClosed,
	breakerStateOpen,
	breakerStateHalfOpen,
}

// OperatorSubmitMetrics bundles the operator-submit instruments.
// One instance per process; share via MetricsRegistry.
type OperatorSubmitMetrics struct {
	requests metric.Int64Counter
	duration metric.Float64Histogram
	// breaker is exposed only for assertion in tests; it holds
	// the registered ObservableGauge so tests can confirm
	// registration succeeded.
	breaker metric.Int64ObservableGauge

	// currentState holds the most-recent breaker state seen by
	// Observe. The ObservableGauge callback reads this to emit
	// the per-state 1/0 wire shape on every scrape.
	currentState atomic.Value // string
}

// NewOperatorSubmitMetrics registers + returns the operator-submit
// instruments using the supplied MetricsRegistry's MeterProvider.
//
// Initial breaker state is "closed" — production reliability.Breaker
// also boots closed, so dashboards see closed=1 from t=0 onward
// without an "all states 0" gap that would suggest a missing scrape.
func NewOperatorSubmitMetrics(r *MetricsRegistry) *OperatorSubmitMetrics {
	meter := r.provider.Meter(
		"github.com/clearcompass-ai/judicial-network/api/middleware/observability/operator_submit",
	)

	requests, err := meter.Int64Counter(
		// OTel-native name; the Prometheus exporter appends "_total"
		// in wire output, producing "jn_operator_submit_total".
		"jn_operator_submit",
		metric.WithDescription(
			"Total operator submit attempts, labelled by outcome (ok / error / circuit_open)."),
	)
	if err != nil {
		panic(fmt.Sprintf("observability/operator_submit: counter: %v", err))
	}

	duration, err := meter.Float64Histogram(
		"jn_operator_submit_duration_seconds",
		metric.WithDescription("Operator submit duration including SDK retry-after handling."),
		metric.WithUnit("s"),
	)
	if err != nil {
		panic(fmt.Sprintf("observability/operator_submit: histogram: %v", err))
	}

	m := &OperatorSubmitMetrics{
		requests: requests,
		duration: duration,
	}
	m.currentState.Store(breakerStateClosed)

	breaker, err := meter.Int64ObservableGauge(
		"jn_operator_submit_breaker_state",
		metric.WithDescription(
			"Circuit breaker state for the operator submit path (1 = current state, 0 = not)."),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			cur, _ := m.currentState.Load().(string)
			for _, s := range breakerStates {
				v := int64(0)
				if s == cur {
					v = 1
				}
				o.Observe(v, metric.WithAttributes(attribute.String("state", s)))
			}
			return nil
		}),
	)
	if err != nil {
		panic(fmt.Sprintf("observability/operator_submit: observable gauge: %v", err))
	}
	m.breaker = breaker

	return m
}

// Observe records one operator-submit outcome. Pass:
//
//	durationSeconds  end-to-end submit latency
//	result           "ok" / "error" / "circuit_open"
//	breakerState     "closed" / "open" / "half_open" — emitted by
//	                 reliability.Breaker.State(); call sites pass it
//	                 in directly so this package doesn't depend on
//	                 reliability.
//
// breakerState is stored atomically and read by the
// jn_operator_submit_breaker_state observable callback on every
// scrape. Any value outside the documented set produces a wire
// state where every label has value 0 — a defensive failure mode
// (no-op signal) rather than a panic.
func (m *OperatorSubmitMetrics) Observe(durationSeconds float64, result, breakerState string) {
	ctx := context.Background()
	m.requests.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
	m.duration.Record(ctx, durationSeconds)
	m.currentState.Store(breakerState)
}
