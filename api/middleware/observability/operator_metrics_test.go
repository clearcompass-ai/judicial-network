/*
FILE PATH: api/middleware/observability/operator_metrics_test.go

DESCRIPTION:
    Pins the operator-submit metrics:
      1. Counter increments per result.
      2. Duration histogram observes per call.
      3. Breaker gauge is exclusive — when state="open", the
         "closed" + "half_open" gauges are 0.
      4. Initial state is "closed" with gauge=1, others=0.
*/
package observability

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestOperatorSubmitMetrics_CounterByResult(t *testing.T) {
	r := NewMetricsRegistry()
	m := NewOperatorSubmitMetrics(r)
	m.Observe(0.05, "ok", "closed")
	m.Observe(0.05, "ok", "closed")
	m.Observe(0.10, "error", "closed")
	m.Observe(0.00, "circuit_open", "open")

	if got := testutil.ToFloat64(m.requests.WithLabelValues("ok")); got != 2 {
		t.Errorf("ok counter = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("error")); got != 1 {
		t.Errorf("error counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("circuit_open")); got != 1 {
		t.Errorf("circuit_open counter = %v, want 1", got)
	}
}

func TestOperatorSubmitMetrics_DurationObserved(t *testing.T) {
	r := NewMetricsRegistry()
	m := NewOperatorSubmitMetrics(r)
	m.Observe(0.10, "ok", "closed")
	if got := testutil.CollectAndCount(m.duration); got == 0 {
		t.Error("duration histogram observed nothing")
	}
}

func TestOperatorSubmitMetrics_BreakerGauge_Exclusive(t *testing.T) {
	r := NewMetricsRegistry()
	m := NewOperatorSubmitMetrics(r)
	m.Observe(0.10, "circuit_open", "open")
	if got := testutil.ToFloat64(m.breaker.WithLabelValues("open")); got != 1 {
		t.Errorf("open gauge = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.breaker.WithLabelValues("closed")); got != 0 {
		t.Errorf("closed gauge = %v, want 0 when open is current", got)
	}
	if got := testutil.ToFloat64(m.breaker.WithLabelValues("half_open")); got != 0 {
		t.Errorf("half_open gauge = %v, want 0 when open is current", got)
	}
}

func TestOperatorSubmitMetrics_InitialState_Closed(t *testing.T) {
	r := NewMetricsRegistry()
	m := NewOperatorSubmitMetrics(r)
	if got := testutil.ToFloat64(m.breaker.WithLabelValues("closed")); got != 1 {
		t.Errorf("initial closed gauge = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.breaker.WithLabelValues("open")); got != 0 {
		t.Errorf("initial open gauge = %v, want 0", got)
	}
}
