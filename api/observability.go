/*
FILE PATH: api/observability.go

DESCRIPTION:
    Composer-side bundle of the Phase 15 observability stack:
    Prometheus metrics, structured logger, request-ID. A single
    Observability instance is shared across every /v1/* handler so
    metrics + logs share one registry + logger output.

    The stack order, outer-to-inner, is:

      RequestID → Metrics → Logger → reliability → auth → handler

    Reasoning:
      RequestID outermost so correlation IDs are present in every
        downstream wrapper's log lines.
      Metrics next so RED counters reflect the FULL request
        latency including auth + reliability outcomes.
      Logger next so log lines see the same body + status the
        metrics counted, without re-buffering.
      Reliability + auth + handler in their original order.

    Tests construct their own Observability with NewObservability();
    production reuses a single instance bound to the composer for
    /metrics scraping.
*/
package api

import (
	"net/http"

	"github.com/rs/zerolog"

	"github.com/clearcompass-ai/judicial-network/api/middleware/observability"
)

// Observability is the composer-level bundle of metrics + logger +
// request-ID middleware. Construct one per process via
// NewObservability(); pass it to NewServer via Config.Observability,
// and reach /metrics via Handler().
type Observability struct {
	metrics *observability.MetricsRegistry
	logger  zerolog.Logger
}

// NewObservability returns a default-configured bundle:
//   - fresh Prometheus registry (jn_http_* metrics)
//   - zerolog → stderr in JSON
func NewObservability() *Observability {
	return &Observability{
		metrics: observability.NewMetricsRegistry(),
		logger:  observability.NewLogger(),
	}
}

// MetricsHandler returns the /metrics endpoint handler. Mount on
// the composer outside auth + reliability so scrapers can always
// reach it.
func (o *Observability) MetricsHandler() http.Handler {
	return o.metrics.Handler()
}

// Wrap stacks RequestID → Metrics → Logger around next, in
// outer-to-inner order. routeLabel is the static label used for
// metrics + log fields (e.g. "/v1/judicial"); request paths with
// per-request variation (sequence numbers, DIDs) MUST NOT be used
// here because Prometheus label cardinality blows up.
func (o *Observability) Wrap(routeLabel string, next http.Handler) http.Handler {
	routeFn := func() string { return routeLabel }
	// Inner-to-outer composition: build from the handler outward
	// so the resulting wrapper executes in the documented order.
	wrapped := observability.LoggerMiddleware(o.logger, routeFn)(next)
	wrapped = o.metrics.Wrap(routeFn, wrapped)
	wrapped = observability.RequestID(wrapped)
	return wrapped
}
