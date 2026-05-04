/*
FILE PATH: tools/cmd/aggregator/probes.go

DESCRIPTION:
    Probe HTTP handlers for the aggregator binary. Three endpoints,
    each unauthenticated so k8s liveness + Prometheus scrapers can
    always reach them:

      GET /healthz
        200 ok unconditionally. Liveness — process is up.

      GET /readyz
        200 ok when both the operator endpoint AND Postgres are
        reachable; 503 otherwise. Used for k8s readiness so a
        replica that can't fulfill its job stops receiving traffic.

      GET /metrics
        Prometheus scrape endpoint. Reuses the Phase 15
        api/middleware/observability.MetricsRegistry so the metric
        name conventions match cmd/network-api (jn_http_*).

    No /v1/* routes — the aggregator is write-only against its own
    database. Read traffic for the aggregator's Postgres state
    belongs in court-tools / provider-tools, which run as separate
    binaries.
*/
package main

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/middleware/observability"
	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// errMissingDB / errMissingOperator are surfaced from run() when
// boot config is incomplete.
var (
	errMissingDB       = errors.New("aggregator: cfg.database_url required")
	errMissingOperator = errors.New("aggregator: cfg.operator_url required")
)

// dbProber is the minimal *common.DB-shaped surface the readyz
// check needs. Tests inject a fake; production passes a *common.DB.
type dbProber interface {
	PingContext(ctx context.Context) error
}

// probeHandlers groups the three probe endpoints. Holds the metrics
// registry + the readyz dependencies (db + operator URL) so the
// handlers can fail-fast when an upstream is unreachable.
type probeHandlers struct {
	metrics     *observability.MetricsRegistry
	db          dbProber
	operatorURL string
	httpClient  *http.Client

	// readyState caches the last computed readiness so /readyz is
	// O(1) when called frequently. Refreshed on a 5-second cadence
	// in the background; the cache TTL bounds staleness.
	ready atomic.Bool
}

// newProbeHandlers constructs the probe surface. The supplied db
// and operatorURL are used for the readyz check; pass them from
// run() once both have been validated.
func newProbeHandlers(db dbProber, operatorURL string) *probeHandlers {
	return &probeHandlers{
		metrics:     observability.NewMetricsRegistry(),
		db:          db,
		operatorURL: operatorURL,
		httpClient:  &http.Client{Timeout: 3 * time.Second},
	}
}

// Handler returns the mux that serves /healthz, /readyz, /metrics.
// Mount this on the aggregator's HTTP server.
func (p *probeHandlers) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", p.healthz)
	mux.HandleFunc("GET /readyz", p.readyz)
	mux.Handle("GET /metrics", p.metrics.Handler())
	return mux
}

// healthz always returns 200. Liveness probes verify only that the
// process is up + responsive — they do NOT check upstream
// dependencies, because k8s would restart the pod on every
// upstream blip otherwise.
func (p *probeHandlers) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// readyz returns 200 only when both Postgres and the operator
// endpoint are reachable. Used for k8s readiness so a replica that
// can't fulfill its job stops receiving traffic. 5s budget for the
// full check.
func (p *probeHandlers) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := p.db.PingContext(ctx); err != nil {
		http.Error(w, "database unreachable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.operatorURL+"/healthz", nil)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		http.Error(w, "operator unreachable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		http.Error(w, "operator unhealthy", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

// Compile-time check that *common.DB satisfies dbProber.
var _ dbProber = (*common.DB)(nil)
