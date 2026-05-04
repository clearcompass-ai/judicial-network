/*
FILE PATH: tools/cmd/witness/probes.go

DESCRIPTION:
    Probe HTTP handlers for the witness daemon. Mirrors the
    aggregator binary's probe surface (same Phase 15 observability
    primitives) so cluster operators scrape uniformly.

      GET /healthz   — liveness, always 200.
      GET /readyz    — 200 only when at least one configured
                       operator endpoint is reachable. Returns 503
                       when ALL configured operators are down so
                       k8s removes the daemon from service when it
                       can't fulfill any cosigning work.
      GET /metrics   — Prometheus, jn_http_* names match the rest
                       of the JN binaries.

    No /v1/* routes — the witness daemon is write-only against
    operator endpoints; it serves no domain queries.
*/
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/middleware/observability"
)

type probeHandlers struct {
	metrics    *observability.MetricsRegistry
	cfg        Config
	httpClient *http.Client
}

func newProbeHandlers(cfg Config) *probeHandlers {
	return &probeHandlers{
		metrics:    observability.NewMetricsRegistry(),
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 3 * time.Second},
	}
}

func (p *probeHandlers) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", p.healthz)
	mux.HandleFunc("GET /readyz", p.readyz)
	mux.Handle("GET /metrics", p.metrics.Handler())
	return mux
}

func (p *probeHandlers) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// readyz returns 200 when ANY configured operator is reachable.
// At least one operator must be alive for the daemon to do useful
// work; if all are down the daemon is dead-weight and k8s should
// remove it from service.
func (p *probeHandlers) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	for _, base := range p.cfg.Operators {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
		resp, err := p.httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode/100 == 2 {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ready"))
				return
			}
		}
	}
	http.Error(w, "no configured operator reachable", http.StatusServiceUnavailable)
}
