/*
FILE PATH: tools/cmd/aggregator/probes.go

DESCRIPTION:

	Probe HTTP handlers for the aggregator binary. Three endpoints,
	each unauthenticated so k8s liveness + Prometheus scrapers can
	always reach them:

	  GET /healthz
	    200 ok unconditionally. Liveness — process is up.

	  GET /readyz
	    200 ok when both the ledger endpoint AND Postgres are
	    reachable; 503 otherwise. Used for k8s readiness so a
	    replica that can't fulfill its job stops receiving traffic.

	  GET /metrics
	    Prometheus scrape endpoint. Reuses the
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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	common "github.com/clearcompass-ai/attesta-tools/libs/clitools"
	"github.com/clearcompass-ai/attesta-tools/libs/httpmw/observability"
)

// errMissingDB / errMissingLedger are surfaced from run() when
// boot config is incomplete.
var (
	errMissingDB     = errors.New("aggregator: cfg.database_url required")
	errMissingLedger = errors.New("aggregator: cfg.ledger_url required")
)

// dbProber is the minimal *common.DB-shaped surface the readyz
// check needs. Tests inject a fake; production passes a *common.DB.
type dbProber interface {
	PingContext(ctx context.Context) error
}

// probeHandlers groups the three probe endpoints. Holds the metrics
// registry + the readyz dependencies (db + ledger URL) so the
// handlers can fail-fast when an upstream is unreachable.
type probeHandlers struct {
	metrics    *observability.MetricsRegistry
	db         dbProber
	ledgerURL  string
	httpClient *http.Client

	// readyState caches the last computed readiness so /readyz is
	// O(1) when called frequently. Refreshed on a 5-second cadence
	// in the background; the cache TTL bounds staleness.
	ready atomic.Bool
}

// newProbeHandlers constructs the probe surface. The supplied db and ledgerURL
// are used for the readyz check; ledgerClient is the CA-aware client the /readyz
// ledger probe uses (build it via ledgerProbeHTTPClient so it verifies the
// ledger's cert like the scanner does). A nil ledgerClient falls back to a bare
// client (plaintext/dev only).
func newProbeHandlers(db dbProber, ledgerURL string, ledgerClient *http.Client) *probeHandlers {
	if ledgerClient == nil {
		ledgerClient = &http.Client{Timeout: 3 * time.Second}
	}
	return &probeHandlers{
		metrics:    observability.NewMetricsRegistry(),
		db:         db,
		ledgerURL:  ledgerURL,
		httpClient: ledgerClient,
	}
}

// ledgerProbeHTTPClient builds the /readyz ledger-health client to the SAME TLS
// posture the scanner's ledger client uses, so the probe verifies the ledger's
// privately-signed cert against the configured CA instead of the system roots.
// A bare client fails x509 against a private CA — so the aggregator would scan
// fine yet never report ready. https + CA → server-verify; + client cert → mTLS;
// http → plain. Verification is never skipped.
func ledgerProbeHTTPClient(cfg common.Config) (*http.Client, error) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.LedgerURL)), "https://") {
		return &http.Client{Timeout: 3 * time.Second}, nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: cfg.LedgerServerName}
	if cfg.LedgerCAFile != "" {
		caPEM, err := os.ReadFile(cfg.LedgerCAFile)
		if err != nil {
			return nil, fmt.Errorf("read ledger CA %q: %w", cfg.LedgerCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("ledger CA %q contains no parseable certificates", cfg.LedgerCAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.LedgerClientCertFile != "" && cfg.LedgerClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.LedgerClientCertFile, cfg.LedgerClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load ledger client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
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

// readyz returns 200 only when both Postgres and the ledger
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.ledgerURL+"/healthz", nil)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		http.Error(w, "ledger unreachable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		http.Error(w, "ledger unhealthy", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

// Compile-time check that *common.DB satisfies dbProber.
var _ dbProber = (*common.DB)(nil)
