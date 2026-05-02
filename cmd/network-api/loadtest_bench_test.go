/*
FILE PATH: cmd/network-api/loadtest_bench_test.go

DESCRIPTION:
    Phase 16 load validation. Drives cmd/network-api.run() as a
    real HTTP listener with N concurrent workers and measures:

      throughput   (requests / second)
      p50 / p95 / p99 latency
      error rate
      goroutine count delta over the run

    Two scenarios:

      BenchmarkBinary_Healthz  — minimum-overhead path (auth +
        reliability + observability all bypass /healthz, so this
        measures the raw HTTP stack ceiling).
      BenchmarkBinary_Cases    — POST /v1/judicial/cases with the
        full middleware stack: RequestID → Metrics → Logger →
        RateLimit → Timeout → MaxBodyBytes → Auth (injecting) →
        judicial handler → cases.InitiateCase. The real production
        write path minus the stub-operator forward.

    Defaults are tuned for CI: 64 workers × 5s. Operators running
    real production validation crank up via env vars:

      LOADTEST_WORKERS=512 LOADTEST_DURATION=60s \
        go test -run=^$ -bench=BenchmarkBinary_Cases ./cmd/network-api/

    Acceptance criteria documented in the result line: throughput
    in req/sec + percentile latencies + error rate. Use the metrics
    endpoint scraped during the run for goroutine / GC visibility
    (Phase 15 wired the Prometheus collectors).
*/
package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
	"github.com/clearcompass-ai/judicial-network/api/middleware"

	tndavidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
)

// loadtestParams reads LOADTEST_WORKERS / LOADTEST_DURATION env
// vars with safe CI defaults.
func loadtestParams() (workers int, duration time.Duration) {
	workers = 64
	duration = 5 * time.Second
	if v := os.Getenv("LOADTEST_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			workers = n
		}
	}
	if v := os.Getenv("LOADTEST_DURATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			duration = d
		}
	}
	return
}

// percentile returns the p-th percentile (0..1) of latencies. The
// slice is sorted in place — callers don't need it again afterward.
func percentile(latencies []time.Duration, p float64) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	idx := int(float64(len(latencies)-1) * p)
	return latencies[idx]
}

// runLoadtest boots the binary on a random port, drives `workers`
// concurrent HTTP loops against the supplied request factory for
// `duration`, and reports the throughput + latency percentiles +
// error rate as a log line. testing.TB so both BenchmarkX and
// TestX can drive it.
func runLoadtest(b testing.TB, name string, makeReq func(addr string) *http.Request) {
	b.Helper()
	workers, duration := loadtestParams()

	// Free port + binary boot mirrors TestBinaryE2E but with a
	// silent logger to keep the bench output readable.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfgPath := writeJSON(b, map[string]any{
		"listen_addr":             addr,
		"operator_endpoint":       "http://op.test",
		"artifact_store_endpoint": "http://art.test",
		"verification_endpoint":   "http://verify.test",
		"eth_rpc_endpoint":        "http://rpc.test",
		"keystore":                map[string]any{"backend": "memory"},
		"nonce_store": map[string]any{
			"backend":          "memory",
			"freshness_window": int64(time.Minute),
		},
		"auth": map[string]any{
			"mode":       "jwt",
			"jwt_issuer": "https://idp.test",
			"jwks_url":   "https://idp.test/.well-known/jwks.json",
		},
	})
	clearAPIBenchEnv(b)

	scwDID := binE2EScwDID()
	stubDeps := deps{
		registerBundles: registerProductionBundles,
		newKeyStore: func(_ config.KeyStoreConfig) (keystore.KeyStore, error) {
			ks := keystore.NewMemoryKeyStore()
			_, _ = ks.GenerateSecp256k1(binE2EOwnerDID, "signing")
			return ks, nil
		},
		newAuthenticator: func(_ config.AuthConfig) (middleware.Authenticator, error) {
			return injectingAuth{did: scwDID}, nil
		},
	}

	runErr := make(chan error, 1)
	go func() { runErr <- run([]string{"--config", cfgPath}, stubDeps) }()
	defer func() {
		proc, _ := os.FindProcess(os.Getpid())
		_ = proc.Signal(os.Interrupt)
		<-runErr
	}()

	if !waitFor(b, 3*time.Second, func() bool {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}) {
		b.Fatal("binary never healthy within 3s")
	}

	// Drive workers in parallel for `duration`. Each worker keeps
	// its own latency slice; we merge at the end.
	client := &http.Client{Timeout: 10 * time.Second}
	var totalReq atomic.Int64
	var errCount atomic.Int64
	allLat := make([][]time.Duration, workers)

	gcStart := runtime.NumGoroutine()
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(workers)
	startWall := time.Now()
	for i := 0; i < workers; i++ {
		i := i
		go func() {
			defer wg.Done()
			lats := make([]time.Duration, 0, 1024)
			for ctx.Err() == nil {
				req := makeReq(addr)
				t0 := time.Now()
				resp, err := client.Do(req)
				dt := time.Since(t0)
				totalReq.Add(1)
				if err != nil {
					errCount.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode >= 500 {
					errCount.Add(1)
				}
				lats = append(lats, dt)
			}
			allLat[i] = lats
		}()
	}
	wg.Wait()
	wallElapsed := time.Since(startWall)

	merged := mergeLatencies(allLat)
	throughput := float64(totalReq.Load()) / wallElapsed.Seconds()
	errRate := float64(errCount.Load()) / float64(totalReq.Load())
	gcEnd := runtime.NumGoroutine()

	b.Logf("[%s] workers=%d duration=%s requests=%d throughput=%.0f req/s error_rate=%.4f%%",
		name, workers, wallElapsed.Truncate(time.Millisecond),
		totalReq.Load(), throughput, errRate*100)
	b.Logf("[%s] latencies p50=%v p95=%v p99=%v max=%v",
		name, percentile(merged, 0.50),
		percentile(merged, 0.95),
		percentile(merged, 0.99),
		percentile(merged, 1.0))
	b.Logf("[%s] goroutines start=%d end=%d delta=%+d",
		name, gcStart, gcEnd, gcEnd-gcStart)
}

func mergeLatencies(in [][]time.Duration) []time.Duration {
	total := 0
	for _, s := range in {
		total += len(s)
	}
	out := make([]time.Duration, 0, total)
	for _, s := range in {
		out = append(out, s...)
	}
	return out
}

// clearAPIBenchEnv mirrors clearAPIEnv from main_test.go but takes
// testing.TB so it's callable from both *testing.T and *testing.B.
func clearAPIBenchEnv(t testing.TB) {
	t.Helper()
	for _, v := range []string{
		"API_LISTEN_ADDR",
		"API_OPERATOR_ENDPOINT",
		"API_ARTIFACT_STORE_ENDPOINT",
		"API_VERIFICATION_ENDPOINT",
		"API_ETH_RPC_ENDPOINT",
		"API_KEYSTORE_BACKEND",
		"API_NONCE_STORE_BACKEND",
		"API_NONCE_STORE_REDIS_ADDR",
		"API_AUTH_MODE",
	} {
		_ = os.Unsetenv(v)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Scenarios
// ─────────────────────────────────────────────────────────────────────

func BenchmarkBinary_Healthz(b *testing.B) {
	runLoadtest(b, "healthz", func(addr string) *http.Request {
		req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/healthz", nil)
		return req
	})
}

func BenchmarkBinary_Cases(b *testing.B) {
	body := []byte(`{
		"destination":   "` + tndavidson.ExchangeDID + `",
		"docket_number": "TN-DAV-2026-CR-LOAD",
		"case_type":     "criminal",
		"filed_date":    "2026-02-01",
		"event_time":    1761000000000000
	}`)
	runLoadtest(b, "cases", func(addr string) *http.Request {
		req, _ := http.NewRequest(http.MethodPost,
			"http://"+addr+"/v1/judicial/cases",
			strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		return req
	})
}

// ─────────────────────────────────────────────────────────────────────
// Acceptance test — sanity-check the load harness itself
// ─────────────────────────────────────────────────────────────────────

// TestLoadtest_Smoke runs a 1-second, 8-worker burst against
// /healthz so `go test ./cmd/network-api/...` always exercises the
// load harness. Catches regressions in the harness wiring without
// imposing benchmark-grade load on every CI run.
func TestLoadtest_Smoke(t *testing.T) {
	t.Setenv("LOADTEST_WORKERS", "8")
	t.Setenv("LOADTEST_DURATION", "1s")
	runLoadtest(t, "smoke", func(addr string) *http.Request {
		req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/healthz", nil)
		return req
	})
}
