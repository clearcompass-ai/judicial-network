# Load validation harness (Phase 16)

Empirical proof that `cmd/network-api` holds the production target
of **1000 TPS sustained** with bounded latency and zero error
inflation.

The harness is implemented as Go benchmarks in
`cmd/network-api/loadtest_bench_test.go` so it boots the **real
binary** end-to-end (loadConfig → registerProductionBundles →
buildKeyStore → buildAuthenticator → buildNonceStores →
buildJudicialDeps → api.NewServer → http.ListenAndServe) over a
real TCP listener. No external load generator (k6 / vegeta) is
required.

## Scenarios

| Benchmark | Path | Stack |
|---|---|---|
| `BenchmarkBinary_Healthz` | `GET /healthz` | bare HTTP — no auth, no reliability, no observability wrapping. Measures the raw mux ceiling. |
| `BenchmarkBinary_Cases`   | `POST /v1/judicial/cases` | full middleware stack: `RequestID → Metrics → Logger → RateLimit → Timeout → MaxBodyBytes → Auth → judicial.cases.InitiateCase`. The real production write path minus the operator forward. |

A third test, `TestLoadtest_Smoke`, runs a 1-second 8-worker burst
against `/healthz` so `go test ./cmd/network-api/...` always
exercises the harness wiring without imposing benchmark-grade load
on every CI run.

## Running

```sh
# CI defaults: 64 workers × 5s
go test -run=^$ -bench=BenchmarkBinary -benchtime=1x ./cmd/network-api/

# Production validation: 512 workers × 60s sustained
LOADTEST_WORKERS=512 LOADTEST_DURATION=60s \
  go test -run=^$ -bench=BenchmarkBinary -benchtime=1x ./cmd/network-api/

# Healthz only — measures the mux + listener ceiling
go test -run=^$ -bench=BenchmarkBinary_Healthz -benchtime=1x ./cmd/network-api/
```

The `-benchtime=1x` flag tells `go test` to run the benchmark body
exactly once — `runLoadtest` does its own `LOADTEST_DURATION`
loop, so we don't want `testing.B` to repeat it.

## Output

Each run logs three lines:

```
[cases] workers=64 duration=5s requests=N throughput=R req/s error_rate=E%
[cases] latencies p50=… p95=… p99=… max=…
[cases] goroutines start=… end=… delta=…
```

## Acceptance criteria

| Metric | Target |
|---|---|
| Throughput on `/v1/judicial/cases` (full stack) | ≥ 1000 req/s sustained for the configured duration |
| Throughput on `/healthz` (bare HTTP)            | ≥ 5000 req/s — confirms the listener / mux is not the bottleneck |
| `error_rate`                                    | < 0.01% (4xx counts as error if it surfaces unexpectedly; 5xx always counts) |
| `p99` latency on `/v1/judicial/cases`           | < 100 ms |
| `p99` latency on `/healthz`                     | < 10 ms |
| `goroutines delta`                              | < +50 (a leak grows linearly with request count; +50 over a 60s run with hundreds of thousands of requests is < 0.001%) |

## Reference run on a 4-vCPU test box

Snapshot from a run on `Intel(R) Xeon(R) @ 2.10GHz` (4 cores), Go
1.25, JN binary built with default flags — captured during this
phase's commit. Numbers above the targets are not headroom-tuned;
they are the out-of-the-box result with zero JVM-style warm-up.

```
[smoke]   workers=8   duration=1s  requests=47277   throughput=47270 req/s  error_rate=0.0000%
                      latencies p50=108µs    p95=362µs    p99=1.12ms   max=5.0ms
                      goroutines start=7  end=12  delta=+5

[cases]   workers=64  duration=5s  requests=122666  throughput=24527 req/s  error_rate=0.0000%
                      latencies p50=1.94ms  p95=5.53ms   p99=7.44ms   max=55ms
                      goroutines start=9  end=12  delta=+3
```

**Headroom vs the 1000 TPS production target:** ~24× on the full
write path with all middleware engaged, and the latency p99 is
~13× under the 100 ms cap. Goroutine delta after 122,666 requests
is +3 — no leak. Error rate is zero.

## What this validates

- Phase 14 reliability primitives don't impose throughput overhead
  beyond their stated work. (RateLimitGlobal disabled in the
  default Config, so this run measures the pure-passthrough cost
  of the middleware shell.)
- Phase 15 observability wiring (RequestID + Metrics + Logger)
  fits inside the per-request budget — even with a JSON log line
  per request and a Prometheus counter increment, p99 stays under
  10 ms.
- The default Phase A `judicial.Dependencies` (in-memory
  KeyStore + DelegationKeyStore, schemas.NewRegistry extractor,
  empty witness maps) does not block the case-initiate hot path.

## What this does NOT validate

- **Operator throughput.** `OperatorEndpoint` is set to
  `http://op.test` — the binary does NOT actually forward to a
  real operator during this benchmark. The `submitToOperator`
  path is exercised by `TestBinaryE2E_DavidsonSCW_HappyPath`
  (Phase C) against a stub operator; sustained-throughput
  validation against a real `ortholog-operator` is the operator
  repo's concern.
- **Aggregator read path.** `/v1/verify/*` calls into Verification
  deps that are nil-shimmed in this build. Read-side throughput
  validation lands when the operator HTTP read-side stabilises.
- **Multi-replica deployment.** Single-replica only here. The
  Phase B Redis NonceStore wiring has its own unit tests; cross-
  replica replay-defence under load is a deployment-validation
  concern.
- **mTLS handshake cost.** The benchmark uses plain HTTP. mTLS
  per-connection cost (5–10 ms) is amortised by HTTP/2 keep-alive
  and connection reuse in production but is not measured here.

## Updating the harness

The benchmark is defined in
[cmd/network-api/loadtest_bench_test.go](../cmd/network-api/loadtest_bench_test.go).
A new scenario is one entry in the `BenchmarkBinary_*` set —
follow the `BenchmarkBinary_Cases` shape: build a request factory
closure, call `runLoadtest(b, "name", makeReq)`.

The harness silences nothing; structured log lines from the bound
JN logger appear in test output. To run the benchmark with quiet
output, redirect stderr at the shell:

```sh
go test -run=^$ -bench=BenchmarkBinary_Cases ./cmd/network-api/ 2>/dev/null
```
