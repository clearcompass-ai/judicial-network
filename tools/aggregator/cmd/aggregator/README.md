# aggregator — standalone log aggregator

Polls the operator for new entries on the registered logs
(officers / cases / parties), classifies + indexes them into
Postgres, and exposes a small probe HTTP surface for k8s liveness
+ Prometheus scraping. Distinct from `court-tools --aggregator-only`:
this binary has **no read-side `/v1/*` query endpoints**. Query
traffic for the aggregator's Postgres state belongs in court-tools
or provider-tools, which can scale separately.

## Layered architecture

```
                        ┌──────────────────────────────────┐
                        │ ortholog-operator                 │
                        │ (Tessera + Postgres + tile store) │
                        └─────────────┬────────────────────┘
                                      │ poll /v1/entries
                                      ▼
       ┌───────────────────────────────────────────────────┐
       │ aggregator (this binary)                           │
       │   tools/aggregator.Scanner                         │
       │     classifies + indexes entries                   │
       │     scan watermark in Postgres                     │
       │   probe surface:                                   │
       │     GET /healthz   liveness                        │
       │     GET /readyz    operator + Postgres reachable   │
       │     GET /metrics   Prometheus (jn_http_*)          │
       └───────────────────────────────┬───────────────────┘
                                      │ writes
                                      ▼
                        ┌──────────────────────────────────┐
                        │ Postgres (aggregator database)   │
                        │   indexed entries + watermarks   │
                        └──────────────────────────────────┘
                                      ▲
                                      │ reads
       ┌──────────────────────────────┴───────────────────┐
       │ court-tools / provider-tools (separate binaries)  │
       │   serve query endpoints over HTTP                 │
       └───────────────────────────────────────────────────┘
```

## Running

```sh
# CI / dev: in-memory Postgres for round-trip smoke (see main_test.go)
go test -race ./tools/cmd/aggregator/...

# Build the binary
go build -o ./bin/aggregator ./tools/cmd/aggregator

# Production: takes a tools/common.Config JSON file
./bin/aggregator --config /etc/jn/aggregator.json --listen-addr :8092
```

## Configuration

Reuses `tools/common.Config`. The aggregator binary requires:

| Field | Purpose |
|---|---|
| `operator_url`              | Operator HTTP endpoint to poll. Required. |
| `database_url`              | Postgres DSN for the aggregator's local store. Required. |
| `cases_log` / `officers_log` / `parties_log` | DIDs of the logs to scan. |
| `aggregator_poll_interval`  | Polling cadence (default 5s). |
| `aggregator_batch_size`     | Entries per scan batch (default 100). |

Other fields on `tools/common.Config` (exchange URL, court SSO
issuer, provider API key header) are unused by this binary —
they're consumed by court-tools / provider-tools.

## Probes

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness. Always 200. k8s restarts on failure. |
| `GET /readyz`  | Readiness. 200 only when Postgres + operator are both reachable; 503 otherwise. k8s removes from service when readyz drops. |
| `GET /metrics` | Prometheus scrape. Emits `jn_http_*` (same conventions as `cmd/network-api`). |

The probes are unauthenticated — k8s pods + Prometheus scrapers
need them to be reachable without credentials. The probe server
listens on a separate address from upstream services so it can be
firewalled to the cluster network.

## Operating

**Scale read-side independently.** This binary's job is one-way
write-side ingestion. Read-side query throughput (court-tools,
provider-tools) is a separate concern; they read from the same
Postgres but can horizontally scale on their own deployment cycle.

**Watermark recovery.** The aggregator stores per-log scan
watermarks in `scan_watermarks` (see `tools/aggregator/schema.sql`).
A restart resumes from the last persisted watermark — no manual
catch-up required. A failed scan retries on the next poll
interval; entries are idempotently re-classified.

**Database availability.** `--readyz` returns 503 when Postgres is
unreachable. Replicas should be configured with a generous
liveness threshold so a transient outage doesn't kill them, but
removed from service quickly via readyz so traffic doesn't queue
on a dead replica.

**Operator availability.** Same model — readyz drops when the
operator is unhealthy. The Phase 14 reliability primitives
(circuit breaker, etc.) live in `cmd/network-api`'s write path;
the aggregator's read path uses the bare HTTP poll.

## Tests

| Test | What it pins |
|---|---|
| `TestParseFlags_Defaults` / `_Override` | flag parsing |
| `TestRun_RejectsEmptyDatabaseURL` / `_OperatorURL` | config validation |
| `TestRun_BootShutdownRoundTrip` | scanner goroutine starts, probe server reachable, SIGINT triggers graceful shutdown |
| `TestProbes_Healthz_AlwaysOK` | liveness independent of upstream health |
| `TestProbes_Readyz_HappyPath` / `_DBDown_503` / `_OperatorDown_503` | readiness gates traffic correctly |
| `TestProbes_Metrics_Reachable` | `/metrics` mounted, registry serves OpenMetrics |
| `TestProbes_UnknownPath_404` | aggregator has no `/v1/*` routes by design |

All tests run with `-race`; the package is independently
buildable + testable from the `tools/cmd/aggregator/` directory.
