# §03 · Boot the JN tools (court-tools + provider-tools)

So far the walkthrough's "running app" is two operators + a CLI. The
operator is the protocol layer; `judicial-cli` is one client. The
**JN tools** are the application-layer HTTP services every real
courthouse deployment runs alongside the operator:

| Binary | Port | Purpose |
|---|---|---|
| `court-tools` | `:8090` | Authenticated REST API used by court personnel (clerks, judges) for case lookup, filings, sealing/unsealing, officer roster. Also runs an in-process **aggregator** goroutine that polls the operator and caches sequenced entries into Postgres. |
| `provider-tools` | `:8091` | Public-records read-only REST API. Background-check, document-list, search-by-docket. Reads the same Postgres cache court-tools' aggregator populates. **Never touches the exchange** — read-only by design. |

Booting both is a one-time setup step. After that, you can re-run
the walkthrough cases (§01–§02 → cases) and watch the aggregator
populate `court_tools.cases` etc. as entries land on the operator.

## What's in scope here vs. what isn't

In scope:
- **court-tools + provider-tools binaries** — real Go HTTP servers,
  same code path as a production deployment.
- **The third Postgres database** (`court_tools`) — already
  created by the operator's `make dev-up` (see
  `deployment/local/postgres-init.sh`). The aggregator's schema
  (`tools/aggregator/schema.sql`) lands on first connect via
  `CREATE TABLE IF NOT EXISTS`.

Out of scope for v1 of this walkthrough:
- **artifact-store** — document fetch/grant endpoints proxy to it.
  When unreachable, the providers HTTP server returns HTTP 502 to
  the caller (graceful degradation; no panic). Document-list and
  search work; document-fetch returns 502.
- **Exchange service** — court-tools' write endpoints (POST
  /v1/cases, POST /v1/filings) route through the exchange. We
  don't run an exchange binary in the dev topology, so write
  endpoints will surface a 502 from court-tools. Reads work fully
  via the aggregator. Use `judicial-cli submit` for entry writes
  in the meantime — `judicial-cli` talks directly to the operator,
  bypassing the exchange.

The walkthrough's two cases ([Case 1](cases/01-acme-v-beta.md),
[Case 2](cases/02-in-re-anderson.md)) submit through
`judicial-cli` (no exchange dependency) and then the aggregator
inside court-tools picks them up from the operator.

## 1. Confirm the `court_tools` database exists

This was created by the operator's `make dev-up` (the
`postgres-init.sh` mounted at first boot of the postgres
container). Verify:

```bash
$ docker exec ortholog-dev-postgres \
    psql -U ortholog -l | grep court_tools
 court_tools | ortholog | UTF8 | ...
```

If `court_tools` is missing — typically because you brought up
the topology before this walkthrough section landed — run
`make dev-down && make dev-up` from the operator repo to
re-trigger the init script. (`dev-down` deletes Postgres
volumes; `dev-up` re-runs the init.)

## 2. Build the two binaries

```bash
cd ~/ortholog/jn
go build -o ~/.local/bin/court-tools     ./tools/cmd/court-tools
go build -o ~/.local/bin/provider-tools  ./tools/cmd/provider-tools

court-tools     -h    # prints flags
provider-tools  -h    # prints flags
```

## 3. Use the walkthrough's pre-built config

The walkthrough ships a config tuned for our topology:
operator on `:8080`, court_did = `did:web:state:tn:davidson`,
the right Postgres URL, no exchange:

```bash
cat ~/ortholog/jn/docs/walkthrough/config/tools.dev.json
```

That file is what `-config` accepts. (Env-var overrides via
`TOOLS_*` take precedence; useful for tweaks without editing JSON.)

## 4. Start court-tools

In one terminal:

```bash
cd ~/ortholog/jn
court-tools -config docs/walkthrough/config/tools.dev.json
```

You should see:

```
aggregator: started (poll=5s, batch=100)
court-tools: listening on :8090
```

Sanity from a second terminal:

```bash
$ curl -fsS http://localhost:8090/healthz
ok
```

The aggregator is now polling Davidson on `:8080` every 5 seconds
and inserting any newly-sequenced entries into `court_tools` →
`cases`, `case_events`, `officers`, etc. With the operator
currently empty (or full of walkthrough entries from a prior
run), it'll either be a no-op or backfill the existing log.

## 5. Start provider-tools

In a third terminal:

```bash
cd ~/ortholog/jn
provider-tools -config docs/walkthrough/config/tools.dev.json
```

You should see:

```
provider-tools: listening on :8091
```

Sanity:

```bash
$ curl -fsS http://localhost:8091/healthz
ok
```

provider-tools does not run an aggregator — it reads from the
Postgres cache court-tools populates. Running both pointed at the
same database is exactly the production shape: `court-tools` on a
private network for court personnel; `provider-tools` on a public
endpoint for records lookups. They share one Postgres because
read-after-write consistency matters for the public-records
guarantee.

## 6. Watch the aggregator backfill

Walk through Case 1 in another terminal (while `court-tools` is
running). After each `judicial-cli submit` step, wait a few
seconds and query the aggregator's cache:

```bash
$ curl -fsS http://localhost:8090/v1/cases | jq '.[] | .docket_number'
"2024-CV-001"
```

The case shows up in the cache after the aggregator's next poll
(default 5s). The same docket is queryable through provider-tools
on `:8091` — different surface, same data:

```bash
$ curl -fsS \
    -H "X-API-Key: $(your-dev-key)" \
    http://localhost:8091/v1/records/search?q=ACME
{"results":[{"docket_number":"2024-CV-001",...}]}
```

(Replace `your-dev-key` with whatever auth your team uses; the
walkthrough doesn't ship a real key. provider-tools' API-key
middleware can be no-op'd in dev by leaving the header unset
in dev mode — see `tools/providers/server.go` for the gate.)

## 7. End-state recap

After §03 you have **five processes** running:

| Process | Port | Repo |
|---|---|---|
| `operator-davidson` | `:8080` | ortholog-operator (docker) |
| `operator-coa` | `:8081` | ortholog-operator (docker) |
| `postgres` | `:5432` | ortholog-operator (docker) |
| `court-tools` | `:8090` | judicial-network (host) |
| `provider-tools` | `:8091` | judicial-network (host) |

Plus your gcloud ADC pointing at two real GCS buckets.

This is the **whole judicial-network app running on your laptop**
as far as the dev topology is concerned. The exchange service +
artifact-store + Privy are the remaining pieces; they're tracked
separately as future walkthrough additions.

## Trouble?

| Symptom | Likely cause | Fix |
|---|---|---|
| `database unavailable: dial tcp ...` | court_tools DB doesn't exist | `make dev-down && make dev-up` in operator repo |
| court-tools runs but `/v1/cases` returns 503 | DB connection failed at startup | Check the WARN line in court-tools output; likely your DATABASE_URL is wrong |
| Aggregator logs `operator: 404 not found` | OperatorURL is misconfigured | Either your `tools.dev.json` points elsewhere or the operator isn't running |
| `502 Bad Gateway` on POST /v1/cases | exchange service not running (expected) | Use `judicial-cli submit` instead — see §02 onward |
| `502 Bad Gateway` on GET /v1/records/{docket}/documents/{cid} | artifact-store not running (expected) | Out of scope for this walkthrough |

## Next

Cases unchanged from the previous version — start with
[Case 1: ACME v. Beta](cases/01-acme-v-beta.md). The cases now
have an extra layer of observability: every entry the cases
submit will appear in `court-tools` and `provider-tools` queries
within ~5 seconds of landing on the operator.
