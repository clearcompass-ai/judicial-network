# Local deployment for the walkthrough

This directory holds the JN-side compose + Dockerfiles the
walkthrough at [`docs/walkthrough/`](../../docs/walkthrough/) uses.

## Two-layer topology

The walkthrough exercises a complete dev-laptop deployment:

| Layer | What | Where it boots from | Endpoints |
|---|---|---|---|
| Protocol | Two ledgers + Postgres | LEDGER repo's `deployment/local/docker-compose.dev.yml` | `:8080` (Davidson trial), `:8081` (TN COA) |
| Application | JN-side tools | THIS repo's `deployment/local/docker-compose.walkthrough.yml` | `:8090` (court-tools), `:8091` (provider-tools) |
| CLI | `judicial-cli` | `make install-bins` (lands in `./bin/`) | shell |

Both layers connect to the same Postgres (the protocol layer brings
it up; the application layer reuses it).

## Boot order

```sh
# 1. Protocol layer (from the LEDGER repo)
cd ~/clarity/ledger
make dev-up

# 2. Application layer (from THIS repo)
cd ~/clarity/judicial-network
make walkthrough-up

# 3. Then continue at docs/walkthrough/01-environment.md.
```

## Run the `network-api` server locally

`make walkthrough-up` boots the JN *tools* layer (court-tools / provider-tools)
in Docker. To run the JN **edge server** (`cmd/network-api`) itself against a
local ledger — without standing up a second compose topology — use
`make run-local`. It runs the binary directly and takes every **reference URI
from an env var** (localhost defaults), so nothing is baked into a committed
config.

```sh
# 1. Bring up a reference ledger (LEDGER repo) — node-a on :8080.
make -C ../ledger integration-up      # offline fake-gcs; or: make -C ../ledger dev-up

# 2. Run the JN edge against it.
make run-local                        # → ledger=http://localhost:8080  listen=:8443

# 3. Confirm it's serving (plain HTTP in the dev profile).
curl -s localhost:8443/healthz        # → ok
curl -s -o /dev/null -w '%{http_code}\n' localhost:8443/readyz   # 200 once ledger is reachable
```

### Reference URIs (env)

Every URI is an `API_*` env var the binary reads (`api/config` `ApplyEnvOverrides`).
Set them inline or `export` them before `make run-local`:

| Env var | Sets | Default |
|---|---|---|
| `API_LISTEN_ADDR` | server listen address | `:8443` |
| `API_LEDGER_ENDPOINT` | upstream ledger base URL | `http://localhost:8080` |
| `API_ARTIFACT_STORE_ENDPOINT` | artifact store base URL | `http://localhost:8002` |
| `API_VERIFICATION_ENDPOINT` | upstream verification service base URL | `http://localhost:8080` |
| `API_NETWORK_BOOTSTRAP_FILE` | path to the network bootstrap doc (cosign NetworkID) | _(unset)_ |
| `API_KEYSTORE_BACKEND` | `memory` \| `softhsm` \| `vault` | `memory` |
| `API_AUTH_MODE` | `mtls` \| `jwt` | from the dev config (`jwt`) |

```sh
# Point at ledger node-b and a different listen port:
API_LEDGER_ENDPOINT=http://localhost:8081 API_LISTEN_ADDR=:8543 make run-local
```

### Dev config (non-URI knobs)

`deployment/local/api.dev.json` carries only what is **not** a reference URI:
auth mode (`jwt` → the server runs plain HTTP, no TLS certs needed) plus a
placeholder issuer/JWKS. Keystore + nonce store fall back to the in-memory
defaults. Protected routes return 401 without a real token — `/healthz`,
`/readyz`, `/metrics` need none. Override the file with `API_DEV_CONFIG=...`.

### Cross-log gossip (optional)

The inbound anti-entropy loop (pull peer feeds → verify → enforce) is **off by
default**. To exercise it locally, set `API_NETWORK_BOOTSTRAP_FILE` (env) and
add the list-valued reference URIs to a dev config — these are structured
lists, so they live in JSON, not env:

```jsonc
{
  "auth": { "mode": "jwt", "jwt_issuer": "https://localhost/dev-issuer", "jwks_url": "http://localhost:9301/jwks.json" },
  "witness": {
    "sets": [ { "log_did": "<peer-log-did>", "witness_dids": ["did:key:..."], "quorum_k": 1 } ]
  },
  "gossip_ingest": {
    "enabled": true,
    "peers": [ { "log_did": "<peer-log-did>", "base_url": "http://localhost:8080" } ],
    "tile_mirrors": [ { "log_did": "<peer-log-did>", "base_url": "http://localhost:8080/" } ]
  }
}
```

## Versioning

| Component | Version |
|---|---|
| `judicial-network` | `v0.0.1` |
| `attesta` (Go SDK pin) | `v0.1.0` |
| `ledger` (HTTP service) | `v0.1.0` |

Run `make version` from the repo root to see the live values
(`attesta` is read from `go.mod`; the others are defaults).

## Tear-down

```sh
make walkthrough-down
cd ~/clarity/ledger && make dev-down
```

`make walkthrough-down` deletes the JN tools containers + named
volumes. The Postgres data volume lives with the LEDGER compose;
`make dev-down` over there clears the DBs.
