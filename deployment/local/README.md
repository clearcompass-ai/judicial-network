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
