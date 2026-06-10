# Run the judicial network locally

One command brings up a REAL network on your machine — the released
`ghcr.io/baseproof/tooling` fleet (ledger + witnesses + auditors) plus this
repo's JN enforcer and aggregator — wired exactly like the federated
deployment: open-HTTPS ledger (self-signed run CA), mTLS JN edge, Mode A
credits seeded, witness-cosigned heads.

## Prerequisites

Docker, Go, `make`, `openssl` (the run CA + server/client certs are minted
per run).

## Bring a network up

```bash
make e2e                      # builds ./bin/e2e (the Go stack runner)
./bin/e2e up single           # 1 network: ledger + 3 witnesses (K=2) + 2 auditors + JN + aggregator
./bin/e2e up federation       # 3 networks (federal/tn/ca) with shared witnesses + auditors
./bin/e2e status              # ports, log DIDs, health — everything below comes from here
```

Each run persists its state (certs, fixtures, manifest) under the run root
(`E2E_RUN_ROOT` overrides the default, which lives beside the repo);
`status` prints the paths and host ports. `./bin/e2e list` shows runs;
`./bin/e2e wipe` tears one down.

## Read from it

The ledger serves OPEN HTTPS — verify its self-signed server cert against
the run CA, no client cert needed (reads are open; writes are gated by
in-body crypto):

```bash
CA=<run-dir>/certs/ca.crt          # path printed by `status`
curl --cacert $CA https://localhost:<ledger-port>/healthz
curl --cacert $CA https://localhost:<ledger-port>/v1/tree/head | jq .
```

The JN serves the network consumption manifest — the machine-readable
"how to consume this network" (operations DAG, signing roles, prerequisite
edges, endpoints, admission posture) — unauthenticated, beside its mTLS
surface:

```bash
curl --cacert $CA "https://localhost:<jn-port>/v1/network/bundle?destination=did:web:state:tn:davidson" | jq .
```

(The JN image is `ghcr.io/clearcompass-ai/judicial-network:latest`; the
manifest endpoint needs an image built from current `main` — override a
stale image with `E2E_JN_IMAGE=<your build>`.)

## Write to it

**Recipes** (the harness's own workloads, in-network with the right certs):

```bash
./bin/e2e run smoke               # seed + verify the basics
./bin/e2e run federation.load     # client load against every network
./bin/e2e run --list              # every registered recipe
```

**The released `baseproof` CLI** (one network per client bundle; Mode A
credits are pre-seeded on `up` — token `baseproof-mode-a`):

```bash
baseproof network add local --from-ledger https://localhost:<ledger-port> \
    --ca-cert $CA --quorum 2 --use
baseproof submit --payload 'hello court' --token baseproof-mode-a
baseproof proof --seq 1 --out entry1.proof && baseproof verify entry1.proof
```

**`judicial-cli`** for domain spec-file submissions and governance
(`keygen`, `submit --spec`, `publish-manifest` — the on-log publication of
the consumption manifest this network serves).

## The v0.1.9 fleet, in one paragraph

v0.1.9 auditors run the rotation-safety machinery ON BY DEFAULT:
journal-first era-aware witness-set resolution, bounded scan
reconciliation, boot-time anchor reconstruction, and the safety/liveness
consistency audit. One local-dev note: the frozen-log alarm WARNS when a
log's latest verified head is older than `AUDITOR_MAX_HEAD_AGE` (default
1h) — an idle stack warning after an hour is truthful liveness signal, not
a failure. Tune per run via env passthroughs (unset = image defaults):

| Env (host) | Tunes | Default |
|---|---|---|
| `E2E_AUDITOR_MAX_HEAD_AGE` | frozen-log warning bound (`0` disables) | `1h` |
| `E2E_AUDITOR_ROTATION_SCAN_INTERVAL` | journal scan-reconciliation cadence | image default |
| `E2E_AUDITOR_ROTATION_CONSISTENCY_INTERVAL` | safety/liveness audit cadence | image default |
| `E2E_AUDITOR_ROTATION_ADOPTION_GRACE` | rotation-adoption liveness window | `1h` |

Fleet pins live in `stack/config.go` (`E2E_LEDGER_IMAGE` /
`E2E_WITNESS_IMAGE` / `E2E_AUDITOR_IMAGE` override per run).
