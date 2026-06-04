# Judicial Network — Architecture & Component Reference

Evidence-based; every file/path verified against the working tree
(**baseproof SDK v1.14.0**; JN on the active feature branch). Aligns with the
Baseproof Architectural Principles (16 SDK · 15 Ledger · 14 Trust &
Equivocation Alignments · 10 Witness).

## 0. The one-sentence model

The baseproof SDK is the entire trust engine (identity, entry build,
cosignature, Merkle proofs, gossip, verify); the JN is the judicial domain
wrapped around it; the standalone-witness is an SDK signing oracle the
ledger drives; auditors (including JN itself) re-derive every claim locally
from the cosigned root, trusting no server.

## 1. System topology (4 actors)

```
standalone-witness     ledger (baseproof-backed)         JN network-api            auditors
(signing oracle)       (sequencer + transparency)      (domain + zero-trust)     (anyone/light)
POST /v1/cosign  ◄───  witnessclient.RequestCosignatures
  secp256k1 sign       assembles K-of-N CosignedTreeHead
                       serves /v1/gossip,/v1/tree/head,
                       /v1/entries,tiles ─────────────► topology.PeerPuller (pull)
                       gossipfeed (serve) ────────────► pull /v1/gossip/since
                                  api/exchange ───────► POST entry (SDK log client)
```

## 2. SDK ↔ JN boundary

JN imports ~30 SDK packages. JN never implements crypto, Merkle, cosignature,
or proof logic — it consumes SDK verdicts and SDK vocabulary (SDK Principle 1).
The v1.14.0 `WitnessPublicKey.SchemeTag` change touched only JN test fixtures,
not JN logic.

| Concern | SDK (baseproof) | JN (domain) |
|---|---|---|
| Identity | `did`, `network`, `crypto/signatures` | `did` (vendor mappings only), `api/exchange/keystore/*`, `api/exchange/auth` |
| Entry build/sign | `core/envelope`, `builder`, `crypto/admission`, `crypto/sct` | `cases,appeals,parties,delegation,escrow,operations,onboarding,migration,consortium,schemas,prerequisites,policy,jurisdiction` |
| State & proofs | `core/smt`, `core/vss` | (consumes only) |
| Witness cosign | `crypto/cosign`, `witness` | `crosslog`, `verification/witness_set_registry.go` |
| Gossip/transparency | `gossip`, `gossip/findings` | `gossipfeed`, `topology`, `judicialfindings`, `monitoring`, `equivocation` |
| Verify/audit | `verifier`, `attestation`, `delegation` | `verification`, `enforcement`, `api/verification`, `api/judicial` |
| Artifacts/escrow | `crypto/artifact`, `crypto/escrow`, `lifecycle/artifact` | `cases/artifact`, `escrow` |
| Ledger I/O | `log`, `storage`, `monitoring` (Alert vocab) | `api/exchange`, `api`, `api/middleware` |

## 3. Deployable services & HTTP surface

| Service | Entrypoint | Surface |
|---|---|---|
| Network API | `cmd/network-api/main.go` | exchange (write) + verification (read) + judicial + gossip serve; inbound gossip puller; equivocation scanner; monitoring scheduler |
| Aggregator | `tools/aggregator/cmd/aggregator/main.go` | relational projection (CQRS read-side) |
| Court Tools | `tools/court-tools/cmd/court-tools/main.go` | dockets, filings, orders, sealing, officers |
| Provider Tools | `tools/provider-tools/cmd/provider-tools/main.go` | records, documents, search, background-check |
| Judicial CLI | `cmd/judicial-cli/main.go` | keygen, onboard, submit, read |
| Deployment tooling | `cmd/{add-destination,add-destination-fields,verify-destination}` | jurisdiction bundles |

### 3.1 Route inventory (verified at file:line)

- **Exchange (write)** `api/exchange/server.go:126-153`: `POST /v1/entries/{build,sign,submit,build-sign-submit}`, `GET /v1/entries/status/{hash}`, `POST /v1/artifacts/publish`, `POST /v1/artifacts/{cid}/grant`, `POST /v1/delegations`, `DELETE /v1/delegations/{did}`, `POST /v1/keys/{generate,rotate,escrow}`, `GET /v1/keys`, `POST|GET /v1/dids`, `POST /v1/scope/{propose,approve/{pos},execute/{pos}}`.
- **Verification (read)** `api/verification/server.go:123-140`: `GET /v1/verify/{origin,authority,delegation,complete}/{logID}/{pos}`, `GET /v1/verify/batch/{logID}/{positions}`, `POST /v1/verify/{cross-log,fraud-proof,consistency}`. The cross-log handler is `api/verification/handlers/verify_cross_log.go`.
- **Judicial** (68 routes) `api/judicial/{appeals,artifacts,cases,consortium,delegation_topology,enforcement,monitoring,escrow,onboarding,parties}.go`.
- **Gossip serve** `/v1/gossip/*` via SDK `gossip.NewFeedHandler` (`gossipfeed/handler.go:77`, mounted `api/server.go:104`).
- **court-tools** `tools/court-tools/server.go:37-56` (15 routes; `POST /v1/cases`, `GET /v1/cases/{docket}[/timeline]`, filings/orders/seal/unseal/expunge — there is no `GET /v1/cases` list route).
- **provider-tools** `tools/provider-tools/server.go:33-41` (`GET /v1/records/{search,{docket},{docket}/documents,{docket}/documents/{cid}}`, `POST /v1/background-check`, `GET /v1/verify/{entry,delegation}/…`).
- **standalone-witness** `/v1/cosign` (+`/v2`) `internal/serve/serve.go:127-138`.

## 4. Subsystems

- **Transparency / zero-trust ingest** — `gossipfeed/{handler,sink,signer,postgres_store,metrics}.go`; `topology/{peer_client,anchor_publisher,discovery,…}.go`; `judicialfindings/{contracts,decode,router}.go`; `verification/{verify_gossip,witness_set_registry,tile_mirror}.go`; `monitoring/{scheduler,gossip_reconciler,*_consistency,*_freshness,*_compliance,…}.go`; `equivocation/{scanner,slasher}.go`; `crosslog/{anchor,witness_sets,hop_dispatch}.go`.
- **Verification & domain-rule engine** — `verification/` (authority/role, custody chains, cosignature/attestation, sealing/status/appeals) + `api/verification/handlers/`.
- **Identity & custody** — `did/mappings.go` only (DID resolution is the SDK's, wired in `cmd/network-api/judicial_deps.go::buildDIDResolver`); `api/exchange/keystore/{pkcs11,vault}/` subpackages (all secp256k1); `api/exchange/auth/*`; `consortium/*`.
- **Domain schemas** — `schemas/` (28 files). `appellate_disposition.go` is a schema (not enforcement code).

## 5. JN ↔ standalone-witness (indirect — JN verifies, never collects)

Witness signs `types.TreeHead` under `PurposeTreeHead` (`cosign.NewECDSAWitnessSigner`); the ledger collects K-of-N via `witnessclient.RequestCosignatures`; JN re-verifies K-of-N via `cosign.Verify` against its own `verification.WitnessSetRegistry`. Rotation: WITROT finding → `witness.VerifyRotation` → `ApplyVerifiedRotation` (verify-before-swap, monotonic). JN's only witness-endpoint use is `witness.TreeHeadClient` as a fallback read source.

## 6. Auditors (symmetric zero-trust)

JN exposes `/v1/gossip/since` (ETag/Cache-Control), `/v1/verify/*`, and (via ledger) `/v1/tree/head`, `/v1/entries/{seq}/raw`, tiles. An auditor runs SDK primitives: `gossip.Verify` → `cosign.Verify` → `core/smt`+RFC-6962 → `verifier`+`attestation`+`delegation` → `witness.DetectEquivocation`. JN itself is a full auditing node via `topology.PeerPuller` + `verification.GossipVerifier` + `equivocation`/`monitoring`.

## 7. Principle alignment (Trust & Equivocation Alignments → JN anchors)

| Alignment | JN anchor | ✓ |
|---|---|---|
| A1/A2/A4 STH + K-of-N | `verification/witness_set_registry.go` + `cosign.Verify` | ✓ |
| A3 topology rotation | `ApplyVerifiedRotation` (`monitoring/gossip_reconciler.go`) | ✓ |
| A5 Open/Closed | `judicialfindings/router.go` | ✓ |
| A6 Parse-don't-validate | `/v1/verify/complete` (LeafReader+LogQueries) | ✓ |
| A7 Equivocation | `equivocation.Scanner` (started in `main.go`) | ✓ |
| A8 SplitID sentry | `judicialfindings/decode.go` | ✓ |
| A9/A10 domain sep / Purpose≠Kind | gossip `PurposeGossipEventV1` | ✓ |
| A11 Pull gossip | serve `/v1/gossip/since`; `topology.PeerPuller` | ✓ |
| A12 Non-blocking sinks | `gossipfeed.Publisher` over `gossip.BufferedSink` | ✓ |
| A13 Idempotent consistency | `gossipfeed.PostgresStore.Append` | ✓ |
| A14 Error dimensionality | `gossipfeed/metrics.go` | ✓ |

## 8. Status — gaps closed this cycle

All previously-listed gaps are now wired (config-gated, off by default, so dev/test boots stay dependency-free):

| Former gap | Resolution | Anchor |
|---|---|---|
| `/v1/verify/complete` not wired | LogQueries + LeafReader threaded | `cmd/network-api/main.go` |
| Equivocation scanner not started | `equivocation.Scanner` run under signal ctx | `cmd/network-api/equivocation_scanner.go` |
| ClassMerkle/XLOG-INCL tile mirrors | wired into the gossip reconciler | `cmd/network-api/gossip_reconciler.go` |
| Monitoring loops not started | `monitoring.Scheduler` ticker engine | `monitoring/scheduler.go` |
| Gossip store in-memory | durable `PostgresStore` (serve + inbound) | `gossipfeed/postgres_store.go` |
| v1.14.0 adoption | `go.mod` at v1.14.0; fixtures declare `SchemeTag` | `go.mod` |

### 8.1 Activation & validation notes
- **Separation of Duties (Phase C):** custody (the durable gossip store) and equivocation detection have MOVED to the external auditor service; the JN runs **verify-only** — it pulls the auditor's `/v1/gossip` feed (`API_GOSSIP_INGEST_PEER_URL`) and re-verifies every event, hosting no store / feed / scanner of its own. The monitoring scheduler (mirror/anchor/sealing audits) stays in the JN, gated by `Monitoring.Enabled` + per-court audit specs.
- The mirror/anchor/sealing scheduler adapters reuse the pre-tested `Check*` funcs but need a deploy-time smoke test against a live ledger.

## 9. Running the stack locally

The whole realistic stack comes up with **one command** — witnesses → ledger →
auditor → aggregator → JN, each health-checked in dependency order:

```bash
make clarity-up        # or: ./e2e/clarity_e2e.py up
make clarity-status    # probe what's currently up
make clarity-down      # tear it all down (clears stale processes + WAL locks)
```

Runtime Separation of Duties — three distinct stores, one per role:

| Role | Launcher | Custody | Port |
|---|---|---|---|
| **auditor** (evidence custodian + detection) | `deployment/local/docker-compose.auditor.yml` | own Postgres; serves `/v1/gossip` | :8088 |
| **aggregator** (rebuildable read-projection) | `deployment/local/docker-compose.aggregator.yml` | own Postgres; self-migrating | :8092 |
| **JN** (enforcer, verify-only) | `scripts/run-jn.sh` | **none** — pulls + re-verifies the auditor's feed | :8443 (mTLS) |

The JN reads its verify-only ingest source from `API_GOSSIP_INGEST_PEER_URL` (the
auditor's `/v1/gossip`); it holds no store, serves no feed, runs no scanner.

## 10. Discovering the witness/network trust from env

The JN discovers its shared trust ROOT — the network bootstrap document
(→ NetworkID + witness keysets) — from env, consuming the **same** var the
standalone-witness fleet emits, so one `eval` feeds the ledger AND the JN:

```bash
# 1. stand up the fleet (standalone-witness repo) and load its env:
(cd ../standalone-witness && ./scripts/run-local.sh --witnesses 5 --port-base 19001)
eval "$(cd ../standalone-witness && make -s print-env)"   # sets LEDGER_NETWORK_BOOTSTRAP_FILE (+ LEDGER_WITNESS_*)

# 2. run the JN in the SAME shell — it auto-discovers the bootstrap doc:
./bin/network-api -config <config.json>
#   precedence: API_NETWORK_BOOTSTRAP_FILE > LEDGER_NETWORK_BOOTSTRAP_FILE > config JSON
```

`ApplyEnvOverrides` reads `API_NETWORK_BOOTSTRAP_FILE` (explicit) and falls
back to `LEDGER_NETWORK_BOOTSTRAP_FILE` (the fleet-emitted var). Byte-identical
bootstrap ⇒ identical NetworkID + witness keyset across ledger, witnesses, and
JN — the precondition for cross-component cosignature verification.

**Slice boundary (why the JN discovers *only* the bootstrap):** the JN
*verifies* cosigned heads; it never *collects* them, so it has no use for
`LEDGER_WITNESS_ENDPOINTS`, and K is encapsulated inside each `WitnessKeySet`
(Two-Tier Quorum Encapsulation), not a flat env knob. The per-log witness
*topology* (`Witness.Sets`) and gossip *peers* (`GossipIngest.Peers`) remain
deployment config — they are topology, not a fleet-emitted trust value.

## 11. Zero-trust auth posture (no backdoor — even in dev)

There is **no no-auth path**, by construction:

- `config.Validate` **rejects** `auth.mode=""` (`operational.go` — *"Auth.Mode required (mtls|jwt)"*). The binary cannot boot unauthenticated.
- mTLS is **hard**: the composer listener sets `tls.RequireAndVerifyClientCert` (`api/server_helpers.go`) — a request without a CA-verified client cert fails the TLS handshake before any handler runs. The caller DID is lifted from the verified leaf cert's `did:` URI SAN (`api/middleware/mtls.go`, `ExtractDIDFromCert`, unit-tested).
- The exchange's `VerifyClientCertIfGiven` is **not** a backdoor: it is paired with mandatory signed-request auth — a call is authenticated by a client cert **or** a request signature (verified against the caller's DID), never anonymously. TLS 1.3 floor throughout.
- `keystore.backend=memory` is **key custody**, not an auth axis — it controls where the JN's *own* secp256k1 keys live (ephemeral in dev), and is orthogonal to caller authentication. `memory` keystore still runs full mTLS.

Dev uses **real certificates**, same code path as production — only the CA is local:

```bash
make dev-certs CALLER_DID=did:web:state:tn:davidson   # → .run/certs/{ca,server,client}.{crt,key}
# wire into config.auth: mode=mtls, client_ca_file/tls_cert_file/tls_key_file = .run/certs/...
# every call presents the client cert (its did: SAN = the caller):
curl --cacert .run/certs/ca.crt --cert .run/certs/client.crt --key .run/certs/client.key \
     https://localhost:<port>/healthz
```

Generator: `scripts/gen-dev-certs.sh` (ECDSA P-256, chain-verified, `did:` URI SAN). The protocol's secp256k1 cosign keys are a separate concern (witness fixtures / keystore) — these are transport certs only.
