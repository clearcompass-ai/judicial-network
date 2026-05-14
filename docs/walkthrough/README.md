# Judicial Network — Developer Walkthrough

A curl-and-CLI walkthrough of two real Tennessee judicial cases that
exercises the system end-to-end: two running ledgers, real
secp256k1 DIDs, and a cross-exchange appeal that physically moves a
signed entry from one ledger to another.

This is not a tour of API surface. It's a story about what happens
when the gears actually turn — what the entries *mean* legally, why
each signature is required, what the log permits and forbids — paired
with the exact commands that produce each step on your laptop.

## Version compatibility

| Component | Version | Source |
|---|---|---|
| `judicial-network` (this repo) | `0.0.1` | `make version` |
| `attesta` (SDK Go module) | `v1.5.2` | `go.mod` require line |
| `ledger` (HTTP service binary) | `main` | `clearcompass-ai/ledger` repo |

attesta v1.5.2 ships three changes that this walkthrough exercises:

- **v1.4.0** — `verifier.VerifyComplete` gained Stage 6
  (`PolicyStageParams`). The JN endpoint
  `/v1/verify/complete/{logID}/{pos}` drives this stage when
  `JN_VERIFY_POLICY_STAGE_ENABLE=true`.
- **v1.5.0** — `AttestationPolicy.AdmissionEnforced bool` is the
  schema-declared evaluation point. JN's schemas declare every
  policy `AdmissionEnforced=false` (async / read-time); the SDK
  fixture-discipline test (v1.5.1) pins this invariant.
- **v1.5.2** — `crypto/signatures.SignEntry` is now RFC 6979
  deterministic. Re-signing the same envelope produces
  byte-identical bytes; the ledger's `log_time_micros` replay
  branch dedupes retries without false-positive drift.

The walkthrough's commands assume those three components match. If
you're on a fork or branch that bumps any of them, expect minor
drift in the response shapes (the wire format itself is stable
within a major).

## What you'll do

| | Case | Court(s) | Actors | Why this case is in the walkthrough |
|---|---|---|---|---|
| 1 | ***ACME Industries v. Beta Corp*** | Davidson Trial → TN COA | 5 | A civil contract dispute that gets appealed. **The appeal physically crosses ledgers.** The COA's appellate-disposition entry carries an `EvidencePointers` reference back to the trial-court entry, demonstrating cross-exchange composition end-to-end. |
| 2 | ***In re Anderson*** | Davidson Family → Davidson Juvenile (judicial succession) | 4 | A custody case where a sealed minor binding, a cross-division judicial succession, and a delegation revocation all land on the same log. Single exchange, but exercises the most complex authority-graph operations. |

5 unique actors total (the clerk appears in both cases). Every DID is
a real secp256k1 keypair you generate yourself in §02.

## DID methods you'll use

The walkthrough exercises **two** real DID methods, mapped to **three
actor tiers** per [Event Dictionary v1.8 Part 1](../event_dictionary_v1.8.md):

| Tier | v1.8 label | Examples | DID method | Web3 wallet? |
|---|---|---|---|---|
| **T1** | Signer | Adjudicators, Clerks, Court Reporters | `did:key` | No (institutional key) |
| **T2** | Filer | Civil Attorneys, Prosecutors, Defense Counsel, Fiduciaries | `did:key` (court capacity) | Optional (personal capacity) |
| **T3** | Party | Plaintiffs, Defendants, Respondents, the State | Strictly v1.8 = no DID; JN adoption-overlay extension allows `did:pkh:eip155:*` for parties that already hold a wallet | **Yes (recommended for key players)** |

- **`did:key`** (W3C-spec multibase form) — institutional court keys.
- **`did:pkh:eip155:<chainId>:0x<addr>`** (CAIP-10 form) — wallet
  identities. **Multi-chain by design**: chain id 1 = Ethereum
  mainnet, 137 = Polygon, 10 = Optimism, 8453 = Base, 42161 =
  Arbitrum. The walkthrough enrolls four party-principal wallets
  across four different EVM chains to demonstrate that the protocol
  admits all of them identically.

Both are minted by `judicial-cli keygen` (just pass `--method
pkh-eip155 --chain-id <N>` for the wallet path); both verify through
the SDK's DID dispatcher. T3 wallet adoption is documented in §02 as
a JN extension to v1.8 — Parties are formally "Passive Metadata
Subjects" without DIDs, but a Party that already holds a wallet can
attach wallet-signed `evidence_artifact` acknowledgments as
authentication overlays. The `binding_id` minted by `party_binding`
remains the v1.8-mandated public reference.

## What's running

```
                    ┌────────────────────────────────────────────────┐
                    │  Your laptop                                    │
                    │                                                 │
                    │   ┌────────────────────┐  ┌────────────────────┐│
                    │   │  ledger-davidson │  │   ledger-coa     ││
       judicial-cli ────►   :8080            │  │   :8081            ││
                    │   │  did:web:state:tn: │  │  did:web:state:tn: ││
                    │   │  davidson          │  │  coa               ││
                    │   └─────────┬──────────┘  └────────┬───────────┘│
                    │             │                      │            │
                    │   ┌──────────┴────────────────┴──┐                │
                    │   │  Postgres (3 DBs)             │                │
                    │   │  davidson, coa, court_tools   │                │
                    │   └───────────────┬───────────────┘                │
                    │                   │                                │
                    │   ┌───────────────┴───────────────┐                │
                    │   │  court-tools     :8090        │                │
                    │   │  provider-tools  :8091        │                │
                    │   │  (HTTP services that read     │                │
                    │   │   the ledger and surface    │                │
                    │   │   case-workflow + public-     │                │
                    │   │   records APIs)               │                │
                    │   └───────────────────────────────┘                │
                    └────────────────┬─────────────────────────────────┘
                                     │
                                     ▼
                            storage.googleapis.com
                       (your real GCS buckets, your project,
                        your gcloud Application Default Creds)
```

The dev path uses **real GCS** in your own GCP project — same code
path as production, same IAM, same latency. For an offline /
no-cloud topology there's a separate
`docker-compose.integration.yml` with `fake-gcs-server`; the
walkthrough doesn't use that path.

Both ledgers are stock Attesta ledgers — domain-agnostic
"dumb writes" that admit signed canonical bytes, sequence them, and
serve them over HTTP. All judicial vocabulary lives in
`judicial-cli` and the JN schemas. **The ledgers don't know
what a `civil_case` is**, and that's the point.

## Folder layout

```
docs/walkthrough/
├── README.md                          ← you are here
├── 01-environment.md                  ← `make dev-up`: ledgers + Postgres + GCS
├── 02-real-dids.md                    ← mint 5 did:key + 2 did:pkh DIDs
├── 03-tools.md                        ← boot court-tools + provider-tools
├── config/
│   └── tools.dev.json                 ← config used by §03's two binaries
├── cases/
│   ├── 01-acme-v-beta.md              ← Civil + cross-exchange to COA
│   └── 02-in-re-anderson.md           ← Family → Juvenile succession + revocation
└── 99-coverage.md                     ← schema-event matrix
```

## Read in order

The first four sections (README + 01 + 02 + 03) bring the **whole
judicial-network app** up: two ledgers, Postgres, real GCS,
court-tools and provider-tools. After that, both case files are
independently runnable — start with whichever interests you.

(Two pieces are deliberately out of scope: the **artifact-store**
binary and the standalone **exchange service**. court-tools' write
endpoints and document-fetch endpoints will return 502 without
them; reads + `judicial-cli submit` work fully.)

## Time

| Stage | Time |
|---|---|
| `make dev-up` (cold, builds the ledger image) | 3–5 min |
| §01 environment verification | 1 min |
| §02 mint 5 + 2 DIDs | 1 min |
| §03 boot court-tools + provider-tools | 2 min |
| Case 1 walkthrough end-to-end | 15 min |
| Case 2 walkthrough end-to-end | 10 min |
| **Total first run** | **~35 min** |

Subsequent runs (after `make dev-down && make dev-up`) skip the
image build and finish in well under 15 minutes.

## What world-class means here

This walkthrough is not a wall of `curl` commands. Every step has:

- **A short narrative paragraph** explaining what's actually happening
  legally — who's signing, what authority they're acting under, why
  this entry needs to be on the log.
- **The exact command** to produce it (one line, copy-paste).
- **The expected response** so you know whether it worked.
- **A "what just happened" pointer** at the file:line of the schema
  or the ledger code that defines the contract you just exercised.

If at any point the technical noise overwhelms the narrative, you've
hit a documentation bug — open an issue and it gets fixed.

## Prerequisites

- Docker + Docker Compose v2 (`docker compose`, not `docker-compose`)
- Go 1.25+ (to build `judicial-cli` from source)
- About 1 GiB of free disk for Postgres + the ledger image (GCS storage lives in your GCP project, not on disk)
- A Google Cloud project + `gcloud` CLI installed, where you can create two buckets
- Ports 5432, 8080, 8081 free on your laptop

We won't ask you to install Privy SDKs, Cellebrite tools, or anything
exotic. Every primitive in this walkthrough is open-source and runs
locally.

## What this walkthrough does **not** cover

- **Privy embedded wallets.** The walkthrough uses local secp256k1
  keys you mint via `judicial-cli keygen`. The Privy code path is
  identical at the SDK seam (`identity.IdentityProvider`); swapping
  is a config change, not a rewrite.
- **Witness cosignatures on the tree head.** Each ledger
  self-signs checkpoints unwitnessed in dev mode.
- **Production sealing of artifacts.** The walkthrough surfaces
  `PartyBindingSealedPayload` shapes but uses placeholder
  `encrypted_mapping_cid` values.

These are deliberate omissions — they have their own walkthroughs
when those paths are ready to be exercised.

## Status

- SDK: `v1.5.2` (PRs #24-#27: AdmissionEnforced, Stage 6, RFC 6979 SignEntry)
- Ledger topology: `deployment/local/docker-compose.dev.yml` in
  the ledger repo (post PR #82/#83)
- CLI: `judicial-network/cmd/judicial-cli/`
- Branch: `main` (`claude/update-attesta-sdk-alignment-TOII0` for PR #26)

Ready? Open **[01-environment.md](01-environment.md)**.
