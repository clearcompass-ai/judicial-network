# Judicial Network — Developer Walkthrough

A curl-and-CLI walkthrough of two real Tennessee judicial cases that
exercises the system end-to-end: two running operators, real
secp256k1 DIDs, and a cross-exchange appeal that physically moves a
signed entry from one operator to another.

This is not a tour of API surface. It's a story about what happens
when the gears actually turn — what the entries *mean* legally, why
each signature is required, what the log permits and forbids — paired
with the exact commands that produce each step on your laptop.

## What you'll do

| | Case | Court(s) | Actors | Why this case is in the walkthrough |
|---|---|---|---|---|
| 1 | ***ACME Industries v. Beta Corp*** | Davidson Trial → TN COA | 5 | A civil contract dispute that gets appealed. **The appeal physically crosses operators.** The COA's appellate-disposition entry carries an `EvidencePointers` reference back to the trial-court entry, demonstrating cross-exchange composition end-to-end. |
| 2 | ***In re Anderson*** | Davidson Family → Davidson Juvenile (judicial succession) | 4 | A custody case where a sealed minor binding, a cross-division judicial succession, and a delegation revocation all land on the same log. Single exchange, but exercises the most complex authority-graph operations. |

5 unique actors total (the clerk appears in both cases). Every DID is
a real secp256k1 keypair you generate yourself in §02.

## DID methods you'll use

The walkthrough exercises **two** real DID methods:

- **`did:key`** (W3C-spec multibase form). Used by court personnel
  whose identity isn't tied to an Ethereum wallet — clerks, judges,
  attorneys with bar-issued keys.
- **`did:pkh:eip155:<chainId>:0x<addr>`** (CAIP-10 form). Used by
  parties whose primary identity lives in an Ethereum-compatible
  wallet — corporate plaintiffs/defendants, outside witnesses,
  any actor who already has a wallet identity. Signs via EIP-191
  (the standard `personal_sign` flow every wallet implements).

Both are minted by `judicial-cli keygen` (just pass `--method
pkh-eip155` for the wallet path); both verify through the SDK's
DID dispatcher.

## What's running

```
                    ┌────────────────────────────────────────────────┐
                    │  Your laptop                                    │
                    │                                                 │
                    │   ┌────────────────────┐  ┌────────────────────┐│
                    │   │  operator-davidson │  │   operator-coa     ││
       judicial-cli ────►   :8080            │  │   :8081            ││
                    │   │  did:web:state:tn: │  │  did:web:state:tn: ││
                    │   │  davidson          │  │  coa               ││
                    │   └─────────┬──────────┘  └────────┬───────────┘│
                    │             │                      │            │
                    │   ┌──────────┴────────────────┴──┐                │
                    │   │  Postgres (2 DBs)             │                │
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

Both operators are stock Ortholog operators — domain-agnostic
"dumb writes" that admit signed canonical bytes, sequence them, and
serve them over HTTP. All judicial vocabulary lives in
`judicial-cli` and the JN schemas. **The operators don't know
what a `civil_case` is**, and that's the point.

## Folder layout

```
docs/walkthrough/
├── README.md                          ← you are here
├── 01-environment.md                  ← `make dev-up`; verify both operators
├── 02-real-dids.md                    ← mint 5 secp256k1 DIDs with judicial-cli
├── cases/
│   ├── 01-acme-v-beta.md              ← Civil + cross-exchange to COA
│   └── 02-in-re-anderson.md           ← Family → Juvenile succession + revocation
└── 99-coverage.md                     ← schema-event matrix
```

## Read in order

The first three files (README + 01 + 02) are setup. After that, both
case files are independently runnable — start with whichever
interests you.

## Time

| Stage | Time |
|---|---|
| `make dev-up` (cold, builds the image) | 3–5 min |
| §01 environment verification | 1 min |
| §02 mint 5 DIDs | 30 sec |
| Case 1 walkthrough end-to-end | 15 min |
| Case 2 walkthrough end-to-end | 10 min |
| **Total first run** | **~30 min** |

Subsequent runs (after `make dev-down && make dev-up`) skip the image
build and finish in well under 10 minutes.

## What world-class means here

This walkthrough is not a wall of `curl` commands. Every step has:

- **A short narrative paragraph** explaining what's actually happening
  legally — who's signing, what authority they're acting under, why
  this entry needs to be on the log.
- **The exact command** to produce it (one line, copy-paste).
- **The expected response** so you know whether it worked.
- **A "what just happened" pointer** at the file:line of the schema
  or the operator code that defines the contract you just exercised.

If at any point the technical noise overwhelms the narrative, you've
hit a documentation bug — open an issue and it gets fixed.

## Prerequisites

- Docker + Docker Compose v2 (`docker compose`, not `docker-compose`)
- Go 1.25+ (to build `judicial-cli` from source)
- About 1 GiB of free disk for Postgres + the operator image (GCS storage lives in your GCP project, not on disk)
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
- **Witness cosignatures on the tree head.** Each operator
  self-signs checkpoints unwitnessed in dev mode.
- **Production sealing of artifacts.** The walkthrough surfaces
  `PartyBindingSealedPayload` shapes but uses placeholder
  `encrypted_mapping_cid` values.

These are deliberate omissions — they have their own walkthroughs
when those paths are ready to be exercised.

## Status

- SDK: `v0.8.0` (EIP-1271 supported but not exercised here)
- Operator topology: `deployment/local/docker-compose.dev.yml` in
  the operator repo
- CLI: `judicial-network/cmd/judicial-cli/`
- Branch: `claude/notice-of-appearance-event-rsEGt` (all three repos)

Ready? Open **[01-environment.md](01-environment.md)**.
