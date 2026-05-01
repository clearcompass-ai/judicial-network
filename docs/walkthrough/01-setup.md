# 01 · Setup — From clone to green tests

Goal: a clean clone of `judicial-network` runs the existing test suite
green on your laptop in under 5 minutes, with **no external services**.

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| Go | `>= 1.25.7` | Module declares `go 1.25.7` (`go.mod`) |
| Git | any recent | Clone the repo |

That's it. No Postgres, no GCS, no Privy, no Docker.

Verify Go:

```bash
$ go version
go version go1.25.7 linux/amd64
```

If you're on an older Go, install 1.25.x from
[go.dev/dl](https://go.dev/dl). The repo's `go.mod` enforces the
toolchain.

## Clone and download deps

```bash
$ git clone <your-fork>/judicial-network
$ cd judicial-network
$ go mod download
```

`go mod download` pulls the Ortholog SDK at `v0.8.0` (per
`go.mod` line citing `github.com/clearcompass-ai/ortholog-sdk v0.8.0`).
v0.8.0 is the EIP-1271-supporting release. Older SDK versions will not
satisfy the imports under `tests/contracts/smart_contract_wallet_*.go`.

## Confirm the test suite is green

```bash
$ go test ./tests/contracts/...
ok  	github.com/clearcompass-ai/judicial-network/tests/contracts	1.060s
```

This runs all 82 contract tests against the in-memory fixture.
If this is green, your environment is ready for the walkthrough.

## What just ran

The 82 tests live in `tests/contracts/*.go` and exercise:

- **Delegation primitives** — issue, cosign, succession, revoke
  (`delegation_*_test.go`)
- **Counsel appearances** (`counsel_appearance_test.go`)
- **Multi-actor cosignature flows** (`cosignature_filing_test.go`)
- **Smart-contract-wallet (EIP-1271) signatures**
  (`smart_contract_wallet_test.go`, `smart_contract_wallet_security_test.go`)
- **Cross-jurisdiction destination binding**
- **Davidson County / TN trial composer pattern**

Each test calls `newFixture(t)` from
`tests/contracts/delegation_helpers_test.go:139`. That fixture is the
same one you'll use in the walkthrough, so understanding it once carries
you through all three cases.

## What is NOT touched by `go test`

| External dependency | Used by | Walkthrough impact |
|---|---|---|
| Postgres | `tools/cmd/court-tools/main.go` (CLI) | None — walkthrough uses in-memory `operatorBackend` |
| GCS / S3 | Production operator's bytestore | None — fixture stores canonical bytes in a `map[uint64][]byte` |
| Privy | `api/exchange/identity/privy.go` (production) | None — fixture uses `StubProvider` (same interface) |
| Tessera log | Production operator's Merkle log | None — fixture's `operatorBackend` assigns sequence numbers directly |
| Witness cosigners | Production checkpoint cosignature | None — not required for entry-level signing flows |

## If tests fail

| Failure | Likely cause | Fix |
|---|---|---|
| `verifying module: checksum mismatch` | Stale `go.sum` from a retagged SDK release | `rm go.sum; go mod download` |
| `undefined: signatures.VerifyEIP1271` | SDK older than v0.8.0 | `go get github.com/clearcompass-ai/ortholog-sdk@v0.8.0` |
| `cannot find package` | Missing `go mod download` | Run it |
| `go: requires Go 1.25.7` | Toolchain too old | Install Go 1.25.x |

## Where to look in the repo

| Folder | Purpose |
|---|---|
| `schemas/` | All 17 event payload types (CivilCase, FamilyCase, etc.) |
| `delegation/` | Issue / cosigned / succession / revocation builders |
| `verification/` | Authority resolver, role resolver, delegation chain |
| `tests/contracts/` | The fixture lives here (`delegation_helpers_test.go`) |
| `deployments/tn/counties/davidson/` | Davidson Bundle (composer for trial courts) |
| `deployments/tn/coa/`, `deployments/tn/sup_ct/` | Appellate composers |
| `internal/testfixtures/davidsonlegacy/` | 6-role catalog used by deeper tests |
| `api/exchange/identity/privy_stub.go` | `StubProvider` — fixture's signing backend |

## Time check

If `go test ./tests/contracts/...` is green and under 30 seconds on
your laptop, you're set. Move on to
**[02-fixture-and-actors.md](02-fixture-and-actors.md)** to learn the
fixture pattern that powers all three case walkthroughs.

## Optional: explore the existing tests first

Before writing your own scenarios, browse one or two existing tests to
get a feel for the API:

```bash
# Smallest end-to-end multi-actor test — clerk + attorney + judge
$ less tests/contracts/delegation_cosigned_filing_test.go

# Phase 4 (v0.8.0) EIP-1271 happy path
$ less tests/contracts/smart_contract_wallet_test.go
```

You don't need to read all 82 tests. The fixture pattern is uniform —
once you've seen one test build, sign, submit, and verify an entry, the
rest are variations on the same shape.

Next: **[02-fixture-and-actors.md](02-fixture-and-actors.md)**.
