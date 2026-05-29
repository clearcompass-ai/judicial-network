# JN-4 — Adopt explicit Time-of-Receipt asOf at the authority call sites

> **Target repo:** clearcompass-ai/judicial-network
> **Labels:** `bug` · `determinism` · `zero-trust-physics`
> **Depends on:** SDK-1 (mandatory asOf) · **Resolves:** #69 open consideration + C-4
> **Status:** Proposal. The 5 authority sites pass `verifier.AsOf{}` and the HTTP
> handler defaults absent `?as_of` to latest. This is exactly the question #69
> left open: *"Should `verify_authority`'s default `asOf` be latest or
> time-of-receipt?"* — answer: Time-of-Receipt.

## Why this exists

Protocol Physics #1 + Scenario 3: *"It is the responsibility of the Domain
Application (the JN API) to explicitly pass Time-of-Receipt (the SMT
sequence/head at the moment the entry was submitted) into the SDK."* Today the JN
passes the zero `AsOf`, inheriting the SDK's latest/local-clock default (the
defect SDK-1 removes).

## Evidence (current behavior)

| File:line | Site | Current shape |
|---|---|---|
| `enforcement/compliance.go:98` | compliance authority | `…WithTrust(…, verifier.AsOf{})`; `cfg.Now` built at `:91-94` but never threaded |
| `verification/sealing_check.go:43` | sealing status | `LocalTrust + AsOf{}` |
| `verification/delegation_chain.go:152` | delegation provenance | `VerifyDelegationProvenanceWithTrust(…, AsOf{})` |
| `api/verification/handlers/verify_authority.go:38` | `GET …/verify_authority` | `AsOf{}`; `parseAsOf` (`:72-85`) defaults absent/`0` → latest |
| `api/verification/handlers/verify_batch.go:59` | batched | same |

## Impact

| Scenario / Physics | Failure today |
|---|---|
| **Physics #1** | The JN never pins; it inherits the forbidden default |
| **Scenario 3** | Two parties at the same activation boundary can get different verdicts |

## Proposed change (per #69 C-4)

| Site | New asOf policy |
|---|---|
| `enforcement/compliance.go` | `asOf = head(caseRootPos.LogDID, cfg.Now)` — `cfg.Now` finally used for its name |
| `verification/sealing_check.go` | `asOf = ResolveLatest(LogDID)` — explicit, snapshotted "live status" |
| `verification/delegation_chain.go` | `asOf =` the target entry's admission head |
| `api/verification/handlers/verify_authority.go` | require/echo explicit `?as_of=<seq>`; "latest" only via explicit `ResolveLatest` |
| `api/verification/handlers/verify_batch.go` | same, per item |

Depends on SDK-1 making `AsOf{}` an error so any missed site fails loudly.

## Test plan

| Test | Asserts |
|---|---|
| `TestActivationDelay_Reproducible` | same query, two wall-clock instants µs apart across an activation boundary ⇒ identical verdict |
| `TestVerifyAuthority_AsOfQueryParam` | `?as_of=N` returns the historical verdict; absence does not silently fall back to latest |
| `TestComplianceUsesCfgNow` | `compliance.go` threads `cfg.Now` into the pinned head |

## Acceptance criteria

- [ ] All 5 sites pass an explicit `asOf` (Time-of-Receipt or explicit `ResolveLatest`).
- [ ] `verify_authority`/`verify_batch` accept `?as_of=<seq>`; no silent latest default.
- [ ] Activation-delay reproducibility test green.

## Dependencies / related

- Depends on **SDK-1**. Resolves the open `asOf`-default consideration and
  completes C-4 in **judicial-network#69**.

## Evidence trail

```bash
grep -rn "EvaluateAuthorityWithTrust\|VerifyDelegationProvenanceWithTrust" --include=*.go \
  enforcement/ verification/ api/verification/handlers/
sed -n '72,85p' api/verification/handlers/verify_authority.go
sed -n '88,98p' enforcement/compliance.go
```
