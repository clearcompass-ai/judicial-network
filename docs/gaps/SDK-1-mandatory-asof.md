# SDK-1 — Make `verifier.AsOf` a mandatory parameter (remove the implicit "latest" / local-clock default)

> **Target repo:** clearcompass-ai/attesta
> **Labels:** `bug` · `breaking-change` · `determinism` · `zero-trust-physics`
> **Depends on:** — (pairs with SDK-2; consumed by judicial-network JN-4)
> **Status:** ✅ **SHIPPED in attesta v1.43.0** (filed as clearcompass-ai/attesta#80;
> adopted JN-side in the merged judicial-network#85). `AsOf` is now mandatory —
> `ErrAsOfRequired` rejects the zero value on the authority + provenance walkers,
> `ResolveLatest` is the only explicit route to "current", and `VerifyComplete`'s
> authority stage takes a required pinned `AsOf` (`AuthorityStageParams.AsOf`), so no
> verdict path reads the wall clock. Retained as the **design record**; the sections
> below describe the fix as implemented.

## Why this exists

Protocol Physics #1: *"There is no default in the SDK. The SDK primitive must
require `asOf` as a mandatory parameter (e.g., passing the specific TreeHead or
LogPosition)… This guarantees that a verdict rendered today will mathematically
render the exact same result 15 years from now."*

The SDK violates this: a zero `AsOf` resolves to "latest", and the
activation-delay reference time falls back to `time.Now()`. A verdict is
therefore a function of *when you asked*, not *what you pinned*.

## Architectural ground truth

| Fact | Implication for verification |
|---|---|
| "Latest" is a moving target | A query at `09:00:00.000` returning `Active` and one at `09:00:00.001` (post-rotation) returning `Invalid` are both "correct" — idempotency is destroyed |
| Two parties, one instant | Defense and prosecution must get identical, court-admissible verdicts; a wall-clock-derived reference time cannot guarantee that |
| The deterministic path already exists | `asOfTime` already returns the head's committed `LogTime` *when a position is pinned* — the only defect is the `IsNull()` escape hatch |
| The walker has **two** callers, not one | `evaluateAuthorityAt` is reached by `authority_withtrust.go:83` (pinnable) **and** `verify_complete.go:280` (hardcoded `time.Now()`) — fixing only `asOfTime` leaves the headline composite wall-clock |

## Evidence (current behavior)

| File:line | Code | Problem |
|---|---|---|
| `verifier/log_trust.go:31-32` | "The zero value (IsNull) means 'latest' (current head)" | "latest" is the *documented* default |
| `verifier/authority_withtrust.go:104-106` | `if asOf.IsNull() { return time.Now().UTC(), nil }` | reference time = **local clock** |
| `verifier/authority_withtrust.go:108-115` | `return ep.Meta.LogTime.UTC()` | ✅ correct deterministic path (pinned case) — keep |
| `verifier/provenance_withtrust.go:129` | `if asOf.IsNull() { … }` | same escape hatch on the provenance walker |
| `verifier/log_trust.go:106` | `verifier.AsOf{} (latest)` | `SingleLog` documents the zero value as latest |
| `verifier/verify_complete.go:274-280` | `evaluateAuthorityAt(…, time.Now().UTC())` in the `VerifyComplete` authority stage | **second wall-clock site** — the headline composite (`ARCH-VP-A`) has no `asOf` param and is live via JN's `/verify-complete` handler; its own header claims "IDEMPOTENT. Pure function of (ctx, params)" |
| `verifier/key_at_position.go:243` | `if query.QueryPos.IsNull() { return nil, ErrZeroQueryPos }` | ✅ the fail-closed precedent to mirror — already shipping in a sibling primitive |

## Impact (mapped to the mandate)

| Scenario / Physics | Failure today |
|---|---|
| **Physics #1** | The forbidden default exists and is load-bearing |
| **Scenario 3** (clock-independent verdicts) | Two parties at the same activation boundary can diverge from µs clock drift |
| **Scenario 2 / Goal 13** (year-15) | "Latest" silently re-evaluates a year-1 question against year-15 state |

## Proposed structural fix (aligned to the design objectives)

A verdict must be a **pure function of `(pinned cosigned head, entry)`** — the wall
clock unreachable from any verdict path. Enforced **fail-closed by construction**
(`ZT-SDK-03`), with **no deprecation shim** (`ZT-SDK-07` / `ZT-LED-02` — zero legacy
shims). Safe as a clean break: the only in-tree consumers are JN's known sites
(`ledger` / `attesta-tools` / `e2e-tests` call none of these APIs).

```go
// BEFORE: zero value silently means "latest" / time.Now()
func EvaluateAuthorityWithTrust(ctx, entity, prov, extractor, asOf AsOf) (*AuthorityEvaluation, error)

// AFTER:
//  1. asOf MUST be non-null; IsNull() → typed ErrAsOfRequired (fail-closed).
//  2. asOfTime() loses the time.Now() branch entirely — reference time is
//     ALWAYS the pinned head's committed LogTime.
//  3. New explicit helper makes "live/current" a deliberate, snapshotted choice:
func ResolveLatest(ctx, prov LogTrustProvider, logDID string) (AsOf, error)
```

- Remove `IsNull()→latest` / `IsNull()→time.Now()` from `authority_withtrust.go`
  and `provenance_withtrust.go`. Reject `AsOf{}` on both walkers with
  `ErrAsOfRequired` before any walk — mirroring the existing
  `key_at_position.go:243 → ErrZeroQueryPos` precedent.
- Add `ErrAsOfRequired` sentinel; document the `AsOf` zero value as **invalid**,
  not "latest".
- **`VerifyComplete` (the second site) takes a required pinned anchor — symmetric
  with the conditions stage.** Its authority stage hardcodes `time.Now().UTC()`
  (`verify_complete.go:280`) and has no `asOf` parameter, while its *conditions*
  stage already accepts a caller time (`EvaluateConditionsParams.Now`). Make the
  structure symmetric:

  ```go
  type AuthorityStageParams struct {
      LeafKey    [32]byte
      LeafReader smt.LeafReader
      Fetcher    types.EntryFetcher
      Extractor  schema.SchemaParameterExtractor
      AsOf       AsOf   // NEW, required — IsNull() ⇒ ErrAsOfRequired
  }
  ```

  `VerifyComplete` then derives the reference time via
  `asOfTime(ctx, prov, params.AuthorityParams.AsOf)`, restoring its documented
  "pure function of (ctx, params)" contract.
- **Coordinate with SDK-2** (RootHash) — both change the `AsOf` contract; land as
  one breaking minor.

## Test plan

| Test | Asserts |
|---|---|
| `TestEvaluateAuthorityWithTrust_NullAsOf_Rejected` | `AsOf{}` → `ErrAsOfRequired`, no walk performed |
| `TestAsOfTime_NeverReadsWallClock` | `asOfTime` returns `ep.Meta.LogTime` for every pinned input; `time.Now` unreferenced |
| `TestVerdict_Reproducible_AcrossClockDrift` | same entry + same pinned `AsOf`, two calls with injected clocks µs apart → byte-identical verdict |
| `TestProvenanceWithTrust_NullAsOf_Rejected` | provenance walker mirrors the authority guard |
| `TestVerifyComplete_AuthorityStage_NoWallClock` | `VerifyComplete` authority stage uses the pinned `AsOf`, never `time.Now()`; null ⇒ `ErrAsOfRequired` |

## Open considerations

| Question | Disposition |
|---|---|
| Migration for existing `AsOf{}` callers | In-tree callers are JN (judicial-network#69 C-4); JN-4 supplies Time-of-Receipt. External callers get a compile break (intended for a zero-trust contract). |
| Keep a `ResolveLatest` convenience? | Yes — "live status" is legitimate (e.g. JN `sealing_check`), but it must be an explicit snapshot, not an implicit default. |
| Phased deprecation (Warn-then-error) instead of a clean break? | **Rejected** — a Phase-1 window that keeps `time.Now()` ships the forbidden default for its duration (`ZT-IMM-01`) and is a legacy shim (`ZT-SDK-07` / `ZT-LED-02`). With zero external callers it buys nothing; the break **is** the fix. |

## Acceptance criteria

- [ ] No code path resolves authority against an unpinned position or a wall-clock time.
- [ ] `AsOf{}` on the authority/provenance primitives returns `ErrAsOfRequired`.
- [ ] `VerifyComplete`'s authority stage takes a required pinned `AsOf` and never reads `time.Now()` (`verify_complete.go:280`).
- [ ] `ResolveLatest` exists and is the only route to "current" semantics.
- [ ] Reproducibility test green; `grep -rn "time.Now" verifier/` shows no authority-path usage (today fails on **both** `authority_withtrust.go:106` and `verify_complete.go:280`).

## Dependencies / related

- Pairs with **SDK-2** (same `AsOf` type change). Consumed by **JN-4**. Resolves
  the open `asOf`-default question in **judicial-network#69**.
- Filed as **clearcompass-ai/attesta#80** ("[GAP-7]") — this draft and that issue track the same mandate.

## Evidence trail

```bash
grep -rn "IsNull()" verifier/authority_withtrust.go verifier/provenance_withtrust.go verifier/log_trust.go
grep -rn "time.Now" verifier/authority_withtrust.go verifier/verify_complete.go   # lines to delete: authority_withtrust.go:104-106, verify_complete.go:280
grep -rn "evaluateAuthorityAt(" verifier/                                          # 2 callers: authority_withtrust.go:83 (pinned) + verify_complete.go:274 (wall clock)
go doc github.com/clearcompass-ai/attesta/verifier.EvaluateAuthorityWithTrust
go doc github.com/clearcompass-ai/attesta/verifier.AsOf
```
