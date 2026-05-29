# SDK-1 — Make `verifier.AsOf` a mandatory parameter (remove the implicit "latest" / local-clock default)

> **Target repo:** clearcompass-ai/attesta
> **Labels:** `bug` · `breaking-change` · `determinism` · `zero-trust-physics`
> **Depends on:** — (pairs with SDK-2; consumed by judicial-network JN-4)
> **Status:** Proposal / ready to implement. The `*WithTrust` API already threads
> `AsOf` through every authority path (judicial-network#69 / PR-C migrated the 5 JN
> call sites). What remains is to make `AsOf` **non-optional** so "latest" stops
> being a silent, clock-derived default. This is the SDK root that
> judicial-network#69's open consideration ("Should `verify_authority`'s default
> `asOf` be latest or time-of-receipt?") depends on.

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

## Evidence (current behavior)

| File:line | Code | Problem |
|---|---|---|
| `verifier/log_trust.go:31-32` | "The zero value (IsNull) means 'latest' (current head)" | "latest" is the *documented* default |
| `verifier/authority_withtrust.go:104-106` | `if asOf.IsNull() { return time.Now().UTC(), nil }` | reference time = **local clock** |
| `verifier/authority_withtrust.go:108-115` | `return ep.Meta.LogTime.UTC()` | ✅ correct deterministic path (pinned case) — keep |
| `verifier/provenance_withtrust.go:129` | `if asOf.IsNull() { … }` | same escape hatch on the provenance walker |
| `verifier/log_trust.go:106` | `verifier.AsOf{} (latest)` | `SingleLog` documents the zero value as latest |

## Impact (mapped to the mandate)

| Scenario / Physics | Failure today |
|---|---|
| **Physics #1** | The forbidden default exists and is load-bearing |
| **Scenario 3** (clock-independent verdicts) | Two parties at the same activation boundary can diverge from µs clock drift |
| **Scenario 2 / Goal 13** (year-15) | "Latest" silently re-evaluates a year-1 question against year-15 state |

## Proposed change

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
  and `provenance_withtrust.go`.
- Add `ErrAsOfRequired` sentinel; document the `AsOf` zero value as **invalid**,
  not "latest".
- **Coordinate with SDK-2** (RootHash) — both change the `AsOf` contract; land as
  one breaking minor.

## Test plan

| Test | Asserts |
|---|---|
| `TestEvaluateAuthorityWithTrust_NullAsOf_Rejected` | `AsOf{}` → `ErrAsOfRequired`, no walk performed |
| `TestAsOfTime_NeverReadsWallClock` | `asOfTime` returns `ep.Meta.LogTime` for every pinned input; `time.Now` unreferenced |
| `TestVerdict_Reproducible_AcrossClockDrift` | same entry + same pinned `AsOf`, two calls with injected clocks µs apart → byte-identical verdict |
| `TestProvenanceWithTrust_NullAsOf_Rejected` | provenance walker mirrors the authority guard |

## Open considerations

| Question | Disposition |
|---|---|
| Migration for existing `AsOf{}` callers | In-tree callers are JN (judicial-network#69 C-4); JN-4 supplies Time-of-Receipt. External callers get a compile break (intended for a zero-trust contract). |
| Keep a `ResolveLatest` convenience? | Yes — "live status" is legitimate (e.g. JN `sealing_check`), but it must be an explicit snapshot, not an implicit default. |

## Acceptance criteria

- [ ] No code path resolves authority against an unpinned position or a wall-clock time.
- [ ] `AsOf{}` on the authority/provenance primitives returns `ErrAsOfRequired`.
- [ ] `ResolveLatest` exists and is the only route to "current" semantics.
- [ ] Reproducibility test green; `grep -rn "time.Now" verifier/` shows no authority-path usage.

## Dependencies / related

- Pairs with **SDK-2** (same `AsOf` type change). Consumed by **JN-4**. Resolves
  the open `asOf`-default question in **judicial-network#69**.

## Evidence trail

```bash
grep -rn "IsNull()" verifier/authority_withtrust.go verifier/provenance_withtrust.go verifier/log_trust.go
grep -rn "time.Now" verifier/authority_withtrust.go        # the line to delete: :104-106
go doc github.com/clearcompass-ai/attesta/verifier.EvaluateAuthorityWithTrust
go doc github.com/clearcompass-ai/attesta/verifier.AsOf
```
