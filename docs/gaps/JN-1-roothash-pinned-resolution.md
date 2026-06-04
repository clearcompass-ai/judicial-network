# JN-1 — Pin cross-network resolution to RootHash (`HeadByRootHash`)

> **Target repo:** clearcompass-ai/judicial-network
> **Labels:** `bug` · `cross-log` · `zero-trust-physics`
> **Depends on:** SDK-2 (`AsOf` RootHash) · **Relates to:** #69 (Goal 2/14)
> **Status:** Proposal. `MultiJurisdictionTrust` resolves heads by sequence only;
> once `AsOf` can carry a RootHash (SDK-2), `resolveHead` should branch to the
> journal's `HeadByRootHash` so a fork can be pinned end-to-end — realizing the
> capability #69 assumed.

## Why this exists

Scenario 4: a verdict must bind to the exact RootHash of the relevant chain. #69
states the capability "asOf = head(seq, RootHash) identifies the chain", but the
JN resolver drops the root dimension because the SDK `AsOf` can't carry it (and
the resolver doesn't call `HeadByRootHash`).

## Evidence (current behavior)

| File:line | Code | Problem |
|---|---|---|
| `verification/trust/multijurisdiction.go:284-287` | `resolveHead`: `asOf.Sequence == 0 → LatestHead` else `HeadAt(logDID, asOf.Sequence)` | resolves by sequence only; never `HeadByRootHash` |
| `verification/trust/multijurisdiction.go:51-57` | AS-OF SEMANTICS doc — sequence-based | no root dimension |
| (substrate) `tooling/.../store/heads_journal.go:139` | `HeadByRootHash(...)` already available | the call the resolver should make |

## Impact

| Scenario / Physics | Failure today |
|---|---|
| **Scenario 4** | On an equivocated foreign log, the resolver can't request a specific fork |
| **Physics #2** | Storage is root-keyed, but JN resolution isn't |

## Proposed change

Once SDK-2 lands, in `resolveHead`:

```go
if !asOf.RootHash.IsZero() {           // SDK-2 field
    return m.journal.HeadByRootHash(ctx, logDID, asOf.Sequence, asOf.RootHash)
}
// existing: LatestHead / HeadAt(sequence)
```

Thread the RootHash through the `LogTrustProvider.TrustRoot/Entry/Leaf` calls so
inclusion/membership proofs verify against the pinned fork's head.

## Test plan

Realize #69's `TestMultiJurisdiction_Fork` against a real root-pinned `asOf`
(not a fixture stub): federal log forked; reference verifies under chain X's head
and **fails** under chain Y's; `HeadByRootHash` mismatch fails closed.

## Acceptance criteria

- [ ] `resolveHead` uses `HeadByRootHash` when `asOf.RootHash` is set.
- [ ] A forked foreign reference is pinnable end-to-end through `MultiJurisdictionTrust`.
- [ ] Zero-root preserves today's behavior.

## Dependencies / related

- Depends on **SDK-2**. Realizes the fork capability in **judicial-network#69**.

## Evidence trail

```bash
sed -n '276,288p' verification/trust/multijurisdiction.go
grep -rn "HeadByRootHash\|HeadAt\|LatestHead" verification/trust/multijurisdiction.go
```
