# SDK-2 — Add a `RootHash` fork discriminator to `AsOf`/`LogPosition`

> **Target repo:** baseproof/baseproof
> **Labels:** `bug` · `breaking-change` · `cross-log` · `zero-trust-physics`
> **Depends on:** — (pairs with SDK-1; consumed by judicial-network JN-1)
> **Status:** Proposal / ready to implement. The storage layer already keys forks
> by RootHash; the SDK selector cannot express one. This realizes the capability
> judicial-network#69 *assumes* ("asOf = head(seq, RootHash)") but which the
> `AsOf` type does not yet provide.

## Why this exists

Protocol Physics #2 / Scenario 4: when a log forks, *"the verifier must
explicitly bind its verdict to a specific chain by pinning the asOf query to the
exact RootHash… It must refuse to blindly accept 'whatever bytes are at sequence
1,345,000'."* `AsOf` is `types.LogPosition = {LogDID, Sequence}` — it has no
RootHash, so two valid chains that share `(LogDID, Sequence)` after a fork are
indistinguishable through the SDK selector.

## Architectural ground truth

| Fact | Implication for verification |
|---|---|
| Forks produce two heads at one sequence | `(LogDID, Sequence)` is ambiguous; only `RootHash` disambiguates which chain |
| The journal already stores both | `(LogDID, Sequence, RootHash)` is the journal PK; `HeadByRootHash`/`HeadsAtSequence` exist — the data is there |
| The selector can't reach it | The `LogTrustProvider` contract takes `AsOf` (no root), so resolution falls back to "head at sequence" |

## Evidence (current behavior)

| File:line | Code | Problem |
|---|---|---|
| `types/log_position.go:9-12` | `LogPosition{ LogDID string; Sequence uint64 }` | no RootHash field |
| `verifier/log_trust.go:36` | `type AsOf = types.LogPosition` | docstring claims it unifies "fork", but the type can't |
| `tooling/libs/monitoring/heads_journal.go:139` | `HeadByRootHash(logDID, sequence, rootHash)` | exact-fork lookup exists one layer down |
| `tooling/libs/monitoring/heads_journal.go:146` | `HeadsAtSequence` "returns ≥2 (the diverging roots)" | journal models forks explicitly |
| `tooling/services/auditor/internal/store/heads_journal.go:110` | `PRIMARY KEY (log_did, sequence, root_hash)` | storage is root-keyed |
| `judicial-network/verification/trust/multijurisdiction.go:284-287` | `resolveHead` → `HeadAt(asOf.Sequence)` | consumer drops the root dimension (see JN-1) |

## Impact (mapped to the mandate)

| Scenario / Physics | Failure today |
|---|---|
| **Scenario 4** (split-brain / fork) | The verifier cannot say which fork it certified |
| **Physics #2** | The storage keys by root, but the verification selector cannot request a specific root |
| **Goal 2 / 14** | Equivocation visibility exists at the journal, but verdicts can't bind to one branch |

## Proposed change

```go
// Option A — extend LogPosition (smallest blast radius for the selector):
type LogPosition struct {
    LogDID   string
    Sequence uint64
    RootHash [32]byte // optional; zero ⇒ resolve-by-sequence (back-compat)
}

// Option B — dedicated AsOf wrapper (avoids overloading LogPosition's
// Less/Equal arithmetic used elsewhere as a pure address):
type AsOf struct {
    Pos      types.LogPosition
    RootHash [32]byte // optional
}
```

- When `RootHash` is set, the `LogTrustProvider` contract MUST resolve via an
  exact `(LogDID, Sequence, RootHash)` lookup and fail closed on mismatch.
- When zero, preserve today's resolve-by-sequence behavior (back-compat).
- Update the `LogTrustProvider` doc to require exact-root resolution when present.
- **Coordinate with SDK-1** — both touch the `AsOf` contract; land together.

## Test plan

| Test | Asserts |
|---|---|
| `TestAsOf_RootHash_PinsExactFork` | two heads at one sequence (R1≠R2); `AsOf{…,R1}` resolves head-1 |
| `TestAsOf_RootHash_MismatchFailsClosed` | entry that verifies under R1 fails under `AsOf{…,R2}` |
| `TestAsOf_ZeroRootHash_BackCompat` | zero RootHash resolves identically to today (resolve-by-sequence) |

## Open considerations

| Question | Disposition |
|---|---|
| Extend `LogPosition` vs new `AsOf` struct? | `LogPosition` is used as a pure address (`Less`/`Equal`) for ordering; adding `RootHash` may perturb those. Prefer Option B unless audited safe. |
| Cross-network fork policy | Per Physics #4, an equivocated log is BURNED — root-pinning is for forensic/historical precision and the detection-latency window, not for "choosing" a live fork. |

## Acceptance criteria

- [ ] `AsOf` can carry an optional `RootHash`.
- [ ] Providers resolve exact heads via `HeadByRootHash` when a root is pinned.
- [ ] Zero-root behavior is unchanged (back-compat test green).

## Dependencies / related

- Pairs with **SDK-1**. Consumed by **JN-1**. Realizes the assumed capability in
  **judicial-network#69** (Goal 2/14).

## Evidence trail

```bash
grep -rn "type LogPosition" types/
grep -rn "type AsOf" verifier/
grep -rn "HeadByRootHash\|HeadsAtSequence" ../tooling/libs/monitoring/heads_journal.go
grep -rn "PRIMARY KEY" ../tooling/services/auditor/internal/store/heads_journal.go
```
