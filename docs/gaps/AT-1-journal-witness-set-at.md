# AT-1 — Journal-backed `WitnessSetAt` materialization

> **Target repo:** clearcompass-ai/attesta-tools
> **Labels:** `enhancement` · `long-term-verifiability`
> **Depends on:** SDK-3 (the `WitnessSetAt` contract) · **Consumed by:** JN-2
> **Status:** Proposal. The heads journal already persists every head with its
> verbatim signing set; what's missing is a read that returns a *constructed*
> `*cosign.WitnessKeySet` for an `asOf`. The data is there — the accessor isn't.

## Why this exists

Scenario 2 (Year-15) needs the quorum authoritative at a historical position.
SDK-3 defines the `WitnessSetAt` primitive; AT-1 backs it with the auditor's
durable journal so a real deployment can reconstruct W1 in year 15 without the
original operator.

## Architectural ground truth

| Fact | Implication |
|---|---|
| The journal stores each head's signatures verbatim | "so a year-15 verifier can authenticate against the ORIGINAL witness public keys" — the raw material for reconstruction is persisted |
| Heads are keyed `(LogDID, Sequence, RootHash)` | Historical + fork-aware reads are already possible (`HeadByRootHash`, `HeadAt`) |
| No reconstructed-set accessor exists | Consumers (JN) fall back to a static boot map (see JN-2) |

## Evidence (current behavior)

| File:line | Code | Note |
|---|---|---|
| `libs/monitoring/heads_journal.go:162-166` | `Head` "Preserves the full witness signature set verbatim so a year-15 verifier can authenticate against the ORIGINAL witness public keys" | signing set is persisted |
| `services/auditor/internal/store/heads_journal.go:308-309` | rejects empty signatures — "year-15 verification needs the original witness set" | invariant already enforced |
| `services/auditor/internal/store/heads_journal.go:139` | `HeadByRootHash(ctx, logDID, sequence, rootHash)` | exact historical/fork read exists |
| (repo-wide) | `grep -rn "WitnessSetAt\|HistoricalWitnessSet"` → no results | the accessor is the gap |

## Impact

| Scenario | Failure today |
|---|---|
| **Scenario 2 / Goal 13** | The journal can return the *head* at `asOf` but not the *constructed quorum* to verify it against |
| **Scenario 1** | JN can't resolve the foreign quorum historically (JN-2 blocked) |

## Proposed change

Add to the `HeadsJournal` interface + Postgres/memory impls:

```go
// WitnessSetAt returns the K-of-N quorum authoritative for logDID at asOf,
// reconstructed from the journaled head's signing set bound to the network's
// K/NetworkID/BLS topology. Fail-closed on burned logs except via root-pinned
// forensic reads (mirrors BurnStatus semantics).
WitnessSetAt(ctx context.Context, logDID string, asOf types.LogPosition) (*cosign.WitnessKeySet, error)
```

Implements the SDK-3 contract; sources keys from `HeadAt`/`HeadByRootHash`.

## Test plan

| Test | Asserts |
|---|---|
| `TestWitnessSetAt_ReconstructsW1` | record heads across a W1→W4 rotation; `WitnessSetAt(asOf=year-1)` returns the W1 quorum |
| `TestWitnessSetAt_BurnedLog_FailsClosed` | burned log returns `ErrEquivocatedLog` on the latest path; resolvable via `HeadByRootHash` |
| `TestWitnessSetAt_Postgres_MemoryParity` | Postgres + memory impls agree |

## Acceptance criteria

- [ ] `WitnessSetAt` on both `HeadsJournal` impls returns the historical quorum.
- [ ] A year-1 head verifies under the reconstructed set and fails under current.
- [ ] Burn semantics match `BurnStatus`/`HeadByRootHash`.

## Dependencies / related

- Implements **SDK-3**. Consumed by **JN-2**. Backs the witness-set half of
  **judicial-network#69** Gap A.

## Evidence trail

```bash
sed -n '160,170p' libs/monitoring/heads_journal.go
grep -rn "HeadByRootHash\|year-15\|original witness set" services/auditor/internal/store/heads_journal.go
grep -rn "WitnessSetAt\|HistoricalWitnessSet" .   # expect: no results (the gap)
```
