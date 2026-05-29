# SDK-3 — Add `WitnessSetAt(asOf)` historical witness-set reconstruction

> **Target repo:** clearcompass-ai/attesta
> **Labels:** `enhancement` · `long-term-verifiability` · `zero-trust-physics`
> **Depends on:** — (backed by AT-1; consumed by judicial-network JN-2)
> **Status:** Proposal / ready to implement. The SDK can verify a single key at a
> position and can walk a rotation chain to *current*, but there is no primitive
> that materializes the **quorum set** authoritative at a historical position.

## Why this exists

Scenario 2 (the Year-15 scenario, Goal 13): *"The system must successfully load
the specific Cosigned Tree Head that was authoritative on the 2026 date,
reconstruct the historically valid W1 witness set, and mathematically
authenticate the year-1 bundle. The bundle must not silently fail by attempting
to verify against the current W4 keys."* No SDK primitive returns
`*cosign.WitnessKeySet` as-of an `asOf`.

## Architectural ground truth

| Fact | Implication for verification |
|---|---|
| Witnesses rotate dozens of times over 15 years | The set authoritative for a 2026 head ≠ the 2041 set |
| Year-1 bundles must verify in year 15 | Verification needs the year-1 quorum, reconstructed deterministically |
| `VerifyRotationChain` only yields *current* | There is no "stop at asOf" — and rotations carry no position to stop on |

## Evidence (current behavior)

| File:line | Code | Problem |
|---|---|---|
| `witness/rotation.go:275-304` | `VerifyRotationChain(genesisSet, rotations) (...)` loops **all** rotations → returns the current set's keys | no position bound; always "now" |
| `verifier/key_at_position.go:220,307` | `VerifyKeyAtPosition(...) (*KeyAtPositionResult, error)` | resolves a **single DID's** key (bool+bytes), not a set |
| `types/witness_rotation.go:3-10` | `WitnessRotation{ CurrentSetHash; NewSet; …Signatures }` | **no position field** → caller can't even truncate-and-replay |
| `crypto/cosign/witness_key_set.go:129,261` | `NewWitnessKeySet` / `NewECDSAWitnessKeySet` | only direct constructors; no as-of form |

## Impact (mapped to the mandate)

| Scenario / Physics | Failure today |
|---|---|
| **Scenario 2 / Goal 13** | Year-1 bundle verification has no path to the year-1 quorum |
| **Scenario 1** (foreign root) | Cross-network references can't be checked against the mint-time quorum (see JN-2) |

## Proposed change

```go
// 1. Give rotations a comparable position (or a parallel record):
type WitnessRotation struct {
    EffectivePos types.LogPosition // NEW: the position at/after which NewSet is authoritative
    // …existing fields…
}

// 2. New primitive — reconstruct the quorum authoritative at asOf:
func WitnessSetAt(
    genesis *cosign.WitnessKeySet,
    rotations []types.WitnessRotation, // sorted by EffectivePos
    asOf types.LogPosition,
) (*cosign.WitnessKeySet, error)
```

Implementation mirrors `VerifyRotationChain` (verify each step, rebuild the set
via `NewWitnessKeySet` with the same K/NetworkID/BLS topology) but **stops** at
the last rotation with `EffectivePos ≤ asOf`. Backed by AT-1 (journal-sourced
rotations/heads) on the consumer side.

## Test plan

| Test | Asserts |
|---|---|
| `TestWitnessSetAt_ReturnsHistoricalSet` | genesis W1 → rotate W2/W3/W4 at known positions; `WitnessSetAt(asOf=year-1)` returns W1 |
| `TestWitnessSetAt_Year1BundleVerifiesUnderW1` | a 2026 cosigned head verifies under the reconstructed W1 |
| `TestWitnessSetAt_FailsUnderCurrentSet` | the same year-1 head **fails** under W4 (the silent-failure the mandate forbids) |
| `TestWitnessSetAt_AsOfBeforeGenesis` | `asOf` before any rotation returns genesis; fail-closed on empty |

## Open considerations

| Question | Disposition |
|---|---|
| Add position to `WitnessRotation` vs a new record type | Adding `EffectivePos` is the smaller change but touches the rotation wire/type; a parallel `RotationAt` record (like `verifier.RotationRecord` for single keys) avoids that. Decide during design. |
| Source of truth for historical rotations | The auditor heads journal persists each head with its signing set (AT-1); that is the durable substrate this primitive reads from. |

## Acceptance criteria

- [ ] `WitnessSetAt(logDID, asOf)` returns the quorum authoritative at `asOf`.
- [ ] A year-1 bundle verifies under the reconstructed W1 and fails under W4.
- [ ] Rotations carry (or can be correlated to) their effective position.

## Dependencies / related

- Backed by **AT-1** (journal-sourced reconstruction). Consumed by **JN-2**.
  Addresses the witness-set half of **judicial-network#69** Gap A.

## Evidence trail

```bash
grep -rn "func VerifyRotationChain" witness/rotation.go
grep -rn "func VerifyKeyAtPosition" verifier/key_at_position.go
grep -rn "type WitnessRotation" types/witness_rotation.go
grep -rn "func NewWitnessKeySet\|func NewECDSAWitnessKeySet" crypto/cosign/witness_key_set.go
grep -rn "WitnessSetAt\|HistoricalWitnessSet" .   # expect: no results (the gap)
```
