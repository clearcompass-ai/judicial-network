# SDK-4 — `anchor.VerifyCrossLog` must accept a burn/equivocation oracle and fail closed

> **Target repo:** baseproof/baseproof
> **Labels:** `bug` · `security` · `cross-log` · `zero-trust-physics`
> **Depends on:** — (consumed by judicial-network JN-3)
> **Status:** Proposal / ready to implement. The primitive verifies quorum +
> inclusion but never consults burn state, so a burned source log's proof still
> verifies. This is the SDK seam JN-3 needs to fail closed.

## Why this exists

Protocol Physics #4 (Cross-Network Fork Policy — STRICT FAIL-CLOSED): *"The
moment the JN detects or receives a KindEquivocationFinding regarding the Federal
log, the SDK's trust status for that specific LogDID transitions to
BURNED/FROZEN. Any subsequent call to VerifyCrossLogProof for an entry residing
on that log must immediately return a fatal ErrEquivocatedLog."* Today
`VerifyCrossLog` has no way to know a log is burned.

## Architectural ground truth

| Fact | Implication for verification |
|---|---|
| A forked log has "committed cryptographic treason" | A validly-cosigned head from it must NOT be trusted post-burn |
| The proof can be cryptographically valid yet from a burned log | Quorum + inclusion passing is necessary but not sufficient |
| Burn state already exists (auditor journal) | The check is a local lookup, not a network call — it does not break the offline/self-contained property |

## Evidence (current behavior)

| File:line | Code | Problem |
|---|---|---|
| `anchor/anchor.go:213-223` | `VerifyCrossLog(proof, sourceSet)`: `Deserialize` → `VerifyCosignedAnchor` (quorum) → `VerifyInclusion` | no burn/equivocation consultation |
| `anchor/anchor.go:202` | "…the source log, which may by then be offline or **equivocating**" | the risk is acknowledged in prose, not checked |
| `attesta-tools/libs/monitoring/heads_journal.go:279` | `ErrEquivocatedLog = "…log burned due to equivocation"` | the sentinel exists, elsewhere |
| `attesta-tools/libs/monitoring/heads_journal.go:159` | `BurnStatus(ctx, logDID) (BurnStatus, error)` | the burn oracle exists, elsewhere |

## Impact (mapped to the mandate)

| Scenario / Physics | Failure today |
|---|---|
| **Physics #4** | A burned/forked source log's well-formed cross-log proof returns valid |
| **Scenario 1** (foreign root) / **Goal 7** | A forged-or-burned cross-log reference is not fail-closed at the proof boundary |

## Proposed change

```go
// New oracle seam (a local lookup; the auditor journal satisfies it):
type BurnOracle interface {
    IsBurned(ctx context.Context, logDID string) (bool, error)
}

// New burn-aware entry point (keeps the pure offline primitive intact):
func VerifyCrossLogWithBurnCheck(
    ctx context.Context,
    proof types.CrossLogProof,
    sourceSet *cosign.WitnessKeySet,
    oracle BurnOracle,
) error // returns ErrEquivocatedLog if the source log is burned, before trusting the proof
```

- Export `ErrEquivocatedLog` at the anchor layer (or alias the monitoring
  sentinel) so callers match a stable error.
- Keep `VerifyCrossLog(proof, sourceSet)` for genuinely journal-less callers, but
  document that consumers holding a journal MUST use the burn-aware form.

## Test plan

| Test | Asserts |
|---|---|
| `TestVerifyCrossLog_BurnedSource_Rejected` | oracle reports burned ⇒ `ErrEquivocatedLog`, regardless of proof validity |
| `TestVerifyCrossLog_CleanSource_Unchanged` | not-burned ⇒ identical result to `VerifyCrossLog` |
| `TestVerifyCrossLog_NilOracle_PureMode` | nil oracle ⇒ documented offline behavior (no panic) |

## Open considerations

| Question | Disposition |
|---|---|
| Pre-check vs post-check burn | Pre-check short-circuits cheaply; post-check still rejects. Either satisfies fail-closed; pre-check preferred. |
| Should the offline `VerifyCrossLog` be deprecated? | No — it's the correct primitive for callers with no journal (Alignment 6, self-contained). The burn check is a consumer responsibility surfaced via the oracle. |

## Acceptance criteria

- [ ] A burn-aware cross-log entry point exists and returns `ErrEquivocatedLog` for burned source logs.
- [ ] `ErrEquivocatedLog` is matchable from the anchor package.
- [ ] The pure offline primitive is unchanged and documented.

## Dependencies / related

- Consumed by **JN-3** (gates the 4 JN call sites). Net-new relative to
  **judicial-network#69** (which scopes authority resolution, not the cross-log
  proof handlers).

## Evidence trail

```bash
grep -rn "func VerifyCrossLog" anchor/anchor.go
sed -n '200,224p' anchor/anchor.go
grep -rn "ErrEquivocatedLog\|func.*BurnStatus" ../attesta-tools/libs/monitoring/heads_journal.go
```
