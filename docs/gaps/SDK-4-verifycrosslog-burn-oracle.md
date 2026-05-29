# SDK-4 — `anchor.VerifyCrossLog` must require a burn/equivocation trust input and fail closed

> **Target repo:** clearcompass-ai/attesta
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
`VerifyCrossLog` has no way to know a log is burned — and note the mandate names
`VerifyCrossLogProof`, a **second** entry point in a different package (see Evidence).

## Architectural ground truth

| Fact | Implication for verification |
|---|---|
| A forked log has "committed cryptographic treason" | A validly-cosigned head from it must NOT be trusted post-burn |
| The proof can be cryptographically valid yet from a burned log | Quorum + inclusion passing is necessary but not sufficient |
| Burn state already exists (auditor journal) | The check is a local lookup, not a network call — it does not break the offline/self-contained property |
| There are **two** cross-log entry points, in different packages | `verifier` has 0 `anchor` import edges, so a burn check on `anchor.VerifyCrossLog` alone cannot reach `verifier.VerifyCrossLogProof` |

## Evidence (current behavior)

| File:line | Code | Problem |
|---|---|---|
| `anchor/anchor.go:213-223` | `VerifyCrossLog(proof, sourceSet)`: `Deserialize` → `VerifyCosignedAnchor` (quorum) → `VerifyInclusion` | no burn/equivocation consultation |
| `anchor/anchor.go:202` | "…the source log, which may by then be offline or **equivocating**" | the risk is acknowledged in prose, not checked |
| `verifier/cross_log.go:128` + `verifier/cross_log_compound.go:155,211` | `VerifyCrossLogProof` / `VerifyCompoundProof` / `ResolveCrossLogRef` verify via `cosign.Verify` directly | **parallel** burn-blind path the mandate names; bypasses `anchor` entirely (no prod callers today, but exported public API) |
| `attesta-tools/libs/monitoring/heads_journal.go:279` | `ErrEquivocatedLog = "…log burned due to equivocation"` | the sentinel exists, elsewhere |
| `attesta-tools/libs/monitoring/heads_journal.go:159` | `BurnStatus(ctx, logDID) (BurnStatus, error)` | the burn oracle exists, elsewhere |

## Impact (mapped to the mandate)

| Scenario / Physics | Failure today |
|---|---|
| **Physics #4** | A burned/forked source log's well-formed cross-log proof returns valid |
| **Scenario 1** (foreign root) / **Goal 7** | A forged-or-burned cross-log reference is not fail-closed at the proof boundary |

## Proposed structural fix (burn/trust as a required input)

Burn/trust status is a **trust input to cross-log verification — exactly like the
source witness set** — not an optional add-on. `ZT-IMM-04` (strict fail-closed) +
`ZT-SDK-03` (fail-closed by construction, not caller discipline) + `ZT-SDK-01` (the
SDK owns the gate) require that you **cannot verify a cross-log proof without supplying
trust state, and the zero value fails closed**.

```go
// TrustStatus is a PINNED, offline trust input (no live network call — preserves the
// self-contained / dissolved-ledger property, ZT-SCN-07). The ZERO value is NOT "trusted".
type TrustStatus struct {
    Known  bool   // false ⇒ no burn evidence supplied ⇒ ErrTrustUnknown (fail-closed)
    Burned bool   // true  ⇒ ErrEquivocatedLog
    AsOf   AsOf   // the snapshot (Heads Journal / signed burn list) this status was read at
}

var (
    ErrEquivocatedLog = errors.New("cross-log: source log is burned (equivocated)")
    ErrTrustUnknown   = errors.New("cross-log: no burn evidence supplied; refusing to trust (fail-closed)")
)

// Both cross-log entry points REQUIRE it (verifier has 0 anchor edges, so an
// anchor-only fix can't reach VerifyCrossLogProof):
func VerifyCrossLog(proof types.CrossLogProof, sourceSet *cosign.WitnessKeySet, trust TrustStatus) error
func VerifyCrossLogProof(proof types.CrossLogProof, sourceSet *cosign.WitnessKeySet, trust TrustStatus /*…*/) error
```

- The trust check runs **before** any crypto: `!trust.Known` ⇒ `ErrTrustUnknown`;
  `trust.Burned` ⇒ `ErrEquivocatedLog`. `monitoring.HeadsJournal.BurnStatus` is the
  canonical producer of `TrustStatus`.
- Export `ErrEquivocatedLog` / `ErrTrustUnknown` from both `anchor` and `verifier`
  (reuse / alias the monitoring sentinel) so callers match a stable error.
- The gate moves **into the SDK** (`ZT-SDK-01`) — today it lives only at
  `MultiJurisdictionTrust.TrustRoot`, which the 4 anchor sites bypass. A clean
  signature change, not an additive shim (`ZT-SDK-07` / `ZT-LED-02`); safe because the
  only callers are the 4 JN `anchor.VerifyCrossLog` sites (+ 0 production callers of
  the verifier-side path).

### Rejected alternative — optional `VerifyCrossLogWithBurnCheck(…, oracle)` with `nil ⇒ pure mode`

Rejected. A `nil`-oracle "pure mode" is **fail-open by default** — it lets a caller
silently skip the burn gate, the exact defect this issue files, and violates
`ZT-SDK-03` ("fail closed by mathematical construction, not caller discipline").
Offline / journal-less callers are served by supplying a pinned `TrustStatus` snapshot
(which still fails closed on `!Known`), never by a permissive `nil`.

## Test plan

| Test | Asserts |
|---|---|
| `TestVerifyCrossLog_BurnedSource_Rejected` | `trust.Burned` ⇒ `ErrEquivocatedLog`, before any crypto, regardless of proof validity |
| `TestVerifyCrossLog_UnknownTrust_FailsClosed` | `TrustStatus{}` / `!Known` ⇒ `ErrTrustUnknown` (no fail-open path) |
| `TestVerifyCrossLog_CleanSource_Verifies` | `trust.Known && !trust.Burned` ⇒ proceeds to quorum + inclusion |
| `TestVerifyCrossLogProof_SameContract` | the verifier-side path enforces the identical `TrustStatus` contract |

## Open considerations

| Question | Disposition |
|---|---|
| Pre-check vs post-check burn | **Pre-check** — the trust gate runs before any crypto work; a burned/unknown log never reaches quorum/inclusion. |
| Offline / journal-less callers | Served by a pinned `TrustStatus` snapshot (from the Heads Journal or a signed burn list), **not** by a permissive `nil`. `!Known` fails closed, preserving both self-containment (`ZT-SCN-07`) and the fail-closed mandate. |

## Acceptance criteria

- [ ] Cross-log verification takes a **required** `TrustStatus`; the zero value / `!Known` fails closed with `ErrTrustUnknown` (no fail-open `nil` path).
- [ ] `trust.Burned` ⇒ `ErrEquivocatedLog` returned **before** any crypto work.
- [ ] **Both** entry points gated identically: `anchor.VerifyCrossLog` and `verifier.VerifyCrossLogProof` / `VerifyCompoundProof` / `ResolveCrossLogRef`.
- [ ] `ErrEquivocatedLog` is matchable from the `anchor` and `verifier` packages.
- [ ] Offline verification (`ZT-SCN-07`) works via a pinned `TrustStatus` snapshot — no live network call introduced.

## Dependencies / related

- Consumed by **JN-3** (gates the 4 JN call sites). Net-new relative to
  **judicial-network#69** (which scopes authority resolution, not the cross-log
  proof handlers). The verifier-side path (`VerifyCrossLogProof`) is covered by the
  same `TrustStatus` contract.
- Filed as **clearcompass-ai/attesta#78** ("[GAP-8]") — this draft and that issue track the same mandate.

## Evidence trail

```bash
grep -rn "func VerifyCrossLog" anchor/anchor.go
sed -n '200,224p' anchor/anchor.go
grep -rn "func VerifyCrossLogProof\|func VerifyCompoundProof\|func ResolveCrossLogRef" verifier/   # the parallel path
go list -deps ./verifier | grep -c attesta/anchor                                                  # expect 0 — verifier can't route through anchor
grep -rn "ErrEquivocatedLog\|func.*BurnStatus" ../attesta-tools/libs/monitoring/heads_journal.go
```
