# SDK-2 — Add a `RootHash` fork discriminator to `AsOf`/`LogPosition`

> **Target repo:** clearcompass-ai/attesta
> **Labels:** `bug` · `breaking-change` · `cross-log` · `zero-trust-physics`
> **Depends on:** — (pairs with SDK-1; consumed by judicial-network JN-1)
> **Status:** ✅ **SHIPPED in attesta v1.43.0** (filed as clearcompass-ai/attesta#79;
> adopted JN-side in the merged judicial-network#85). `verifier.AsOf` is now its own
> struct embedding `types.LogPosition` + a `RootHash` head discriminator; providers
> resolve the exact head and fail closed with `ErrForkNotPresent` on a pinned root
> they can't serve; `types.LogPosition` is unchanged (map-key / `Equal` / `Less`
> invariants preserved). Retained as the **design record**.

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
| Head identity **is** the RootHash | `ZT-ALN-01` (Tree Head as Universal Anchor); `types.CosignedTreeHead` embeds `TreeHead`, exposing `head.RootHash`/`head.TreeSize` — the selector should pin to the head, not a bare address |

## Evidence (current behavior)

| File:line | Code | Problem |
|---|---|---|
| `types/log_position.go:9-12` | `LogPosition{ LogDID string; Sequence uint64 }` | no RootHash field |
| `verifier/log_trust.go:36` | `type AsOf = types.LogPosition` | docstring claims it unifies "fork", but the type can't |
| `attesta-tools/libs/monitoring/heads_journal.go:139` | `HeadByRootHash(logDID, sequence, rootHash)` | exact-fork lookup exists one layer down |
| `attesta-tools/libs/monitoring/heads_journal.go:146` | `HeadsAtSequence` "returns ≥2 (the diverging roots)" | journal models forks explicitly |
| `attesta-tools/services/auditor/internal/store/heads_journal.go:110` | `PRIMARY KEY (log_did, sequence, root_hash)` | storage is root-keyed |
| `judicial-network/verification/trust/multijurisdiction.go:284-287` | `resolveHead` → `HeadAt(asOf.Sequence)` | consumer drops the root dimension (see JN-1) |

## Impact (mapped to the mandate)

| Scenario / Physics | Failure today |
|---|---|
| **Scenario 4** (split-brain / fork) | The verifier cannot say which fork it certified |
| **Physics #2** | The storage keys by root, but the verification selector cannot request a specific root |
| **Goal 2 / 14** | Equivocation visibility exists at the journal, but verdicts can't bind to one branch |

## Proposed structural fix (head-identity selector)

The unit of trust is the **cosigned tree head**, whose identity includes `RootHash`
(`ZT-ALN-01`). The selector must pin to **head identity**, not a bare
`(LogDID, Sequence)` address. `verifier.AsOf` becomes its own struct (breaks the
`= types.LogPosition` alias); `types.LogPosition` stays a pure address:

```go
type AsOf struct {
    types.LogPosition          // LogDID + Sequence — unchanged, still a pure address
    RootHash [32]byte          // head identity; zero = pre-fork / no-fork-observed
}
```

- **Additive / flagless** (`ZT-SCN-10` — no flag day): the shared wire/address type
  `types.LogPosition` is untouched, so its map-key and `Equal`/`Less` invariants are
  preserved; the change is a compiler-checked update to `LogTrustProvider` signatures.
- **Fail-closed resolver contract** (`ZT-SDK-03`): `RootHash != zero` ⇒ every provider
  resolves the exact head via `HeadByRootHash` and returns `ErrForkNotPresent` if
  absent — **including** the providers that ignore `asOf` today (`verifier.SingleLog`,
  `anchor.MultiLog` at `anchor/multilog.go:71-73`). Silently serving a different head
  against a pinned root is **fail-open** and forbidden.
- **Zero-RootHash** preserves today's resolve-by-sequence behavior (back-compat). Once
  a fork is observed for a log, verification of that log MUST be root-pinned (an
  equivocated log is burned anyway — see SDK-4).

### Rejected alternative — Option A (add `RootHash` to `types.LogPosition`)

Rejected on **structural** grounds, not preference. `types.LogPosition` is a **Go map
key** (`schema/resolver.go:25,33`, `attestation/policy_verifier.go:149`,
`verifier/evidence_chain.go:249,254` cycle-detection, `authority_evaluator.go:171`,
`schema_succession.go:123`, `core/scope/history.go:168`) and an identity value compared
by a hand-written `.Equal()`/`.Less()` (`types/log_position.go:20-29`, `LogDID` +
`Sequence` only). Adding a field silently changes `map[types.LogPosition]` keying and
diverges built-in `==` from `.Equal()` — an illegal state introduced by stealth (anti
`ZT-ENG-DEF-04`). A shared address type must stay a pure address; the discriminator
belongs on the verification selector, whose blast radius is enumerable and
compiler-checked.

## Test plan

| Test | Asserts |
|---|---|
| `TestAsOf_RootHash_PinsExactFork` | two heads at one sequence (R1≠R2); `AsOf{…,R1}` resolves head-1 |
| `TestAsOf_RootHash_MismatchFailsClosed` | entry that verifies under R1 fails closed (`ErrForkNotPresent`) under `AsOf{…,R2}` |
| `TestAsOf_ZeroRootHash_BackCompat` | zero RootHash resolves identically to today (resolve-by-sequence) |
| `TestAsOf_PinnedRoot_AllProvidersFailClosed` | `SingleLog` + `anchor.MultiLog` return `ErrForkNotPresent` (never a silent fixed head) for an unresolvable pinned root |
| `TestLogPosition_Unchanged` | `types.LogPosition` gains no field; map-key / `Equal` / `Less` behavior is byte-identical |

## Open considerations

| Question | Disposition |
|---|---|
| Extend `LogPosition` vs new `AsOf` struct? | **Decided: new `AsOf` struct (Option B).** `LogPosition` is a Go map key + `.Equal()`/`.Less()` identity at ≥8 sites; adding `RootHash` silently changes keying and diverges `==` from `.Equal()`. Option A rejected — see Proposed structural fix. |
| Cross-network fork policy | Per Physics #4, an equivocated log is BURNED — root-pinning is for forensic/historical precision and the detection-latency window, not for "choosing" a live fork. |

## Acceptance criteria

- [ ] `verifier.AsOf` is its own struct carrying `RootHash`; **`types.LogPosition` is unchanged** (map-key / `Equal` / `Less` invariants preserved).
- [ ] `RootHash != zero` ⇒ providers resolve the exact head via `HeadByRootHash`; **fail closed** with `ErrForkNotPresent` if no match — across ALL `LogTrustProvider` impls (JN `MultiJurisdictionTrust`, `SingleLog`, `anchor.MultiLog`). No provider silently serves a different head.
- [ ] Zero-RootHash behavior is unchanged (additive / flagless — back-compat test green).

## Dependencies / related

- Pairs with **SDK-1**. Consumed by **JN-1**. Realizes the assumed capability in
  **judicial-network#69** (Goal 2/14).
- Filed as **clearcompass-ai/attesta#79** ("[GAP-3]") — this draft and that issue track the same mandate.

## Evidence trail

```bash
grep -rn "type LogPosition" types/
grep -rn "type AsOf" verifier/
grep -rn "map\[types.LogPosition\]\|\.Less(\|\.Equal(" verifier/ core/ attestation/ schema/   # the map-key / identity sites Option A would perturb
grep -rn "HeadByRootHash\|HeadsAtSequence" ../attesta-tools/libs/monitoring/heads_journal.go
grep -rn "PRIMARY KEY" ../attesta-tools/services/auditor/internal/store/heads_journal.go
```
