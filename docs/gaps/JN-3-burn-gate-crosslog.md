# JN-3 — Burn-gate the four `VerifyCrossLog` call sites

> **Target repo:** clearcompass-ai/judicial-network
> **Labels:** `bug` · `security` · `cross-log` · `zero-trust-physics`
> **Depends on:** SDK-4 (burn oracle) · **Net-new vs #69**
> **Status:** Proposal. All four JN cross-log verification paths call
> `anchor.VerifyCrossLog` with a static witness map and never consult burn state.
> A burned source log's proof returns valid.

## Why this exists

Protocol Physics #4: *"Any subsequent call to VerifyCrossLogProof for an entry
residing on that [burned] log must immediately return a fatal
ErrEquivocatedLog."* The JN holds the burn journal, but its cross-log proof
handlers don't ask it. Burn fail-closed currently lives only in the
authority-walker path (`MultiJurisdictionTrust`), not the proof path.

## Evidence (current behavior)

| File:line | Call site | Burn check? |
|---|---|---|
| `verification/appellate_history.go:152` | `anchor.VerifyCrossLog(*proof, set)` in `VerifyAppealChain` | none |
| `api/verification/handlers/verify_cross_log.go:38` | `anchor.VerifyCrossLog(req.Proof, set)` — `POST /v1/verify/cross-log` | none |
| `api/judicial/verification_appeals.go:126` | `anchor.VerifyCrossLog(proof, set)` — `POST /v1/judicial/verification/cross-log-proof` | none |
| `consortium/federated_did.go:63` | `anchor.VerifyCrossLog(proof, sourceSet)` in `VerifyCrossCourtProof` | none |
| `verification/trust/multijurisdiction.go:236-240` | LAW 4 burn fail-closed | **only** here (authority walker) — a different path |

All four resolve `set` from a static boot `WitnessSets`/`witnessSetByLog` map and
never reference the journal/`BurnStatus` (grep of these four files for
`burn`/`journal`/`Equivocat` → none).

## Impact

| Scenario / Physics | Failure today |
|---|---|
| **Physics #4** | A burned/forked source log's well-formed proof returns `valid:true`/`verified:true` |
| **Scenario 1 / Goal 7** | The cross-log proof boundary is not fail-closed against a burned source |

## Proposed change

- Pass the auditor heads journal as the SDK-4 `BurnOracle` to all four sites
  (or pre-check `journal.BurnStatus(sourceLogDID)` before `VerifyCrossLog`), and
  return `ErrEquivocatedLog`.
- Surface it at the HTTP handlers as a distinct fatal status (not `valid:false`
  with a generic error) so a burned log is unambiguous to callers.

## Test plan

| Test | Asserts |
|---|---|
| `TestVerifyAppealChain_BurnedSource_Rejected` | source LogDID marked burned ⇒ chain verification halts with `ErrEquivocatedLog` |
| `TestVerifyCrossLogHandler_BurnedSource` | `POST /v1/verify/cross-log` ⇒ fatal equivocation status, not `valid:true` |
| `TestVerificationAppeals_BurnedSource` | `POST /v1/judicial/verification/cross-log-proof` ⇒ same |
| `TestVerifyCrossCourtProof_BurnedSource` | `consortium` path ⇒ same |

## Acceptance criteria

- [ ] All four call sites consult burn state via the SDK-4 oracle.
- [ ] A burned source ⇒ `ErrEquivocatedLog` at every path.
- [ ] Regression fixture: journal-marked-burned source rejected end-to-end.

## Dependencies / related

- Depends on **SDK-4**. Net-new relative to **judicial-network#69** (authority
  resolution scope, not the cross-log proof handlers).

## Evidence trail

```bash
grep -rn "anchor.VerifyCrossLog" --include=*.go verification/ api/ consortium/ | grep -v _test.go
grep -rn "burn\|Burn\|journal\|Journal\|Equivocat" verification/appellate_history.go \
  api/verification/handlers/verify_cross_log.go api/judicial/verification_appeals.go \
  consortium/federated_did.go   # expect: no results (the gap)
sed -n '236,240p' verification/trust/multijurisdiction.go
```
