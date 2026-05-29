# E2E — Cross-stack regression scenarios for the 4 mandates

> **Target repo:** clearcompass-ai/e2e-tests
> **Labels:** `test` · `zero-trust-physics`
> **Depends on:** SDK-1…4, AT-1, JN-1…4 (validates them end-to-end)
> **Status:** Proposal. The mandate failures are cross-repo; only an integrated
> suite proves the fixes hold across SDK → ledger → tools → JN. The harness
> already has the right shape.

## Why this exists

Four mandates fail today (Physics #1, Physics #4, Scenario 2, Scenario 4). Unit
tests in each repo are necessary but not sufficient — the guarantees are
emergent across the stack (e.g. JN resolves an `asOf` against the auditor journal
to verify a ledger-produced head under an SDK-reconstructed witness set). These
scenarios lock the behavior in CI once the upstream fixes land.

## Architectural fit (existing harness)

| Existing | Reuse for |
|---|---|
| `tests/phase8_determinism_test.go` | asOf determinism (Physics #1 / Scenario 3) |
| `tests/phase7_negative_test.go` (`TestS7_4_CrossExchangeReplay`, `TestS7_6_WitnessRollback`) | burn / fork negative cases as siblings |
| `tests/harness.go`, `tests/assert.go`, `internal/env`, `internal/types/wire.go` | spin-up + wire helpers |
| `SCENARIOS.md` | scenario registry to extend |

## Proposed scenarios

| New test | Asserts | Mandate |
|---|---|---|
| `TestS8_x_AsOfDeterminism` | same entry, two wall-clock instants across an activation boundary ⇒ identical verdict; unpinned `AsOf{}` rejected | Physics #1 / Scenario 3 |
| `TestS7_x_ForkPinning` | two heads at one sequence (R1≠R2); verdict pinned to RootHash; the other root fails closed | Scenario 4 |
| `TestS7_x_BurnedCrossLogRejected` | mark a source log burned, then `POST /v1/judicial/verification/cross-log-proof` ⇒ `ErrEquivocatedLog` (not `verified:true`) | Physics #4 |
| `TestS_x_Year15WitnessReconstruction` | rotate witnesses W1→W4; verify a W1-era bundle ⇒ passes under reconstructed W1, fails under W4 | Scenario 2 / Goal 13 |

## Test plan / fixtures

- Drive through real component endpoints (ledger admission, witness `/v1/cosign`,
  auditor journal, JN verify handlers) via the existing `harness`.
- For year-15: rotate the witness set across recorded heads in the auditor
  journal, then verify an early bundle through the JN path (exercises AT-1 + JN-2).
- For burn: emit/record an equivocation (same size, different root) so the
  journal burns the log (exercises AT-2 / the live monitor), then hit the
  cross-log proof endpoint (exercises JN-3 / SDK-4).

## Acceptance criteria

- [ ] All four scenarios green in CI against the integrated stack.
- [ ] Added to `SCENARIOS.md` with mandate references.
- [ ] Negative assertions are explicit (forbidden outcomes fail the test).

## Dependencies / related

- Depends on the SDK + JN + AT issues landing. Mirrors the per-issue unit tests
  at the integration layer.

## Evidence trail

```bash
ls tests/   # phase0..phase8 harness
grep -rn "func TestS7_\|func TestS8_" tests/phase7_negative_test.go tests/phase8_determinism_test.go
sed -n '1,40p' SCENARIOS.md
```
