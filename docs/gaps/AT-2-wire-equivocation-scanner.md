# AT-2 — Wire the dormant standalone equivocation `Scanner`

> **Target repo:** clearcompass-ai/attesta-tools
> **Labels:** `bug` · `defense-in-depth` · `equivocation`
> **Depends on:** —
> **Status:** Proposal. The standalone, sequencer-independent equivocation
> detector exists and is tested, but no binary runs it — so the "independent
> watchdog" half of Scenario 12 is dormant code.

## Why this exists

Scenario 12 (Orthogonal Equivocation Detection): *"The Gossip network and the
standalone Equivocation Monitor must independently catch the contradiction…
without requiring the primary ledger to self-report or coordinate the
detection."* Two independent detectors are mandated. Today only the
ledger-resident gossip peer-monitor runs; the dedicated standalone scanner is
unwired.

## Architectural ground truth

| Fact | Implication |
|---|---|
| Detection must be orthogonal to sequencing | A detector that lives only in the ledger is structurally separate but not a *second, independent* observer |
| The witness daemon does NOT detect | It's a Blind Notary by design (`services/witness/cmd/witness/main.go:26-28`) — it cosigns, delegates detection downstream |
| The scanner is complete but unwired | The capability exists; only the boot wiring is missing |

## Evidence (current behavior)

| File:line | Code | Note |
|---|---|---|
| `services/auditor/internal/equivocation/scanner.go:109` | `func NewScanner(cfg ScannerConfig) (*Scanner, error)` | exists; **zero non-test callers** (grep) |
| `services/auditor/internal/app/app.go:199-208` | constructs `equivocation.NewSlasher` + `monitoring.NewEquivocationResponder` only | read-side wired; detector not |
| `services/auditor/internal/gossipfeed/sink.go:169-173` | `evidenceSink.Broadcast` | the dissemination path the scanner would emit through |
| `ledger/gossipnet/equivocation_monitor.go:319-421` (+ `boot/wire/gossip.go:327`) | the **live** detector — but ledger-resident | the only running detector today |

## Impact

| Scenario | Failure today |
|---|---|
| **Scenario 12** | If the ledger-resident monitor is compromised/disabled, no independent detector runs; the mandated second observer is dormant |
| **Goal 14** | Reduced orthogonality of fraud detection |

## Proposed change

- Wire `equivocation.NewScanner` into the auditor boot (`app.go`) behind a config
  flag (peer-STH endpoints + poll interval), OR ship a dedicated watchdog binary
  under `services/`.
- Run the scanner loop independently of any ledger; emit `KindEquivocationFinding`
  via the existing `gossipfeed` sink.
- Keep it free of any `clearcompass-ai/ledger` import (the auditor module already
  enforces this — `services/witness/internal/serve/serve.go:20` documents the same
  discipline).

## Test plan

| Test | Asserts |
|---|---|
| `TestScanner_SameSizeDifferentRoot_Emits` | two mock peer heads, same size / different root ⇒ one verified `EquivocationFinding`, no ledger involvement |
| `TestScanner_SameRoot_NoEmit` | identical roots ⇒ no emit, no error |
| `TestAuditorBoot_ScannerWired` | with config present, boot constructs and starts the scanner loop |

## Acceptance criteria

- [ ] A ledger-independent detector runs in a deployable binary.
- [ ] It emits `KindEquivocationFinding` on a same-size/different-root collision with no ledger cooperation.
- [ ] No `clearcompass-ai/ledger` import in the detector's module.

## Dependencies / related

- Independent of the SDK issues. Complements the existing ledger-resident monitor.

## Evidence trail

```bash
grep -rn "NewScanner" services/auditor/internal/equivocation/scanner.go
grep -rn "equivocation.NewScanner" . | grep -v _test.go     # expect: no callers
grep -rn "NewSlasher\|NewEquivocationResponder\|NewScanner" services/auditor/internal/app/app.go
```
