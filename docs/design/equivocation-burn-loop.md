# Design: Equivocation enforcement — the burn loop

Status: **verified against `judicial-network` main `f6bd042`** · Scope:
`judicial-network` (the enforcement wiring) · Depends on: `baseproof` (the trust
Gate, SDK-4) + `tooling/libs/monitoring` (the `HeadsJournal`) · Siblings:
`baseproof/verifier/trust_status.go`, `tooling/libs/monitoring/heads_journal.go`

> **Why this doc exists.** The integrity claim *"an equivocating source log can never
> be trusted by a cross-log verifier"* is only as strong as the **linkage** between
> the component that DETECTS equivocation and the component that ENFORCES it. This
> doc records the end-to-end proof — verified against code, `file:line` — that
> detection (the journal's ingest path) and enforcement (`StatusFor` →
> `VerifyCrossLog`) read and write the **same journal instance**, joined at a single
> wiring line. The rule: **detection writes the journal; the SDK owns the gate; they
> share one store.**

This document is pointer-shaped: where this prose and the cited code ever disagree,
the code wins.

---

## The two-axis model

A cross-log proof from a source log has two independent properties, checked by two
independent mechanisms:

- **Is the proof cryptographically valid?** — K-of-N witness quorum over the source
  head, replayed by the consumer (`anchor.VerifyCrossLog` →
  `verifier.VerifyCrossLogProof`).
- **Has the source log been observed to equivocate (burned)?** — a *trust* input,
  pinned offline, consulted **before** any cryptographic work.

The split is deliberate and stated in the SDK: *"a validly-cosigned head from a
burned log is still cryptographically valid — quorum signed it — [but] must not be
trusted"* (`baseproof/verifier/trust_status.go:5-6`). And the ownership boundary:
*"The SDK owns the GATE, not burn DETECTION. Detection is the auditor's Heads
Journal"* (`baseproof/verifier/trust_status.go:17`), mirrored on the JN side: *"JN
owns DETECTION (the gossip reconciler writes the HeadsJournal), the SDK owns the
GATE"* (`verification/trust/burn.go:14`).

So burn enforcement is a producer → store → consumer loop. The rest of this doc
proves the store is **one instance** across producer and consumer.

---

## The complete chain (every link cited)

```
source log equivocates → two divergent CosignedTreeHeads on the wire
  → reconciler ingests both           (cmd/network-api/gossip_reconciler.go:188,202)
  → MemoryHeadsJournal.Record         (tooling/libs/monitoring/heads_journal_memory.go:80)
        conflict @ (LogDID,Sequence)  →  Burned=true   (:111-140)
  ──────────────── SAME sharedJournal instance ────────────────
  → judicialDeps.HeadsJournal = gossipPipelines.Journal   (cmd/network-api/main.go:325)
  → handler: jntrust.StatusFor(ctx, h.deps.HeadsJournal, src)
                                       (api/judicial/verification_appeals.go:87)
  → journal.BurnStatus → {Burned:true} (verification/trust/burn.go:45-51)
  → anchor.VerifyCrossLog(proof, set, trust) → ErrEquivocatedLog
                                       (baseproof/anchor/anchor.go:228; trust_status.go:41)
  → appeal hop ProofVerified=false     (verification/appellate_history.go:183-185)
```

---

## Link 1 — the journal detects equivocation at ingest

`MemoryHeadsJournal.Record` (`tooling/libs/monitoring/heads_journal_memory.go:80`) is
both the write path AND the detector — there is no separate "mark-burned" call that
could be left unwired:

- **Conflict detection** (`:111-119`): a different `RootHash` already present at this
  `(LogDID, Sequence)` → `equivocation := len(existing) > 0`.
- **Burn transition** (`:130-140`): the first observation flips the log →
  `BurnStatus{Burned: true, FirstForkSequence, ConflictingRoots}`.
- **Fail-closed thereafter** (`:126-127, 145-146`): a burned log's `LatestHead`
  freezes; `HeadAt` / `HeadAtTime` / `LatestHead` consult the burn map first and
  return `ErrEquivocatedLog`.
- **Monotonic + irreversible** (`:147-152`): further forks accumulate into
  `ConflictingRoots`; nothing clears `Burned`.

The journal burns from the **raw conflicting heads**, not from any published
`KindEquivocationFinding`. That is strictly stronger: the JN re-derives burn from
primary evidence rather than trusting a claim. The ledger's equivocation
monitor/scanner + finding
(`tooling/services/ledger/gossipnet/equivocation_monitor.go`) remain a complementary
propagation path for other consumers, **not** a dependency of this gate.

---

## Link 2 — the keystone: one journal instance, producer and consumer

The reconciler (writer) and `StatusFor` (reader) operate on the same Go object:

```
gossip_reconciler.go:171   sharedJournal := monitoring.NewMemoryHeadsJournal()   // ONE
gossip_reconciler.go:181   Journal: sharedJournal                                // writers
gossip_reconciler.go:29-30 "All pipelines write into the SAME … HeadsJournal"

main.go:325   judicialDeps.HeadsJournal = gossipPipelines.Journal   ◄── THE IDENTITY

verification_appeals.go:87 jntrust.StatusFor(ctx, h.deps.HeadsJournal, src)
burn.go:45                 journal.BurnStatus(ctx, logDID)
```

`h.deps.HeadsJournal` == `judicialDeps.HeadsJournal` == `gossipPipelines.Journal` ==
`sharedJournal`. The object the reconciler `Record`s into is the same object the
appeal-chain handler hands to `StatusFor`. No copy, no second store, no sync gap.
`buildMultiJurisdictionTrust` is handed the same journal (`main.go:337`), so the
multi-network ingest writes through the one store too.

---

## Link 3 — the gate, fail-closed at every edge

`StatusFor` (`verification/trust/burn.go:41-56`) maps the journal's burn state to the
SDK's `verifier.TrustStatus`, and every failure edge resolves closed:

| Edge | Result |
|---|---|
| nil journal | zero `TrustStatus` (`Known=false`) → `ErrTrustUnknown` (`burn.go:42-43`) |
| journal read error | zero `TrustStatus` → `ErrTrustUnknown` (`:46-47`) |
| burned log | `Known=true, Burned=true` → `ErrEquivocatedLog` (`trust_status.go:41`) |
| warming journal (post-restart) | era resolver returns `ErrWarming` → retryable **503**, verification aborts (`appellate_history.go:177-178`) |

The contract is explicit: *"We never synthesise `Known=true` without a real consult —
that would defeat SDK-4"* (`burn.go:24-25`). A new cross-log call site that forgot to
build `trustByLog` fails closed, not open.

All three production call sites consult the journal: the appeal-chain walker
(`api/judicial/verification_appeals.go:86-90`), the single-hop cross-log verify
(`api/verification/handlers/verify_cross_log.go:64`), and the consortium handler
(`api/judicial/consortium.go:189`).

---

## Honest nuances — none is a hole

1. **In-memory journal, rebuildable + fail-closed while warming.** This binary uses
   the `MemoryHeadsJournal` (`gossip_reconciler.go:40-42`); the durable
   `PostgresHeadsJournal` lives with the auditor. The in-memory one is a *projection*
   of the gossip log — it rebuilds on restart by re-ingesting. The warming window does
   not open a trust gap: the era resolver returns `ErrWarming` → 503, aborting rather
   than proceeding on an empty journal.
2. **You must observe both forks to burn.** The journal can only burn a log if both
   conflicting heads reach *it* — the irreducible detective-system property. Multi-
   pipeline ingest (home + foreign + peer) maximizes that, and the `StatusFor` default
   is fail-closed on an unconsulted source. Worst case is a missed detection (which any
   honest peer can still surface), never a silent trust of a *known*-burned log.
3. **Detection is doubled at the source.** Beyond the journal's ingest-time detection,
   the ledger runs a peer-comparison monitor and a standalone split-ID scanner (the
   latter wired at `tooling/services/ledger/cmd/ledger/boot/wire/gossip.go:443`), each
   publishing verify-before-broadcast evidence across all four violation classes
   (equivocation, history-rewrite, SMT-replay, ghost-leaf).

---

## Verdict

A conflicting head ingested by the reconciler sets `Burned` in the exact
`sharedJournal` instance that `StatusFor` reads and `VerifyCrossLog` gates on, joined
at `cmd/network-api/main.go:325`. Detection and enforcement are the same store; the
transition is monotonic and irreversible; every failure edge resolves fail-closed.
**The producer → journal → consumer path has no hole.**

## How to re-verify

```sh
# the keystone identity (producer-journal == consumer-journal)
grep -n 'HeadsJournal = gossipPipelines.Journal' cmd/network-api/main.go

# the journal self-detects the conflict and burns
sed -n '111,152p' ../tooling/libs/monitoring/heads_journal_memory.go

# the consumer reads the same journal, fail-closed by construction
sed -n '41,56p' verification/trust/burn.go

# the SDK gate rejects a burned source before any crypto work
grep -n 'ErrEquivocatedLog' ../baseproof/verifier/trust_status.go
```
