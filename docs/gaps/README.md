# Zero-Trust Mandate Gap Catalog

This directory stages **file-ready GitHub issue drafts** for the gaps found while
auditing the implementation against the *15-Year Zero-Trust Mandates* (12
operational scenarios + 4 protocol-physics rules). Every claim in every draft is
backed by `file:line` evidence verified against the working branch, with a
reproducible `grep`/`go doc` evidence trail at the bottom of each file.

These are **drafts for review**, centralized here for a single PR. Each file's
header names its **real target repo** — the actual GitHub issue should be filed
there when approved. This catalog does not itself create any GitHub issues.

Format reference: `judicial-network#69` (PR-C tracker) — the quality bar for how
an issue is raised (status framing, fact→implication tables, file:line evidence,
test matrix, acceptance criteria, reproducible evidence trail).

## Audit result

12 scenarios + 4 physics → **9 satisfied · 3 partial · 4 violated**. The
violations cluster on one seam: the storage / admission / codec layers are
compliant, but the SDK's verification-API (`AsOf` selector + cross-log
primitive) cannot express the determinism, fork-pinning, historical
reconstruction, or burn-awareness the physics require.

## Final issue list (grouped by repo)

| # | Target repo | Title | Mandate | Depends on |
|---|---|---|---|---|
| **SDK-1** | baseproof/baseproof | Make `verifier.AsOf` mandatory — remove implicit latest/local-clock default | Physics #1 | — |
| **SDK-2** | baseproof/baseproof | Add `RootHash` fork discriminator to `AsOf`/`LogPosition` | Scenario 4 / Physics #2 | — |
| **SDK-3** | baseproof/baseproof | Add `WitnessSetAt(asOf)` historical witness-set reconstruction | Scenario 2 (Goal 13) | — |
| **SDK-4** | baseproof/baseproof | `anchor.VerifyCrossLog` must take a burn oracle and fail closed | Physics #4 | — |
| **AT-1** | baseproof/tooling | Journal-backed `WitnessSetAt` materialization | Scenario 2 | SDK-3 |
| **AT-2** | baseproof/tooling | Wire the dormant standalone equivocation `Scanner` | Scenario 12 | — |
| **JN-1** | clearcompass-ai/judicial-network | Pin cross-network resolution to RootHash (`HeadByRootHash`) | Scenario 4 | SDK-2 |
| **JN-2** | clearcompass-ai/judicial-network | Replace static `foreignSets` with journal-backed historical sets | Scenario 2 | SDK-3, AT-1 |
| **JN-3** | clearcompass-ai/judicial-network | Burn-gate the 4 `VerifyCrossLog` call sites | Physics #4 | SDK-4 |
| **JN-4** | clearcompass-ai/judicial-network | Adopt explicit Time-of-Receipt asOf (resolve #69 open item) | Physics #1 / Scenario 3 | SDK-1 |
| **E2E** | clearcompass-ai/e2e-tests | Cross-stack regression scenarios for the 4 mandates | all | all above |

**Ledger** — no new issue. All ledger-side scenarios (5 replay/domain-sep,
6 S3 fallback, 7 billion-entry, 8 dual-mode admission, 9 entry-level PQ,
12 wired equivocation monitor) verified satisfied. One **already-captured**
watch item: PQ at the witness cosign-quorum is blocked by the c2sp.org/tlog-tiles
64 KiB entry ceiling (`tessera/append_lifecycle.go:62-63`,
`baseproof/core/envelope/tessera_compat.go:98`, `baseproof/docs/crypto-size.md:15-16`,
`ledger/docs/v1.37.0-adoption-runbook.md:118`) — a spec-bound constraint, not an
actionable gap.

## Relationship to judicial-network#69 (PR-C)

#69's C-1…C-5 landed the **substrate** (heads journal keyed
`(LogDID,Sequence,RootHash)`, `MultiJurisdictionTrust`, peer registry,
`*WithTrust` migration). It did **not** deliver the zero-trust **hardening**:

- #69's own "Open considerations" leave the default-`asOf` question unresolved → **SDK-1 / JN-4**.
- #69 *assumes* the capability "asOf = head(seq, RootHash)" but the SDK `AsOf` type still can't carry a root → **SDK-2 / JN-1**.
- #69 Gap A (no historical-asOf head lookup) was addressed for *heads*; the *witness-set* reconstruction remains → **SDK-3 / AT-1 / JN-2**.
- Burn-gating the cross-log **proof** handlers is outside #69's authority-resolution scope → **SDK-4 / JN-3** (net-new).

## Recommended filing order

1. **SDK-1 … SDK-4** first (the root primitives).
2. Then **AT-1/2**, **JN-1…4**, **E2E** with `Depends on #<sdk>` links and a
   `Relates to judicial-network#69` backref on the JN four.

## Dedup note

`judicial-network#69` reviewed directly. The GitHub API was rate-limited during
the audit, so open issues in baseproof / tooling / ledger / e2e-tests were
**not** queried — run a dedup pass there (especially baseproof, for any existing
`AsOf`/PQ tickets) before filing SDK-1…SDK-4.
