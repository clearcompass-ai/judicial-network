# Attesta — Core Components (Architecture Reference)

> **Purpose.** One code-grounded map of every core component: what it is, where
> it lives, what it does, **what it deliberately does not do**, and how they
> connect. Every path/behavior is verified against source on this branch
> (per `ZT-ENG-VAL-01` *Code is Truth*).
>
> **Read in layers (each says a thing once):**
> 1. **Dictionary** — plain English + analogy + how many of each (start here).
> 2. **Reference** — the deep, code-grounded definition of each component.
> 3. **Pipelines** — how a request actually flows through them.

## The organizing principle

> **Infrastructure is dumb; truth is smart.** All "thinking" (domain logic,
> verification, policy) lives in the **SDK** and the **Auditors**; the **Ledger**
> and **Witness** are kept structurally blind. A component that cannot evaluate
> truth cannot bottleneck it (`ZT-SCN-08`, 1,000+ TPS); a component that cannot
> read payloads cannot censor them.

Components fall into four classes: **Actors** (Network, Exchange, Ledger,
Witness, Auditor, Judicial Network), the **Engine** (SDK), **Sub-systems**
(Tessera, Gossip, Heads Journal), and **Artifacts** (the nouns they exchange).

---

# Layer 1 — Dictionary (plain English)

> The simple on-ramp. If you read only one section, read this. Each term gets
> three framings: **definition · think of it as · connects to**. No file paths
> here — those live in the Reference below.

## The whole system in one breath

Picture a **county records office**: the **Network** is one record **book**; the
**Exchange** is the **office** that runs it; the **Ledger** is the **clerk** who
files entries in order and never judges them; the **Witnesses** are **notaries**
who stamp each new page without reading it; the **Auditors** are outside
**inspectors** who re-check every stamp; the **SDK** is the **rulebook**;
**Tessera** is the **filing cabinet and paper**; the **Gossip Network** is the
**courier** copying stamped pages to everyone; the **Heads Journal** is the
**permanent vault** that keeps every stamped page forever.

## The terms

- **Network** — one logbook with a permanent ID (NetworkID). *Think of it as:* one record book on the shelf. *Connects to:* **submissions are addressed to it**; run by 1 Exchange; cosigned by its witness set; watched by many Auditors.
- **Exchange** — the company that **operates** a Network. *Think of it as:* the records office (front desk, building). *Connects to:* runs the admission gate + Ledger + Witness infra; **cannot rewrite history**.
- **Ledger** — the sequencer that orders bytes. *Think of it as:* the clerk who files in order and never judges. *Connects to:* serves 1 Network; **admits only what the Network gate passed**; defers all judgment to the SDK; writes into Tessera.
- **Witness** — a blind notary; one of K-of-N cosigners. *Think of it as:* a notary who stamps a page without reading it. *Connects to:* stamps Tree Heads; its stamps become the Auditor's evidence. *(Detective, not preventative — it does not stop forks.)*
- **Auditor** — independent monitor and fraud-catcher. *Think of it as:* an outside inspector who re-does the math. *Connects to:* reads Gossip + the Heads Journal; runs the SDK to render verdicts; can slash/burn a lying log.
- **Judicial Network (JN)** — an Auditor specialized for cross-network trust. *Think of it as:* an inspector for one court that also verifies references to other courts' books.
- **SDK** — the shared rulebook (all the smarts). *Think of it as:* the law everyone follows. *Connects to:* imported by every component; runs nothing itself.
- **Tessera** — the append-only log + static tiles. *Think of it as:* the filing cabinet and paper. *Connects to:* written by the Ledger; **read by anyone, anonymously, even offline**.
- **Gossip Network** — pull-based copying of heads and findings. *Think of it as:* the courier. *Connects to:* every Ledger publishes; every Auditor pulls (no one self-reports).
- **Heads Journal** — the permanent vault of every cosigned head. *Think of it as:* the archive that never throws anything away. *Connects to:* written by the Auditor's reconciler; read for history/forks/burns; **never pruned**.
- **Artifacts** — *Entry* = one filed record; *Tree Head* = the running fingerprint of the whole book; *Bundle* = a self-contained certified copy you can verify alone; *Witness Set* = the current notary roster (rotates; old rosters kept forever).

## How they interconnect (the counts)

| Relationship | Count | Plain English |
|---|---|---|
| Exchange → Network | **1 → many** | One office can run several books |
| Network → Exchange | **1 → 1** | A book has exactly one operating office |
| Network → admission gate → Ledger → Tessera | **1 → 1 → 1 → 1** | One book: one gate, one clerk, one cabinet |
| Network → Witnesses | **1 → N** (need **K**) | Stamped by a small notary set; most must agree |
| Network → Auditors | **1 → many** | Anyone can independently inspect (more = safer) |
| Auditor → Networks | **1 → many** | One inspector can watch many books |
| JN → home / foreign Networks | **1 / many** | Audits its own book; verifies pointers into others |
| Network → Entries → Tree Heads | **1 → billions → many** | Billions of pages; a running stamp per batch |
| Network → Witness Sets | **1 active + many historical** | The roster rotates; old rosters kept for Year-15 proofs |

> **Worked example.** *"Tennessee Courts"* is **one Network**, run by **one
> Exchange**, with **one admission gate** in front of **one Ledger** sequencing
> into **one Tessera** log. Each head is stamped by, say, **5 Witnesses under
> 3-of-5**. **Several Auditors** plus **one JN** watch it; if the operator signs
> two roots at one page number, *any* Auditor catches it from the Witnesses' own
> stamps and **burns** the book — nobody had to trust the operator to confess.
> *(Counts like 3-of-5 are per-Network charter choices; the relationships above
> are the invariants.)*

```
   Exchange (operator)                         Auditor / Judicial Network
      │ runs                                        ▲ pulls          │ runs SDK
      ▼                                             │                ▼
   Network ──submit──▶ [Admission Gate] ──pass──▶ Ledger ──▶ Tessera (public tiles)
   (NetworkID)         destination + auth          │ (dumb)         │
                       + Mode A/B  (pre-WAL)        │ asks to stamp  │ anyone reads
                                                    ▼                ▼  (anon, offline)
                                            Witness Set (K-of-N) ──▶ Tree Head
                                                    │ stamps = evidence
                                                    ▼
                                            Gossip ──▶ Heads Journal (forever)
```

---

# Layer 2 — Component Reference (code-grounded)

## Index

| Component | Class | Where | Duty |
|---|---|---|---|
| Network | Actor | `attesta/network/`, `crypto/cosign` (NetworkID) | The logbook; the addressed target of submissions |
| Exchange | Actor | `attesta/exchange/`, `ledger/api/` | Operates the Network; economic firewall |
| Ledger | Engine | `ledger/` | Network admission gate **+** dumb sequencer |
| Witness | Actor | `attesta-tools/services/witness/` | Blindly cosigns tree heads |
| Auditor | Actor | `attesta-tools/services/auditor/` | Re-runs the math; detects fraud; slashes |
| Judicial Network | Actor | `judicial-network/` | Cross-network trust specialization of the Auditor |
| SDK | Engine | `attesta/` | Owns all domain logic, crypto, schema, verification |
| Tessera | Sub-system | `tessera/`, `ledger/tessera/`, `ledger/bytestore/` | Append-only log + transparently-fetched static tiles |
| Gossip Network | Sub-system | `attesta/gossip/`, `attesta-tools/libs/monitoring/` | Pull-based dissemination (the Transparency Clock) |
| Heads Journal | Sub-system | `attesta-tools/libs/monitoring/`, `auditor/.../store/` | Permanent, fork-aware archive of cosigned heads |

> Format per entry: **Duty · Where (file:line) · Mechanism · Boundaries (what it
> does NOT do) · Why.** Interconnection is in Layer 1 (counts) and Layer 3 (flow)
> — not repeated here.

## Actors

### Network — *the logbook & the addressed target*
- **Duty.** Be the atomic unit of the chain: one append-only log with a permanent **NetworkID** from its founding charter; the entity a submission is *addressed to*.
- **Where.** `cosign.NetworkID` / `NetworkIDFromWire` in `attesta/crypto/cosign/`; charter/bootstrap in `attesta/network/`.
- **Mechanism.** The NetworkID is mixed into every cosignature digest and is the `Destination` a submission must name. It is the gate's domain identity (see Ledger).
- **Boundaries.** Not a process; not the operator; not the storage. It can outlive its operator (`ZT-SCN-07`).
- **Why.** The subject of **cryptographic domain separation** (`ZT-SCN-05` / `ZT-SDK-11`): a submission signed for Network A fails on Network B.

### Exchange — *the operator*
- **Duty.** The legal/operational identity that runs a Network: API surface, infrastructure, and the **economic firewall** (rate-limit, write credits / bonds).
- **Where.** `attesta/exchange/` (e.g. `exchange/auth/signed_request.go`); operates the Ledger admission API (`ledger/api/`).
- **Mechanism.** Accepts submissions at the Network boundary, funds Mode A credits, runs the Witness + Ledger stack, serves reads.
- **Boundaries.** **Lacks cryptographic authority to rewrite history** — it cannot forge a witnessed head, mutate a sealed payload, or drop an entry without being caught.
- **Why.** Trust never rests on operator honesty; it rests on the recomputed quorum and the Auditor's math.

### Ledger — *the network admission gate + the dumb sequencer*
- **Duty.** Gate submissions for the Network, then order the admitted bytes. Two distinct layers.
- **Where.** Gate: `ledger/admission/` (`write_auth_gate.go`, `pow_gate.go`, `network_payload_validator.go`, `entry_signature_verifier.go`, …) + `ledger/api/submission.go`. Sequencer: `ledger/wal/` (Badger WAL), `sequencer/`, `ledger/tessera/`.
- **Mechanism.**
  - **Admission gate (network-keyed, pre-WAL).** `api/submission.go:481-486` rejects `Header.Destination != deps.LogDID` (`ErrorClassDestinationMismatch`); then signature/schema/policy verify (`:529`); then **Mode A** credit (`store/credits.go:62`, *"before wal.Submit … never gets an SCT or a slot in the WAL"* `:746-748`) or **Mode B** PoW (`admission/pow_gate.go:191`).
  - **Dumb sequencer (post-admission).** Only on success → `WAL.Submit` → returns an **SCT** (committing to the MMD) → Shipper sequences into Tessera. *"admission writes wire bytes to the WAL only"* (`api/submission.go:164`).
- **Boundaries.** The sequencer holds **ZERO domain logic** (`ZT-SOD-01`) — it never decides if a court order is lawful. The gate enforces only network/domain admission, not domain truth (that's the SDK's, run later by Auditors).
- **Why.** Gate-then-sequence keeps the hot path melt-proof (`ZT-SCN-08`); reads/writes share zero mutexes; the two clocks decouple ingest from gossip (`ZT-LED-12`).

### Witness — *the blind notary*
- **Duty.** Lend cryptographic weight (one of **K-of-N**) attesting a Tree Head was presented at a moment in time.
- **Where.** `attesta-tools/services/witness/internal/serve/serve.go` (cosign handler; signer at `:150`); `cmd/witness/main.go`. *(`witkey/witkey.go` is only key loading.)*
- **Mechanism.** Reads only the Target Root + Sequence size and signs the dense log root. Its sole state is a RAM-only, per-process `lastSignedSize` misfire guard (`serve.go:245-302`).
- **Boundaries — Detective, not Preventative (`ZT-WIT-01`).** It does **not** prevent forks: *"size-only monotonicity does not prevent a fork"* (`serve.go:48`), it has *"no log access"* to check consistency (`:54`), and *"fork detection is a DETECTIVE control owned by the auditors"* (`:61`, `main.go:26`). It cannot read payloads → cannot censor.
- **Why.** A Witness blindly cosigns **both** sides of a same-sequence fork — and that is the point: two valid K-of-N cosignatures are the **evidence** the Auditor uses to prove equivocation (`ZT-SCN-06`).

### Auditor — *the enforcer of truth*
- **Duty.** Enforce physics, resolve cross-network trust, detect fraud — asynchronously and orthogonally to the Ledger.
- **Where.** `attesta-tools/services/auditor/`; runs `attesta/verifier/verify_complete.go` and the reconciler `attesta-tools/libs/monitoring/gossip_reconciler.go`.
- **Mechanism.** **Equivocation** — `services/auditor/internal/equivocation/slasher.go:111` (+ `scanner.go`): conflicting RootHash → `KindEquivocationFinding` → slash/freeze. **Cross-log** — `attesta/verifier/cross_log.go`, `anchor/anchor.go:213`: authenticate foreign proofs against the *foreign* head. **Policy** — `attesta/verifier/policy_stage.go`: did the `Signer_DID` hold authority **at that `asOf`**?
- **Boundaries.** Does not sequence, does not hold the write path, does not require the offending Ledger to self-report.
- **Why.** Where Separation of Duties lives — turns Witness evidence into burns/slashes.

### Judicial Network (JN) — *the domain-specialized Auditor*
- **Duty.** An Auditor deployment for cross-network trust (e.g. courts): foreign-log authority, cross-log proof verification, delegation/policy.
- **Where.** `judicial-network/` — `verification/trust/multijurisdiction.go` (`MultiJurisdictionTrust`), cross-log handlers, `consortium/`.
- **Mechanism.** Audits one home Network; verifies references into foreign logs against the foreign log's own witnessed head, resolved from the Heads Journal at `asOf`.
- **Boundaries.** Does not operate foreign Networks; does not "pick" a fork — on a verified fraud proof it transitions the log to **BURNED/FROZEN** (`ZT-IMM-04`).
- **Why.** The canonical consumer of the SDK's trust machinery. *(See `docs/gaps/` — JN-1…JN-4 track its remaining zero-trust hardening.)*

## Engine

### SDK — *the smart brain*
- **Duty.** Own **all** domain logic, cryptography, schema, and verification — the single Universal Source of Truth (`ZT-SDK-01`). Every other component defers to it.
- **Where.** `attesta/` — `verifier/` (`verify_complete.go`, `policy_stage.go`, `cross_log.go`, `log_trust.go`), `crypto/`, `anchor/`, `did/`, `core/envelope/`, `log/bundle/`, `witness/`, `gossip/`, `schema/`, `delegation/`, `authz/`, `types/`.
- **Mechanism.** Fail-closed in a single frame (`ZT-SDK-03`); Parse-Don't-Validate; identity-agnostic (`ZT-SDK-09`); per-signature PQ dispatch (`ZT-SCN-10`); all within the 65,535-byte cap (`core/envelope/tessera_compat.go:98`).
- **Boundaries.** Runs no servers, stores no state — a pure library. Infrastructure blindly drops whatever it rejects.
- **Why.** It is *where truth lives*; without it the SoD story has no subject.

#### SDK internal architecture (three evidence-based views)

**View A — the 4-layer cross-log trust spine** (the verification core everything hangs off; `docs/design/cross-log-authority-resolution.md`). *"Every hop is verified under its own log's trust root; the as-of selector unifies time, cross-log, and fork into one mechanism."* Higher layers compose lower ones and never bypass them; **3 and 4 both consume 1 but are independent of each other.**

| # | Layer | Symbol (verified in code) | Gap-catalog tie-in |
|---|---|---|---|
| **1** | Trust provider (the seam) | `verifier.LogTrustProvider` (`verifier/log_trust.go`) — yields `(WitnessSet, Head, EntryProof, LeafProof)` per `LogDID` at an `asOf` | **SDK-1** (mandatory `asOf`), **SDK-2** (RootHash on the selector) |
| **2** | Implementations | `verifier.SingleLog` (degenerate) · `anchor.MultiLog` (`anchor/multilog.go:56`) · JN `MultiJurisdictionTrust` | **JN-1** (RootHash pin), **JN-2** (journal-backed sets) |
| **3** | Trust-aware walkers | `verifier.EvaluateAuthorityWithTrust` / `VerifyDelegationProvenanceWithTrust` | **JN-4** (Time-of-Receipt `asOf`) |
| **4** | Cross-log composites | `verifier.VerifyCrossLogProof` (`cross_log.go:128`) · `VerifyCompoundProof` / `ResolveCrossLogRef` (`cross_log_compound.go:155,211`) | **SDK-4 / JN-3** (burn-gate) |

**View B — the dependency foundation** (derived from `go list`, *not* docs). The SDK is a one-way DAG with a genuinely pure base:
- **Pure base** (imports *nothing* internal): `types`, and the leaf crypto `crypto/hash`, `crypto/signatures`.
- **Wire/core:** `core/envelope` (→`types`), `core/smt` (→`core/envelope`).
- **Crypto compositions (NOT pure):** `crypto/cosign` (→`crypto/signatures`,`types`,`internal/wireerror`), `crypto/escrow`/`crypto/artifact` (→`core/envelope`,`core/vss`,`storage`,…).
- **Domain / verification:** `schema`, `attestation`, `authz`, `did`, `network`, then `verifier`, with `anchor` and `gossip/findings` at the top (`anchor`→`verifier`+`gossip`).

> ⚠️ **`crypto/about.md` is outdated — do not cite it.** It calls `crypto/` the *"Pure Cryptography Layer (Layer 1)… imports nothing but standard Go."* `go list` disproves this: `crypto/cosign` imports `types`+`crypto/signatures`+`internal/wireerror`; `crypto/escrow`/`artifact` import `core/envelope`/`core/vss`/`storage`. **Only the leaf crypto packages are pure.** The DAG above (toolchain-derived) is the truth.

**View C — the 5-layer package-role model** (`docs/layers-roles.md`, secondary): **1** Entry plane (`core/envelope`,`crypto/signatures`,`types`) · **2** Schema & policy (`schema`,`attestation`) · **3** On-log policy walkers (`network`,`authz`) · **4** Witness plane (`crypto/cosign`,`witness`) · **5** Federation & cross-log (`anchor`, cross-log composites). This is a *role* grouping, **not** a strict import order — e.g. role-L3 `network` imports role-L4 `crypto/cosign`, so the numbers label planes, not topological height. (Use View B when you need the real dependency direction.)

## Sub-systems

### Tessera — *the log storage engine & transparent tiles*
- **Duty.** Be the append-only Merkle log + static `c2sp.org/tlog-tiles` tiles beneath the Ledger, and serve those tiles **transparently**.
- **Where.** Upstream `github.com/transparency-dev/tessera` (`tessera/`); integrated via `ledger/tessera/`; tiles served from object stores via `ledger/bytestore/{s3,gcs,publicurl,tile_backend}.go`; SDK-side bounded fetch `attesta/log/tessera_fetcher.go`; cross-log mirrors `attesta-tools/libs/auditing/gossipverify/tile_mirror.go`.
- **Mechanism — transparent fetch (the read side of `ZT-LED-10`).**
  - **Anonymous / credential-free** — public-read buckets, no API key or session (`bytestore/publicurl.go`: *"anonymous-read … no expiry"*; `s3.go:288`).
  - **Deterministic addressing** — a tile's URL is a pure function of its coordinates (`publicurl.PublicURL(seq, hash)`); any client computes any tile's location with no operator query.
  - **Trust the root, not the server** — tile bytes are authenticated by local Merkle recomputation against the cosigned Tree Head's RootHash (`ZT-LIM-02/03`); a hostile mirror cannot forge a tile that hashes to the trusted root.
  - **Interchangeable mirrors / failover** — any source returns byte-identical tiles; `ledger/store/fetcher.go` falls through WAL → object store; `gossipverify` `HTTPTileMirrors` maps source-log DID → mirror.
  - **Bounded** — `tessera_fetcher.go:79` `MaxTileBytes = 16,777,472` via `io.LimitedReader` (`ErrTileTooLarge`) → safe to fetch from an untrusted source.
- **Boundaries.** Content-agnostic (leaves are 32-byte hashes, `ZT-LIM-02`); enforces the 65,535-byte entry cap (a spec invariant, not a knob). Ledger only *reads* tiles; Tessera owns writes.
- **Why.** Anonymous, deterministic, root-checked tiles are what make the **dissolved-ledger fallback** work: in Year 12 a verifier authenticates Year-2 evidence from read-only tiles with no operator API (`ZT-SCN-07`). *(Enhancement on file: set `Cache-Control: immutable` on tile PUTs — not currently in `bytestore/`.)*

### Gossip Network — *the transparency fabric*
- **Duty.** Disseminate heads, findings, and equivocation proofs across peers, pull-based and fire-and-forget (the "Transparency Clock").
- **Where.** `attesta/gossip/`, `attesta-tools/libs/monitoring/gossip_reconciler.go`, `ledger/gossipnet/`.
- **Mechanism.** Peers **pull** proven events via HTTP caches/CDNs (`ZT-LED-11`); Lamport time makes re-receipt idempotent (`ZT-SDK-14`); emit queues never block the commit hot-path (`ZT-SDK-13`).
- **Boundaries.** Carries no authority — gossip is transport; a received finding is re-verified by the SDK before action.
- **Why.** How Witnesses, Auditors, and peers learn state **without trusting the Ledger to self-report** (`ZT-SCN-06`); gossip degradation cannot pause ingestion (`ZT-LED-12`).

### Heads Journal — *the cryptographic bedrock*
- **Duty.** Durably archive every cosigned head, addressable historically and fork-aware.
- **Where.** `attesta-tools/libs/monitoring/heads_journal.go` (+ `_memory.go`); Postgres at `attesta-tools/services/auditor/internal/store/heads_journal.go`.
- **Mechanism.** Primary key **`(LogDID, Sequence, RootHash)`** (`store/heads_journal.go:110`) → a fork stores both rows and triggers the burn transition in one advisory-locked txn. Reads: `HeadAt`, `HeadAtTime`, `HeadByRootHash`, `HeadsAtSequence`, `LatestHead`, `BurnStatus`; `ErrEquivocatedLog` on burned logs (`:279`).
- **Boundaries.** A *witness, not a judge* — records both forks, lets the responder decide slashing. **Never pruned** (no TTL, no PruneJob hook).
- **Why.** The single substrate behind `asOf` history (`ZT-SCN-03`), fork-ID (`ZT-SCN-04`), Year-15 reconstruction (`ZT-SCN-02`), and burn fail-closed (`ZT-IMM-04`). ~250M rows / 15 yrs ≈ tens of GB — trivial; permanent bedrock (`ZT-IMM-03`).

## Artifacts

| Artifact | Where | What it is |
|---|---|---|
| **Entry / Envelope** | `attesta/core/envelope/` | Canonical signed unit (payload + control header + N signatures), ≤ 65,535 B; `Destination` is bound into the signed hash |
| **Cosigned Tree Head (STH)** | `attesta/crypto/cosign/` | Merkle root + K-of-N witness cosignatures, NetworkID-bound — the Universal Anchor (`ZT-ALN-01`) |
| **Bundle** | `attesta/log/bundle/` | Self-contained, offline-verifiable artifact (entry + inclusion proof + cosigned head + SMT proof); `FormatV1` is frozen (`ZT-SCN-12`) |
| **Cross-Log Proof / Anchor** | `attesta/anchor/`, `verifier/cross_log.go` | Binds one log's entry into another's tree — the cross-network trust artifact (`ZT-SCN-01`) |
| **Witness Set / Quorum** | `attesta/crypto/cosign/witness_key_set.go` | Immutable K-of-N keyset bound to a NetworkID; rotates via verified events; reconstructable at any `asOf` |
| **Identity / DID** | `attesta/did/` | Signer identities — did:web, did:pkh/EIP-1271, mTLS, role/vendor DIDs (`ZT-SCN-11`) |

---

# Layer 3 — How it all connects (pipelines)

Two physically decoupled clocks (`ZT-LED-12`). Neither blocks the other — which
is why the system stays melt-proof at scale while remaining zero-trust.

## The write path — *Commit Clock (synchronous)*

1. An **Exchange** receives a submission **addressed to its Network** (`Header.Destination = NetworkID`).
2. The **Network admission gate** (`ledger/admission/`) vets it **before any write**: destination binding (`Destination == LogDID`), signature/schema/policy, then **Mode A** credit *or* **Mode B** PoW. A rejected submission **never reaches the sequencer**.
3. Only on success does the **dumb Ledger** append to the **Badger WAL** and return an **SCT** (committing to sequence within the MMD).
4. Background workers sequence the **Entry** into **Tessera** and ask the **Witnesses** to cosign the new **Cosigned Tree Head**.

> The gate is network-keyed; the sequencer is domain-blind. That is the literal
> meaning of *"the Network gates submission to the Ledger."*

## The transparency path — *Transparency Clock (asynchronous)*

1. The **Gossip Network** disseminates each cosigned head and any findings, pull-based.
2. An **Auditor** (or the **JN**) ingests them, records every head into the **Heads Journal**, and re-runs the **SDK** math.
3. A conflicting RootHash at one sequence → `KindEquivocationFinding` → the log is **burned**.
4. To verify a **Cross-Log Proof** or an authority `asOf`, the Auditor resolves the historical **Witness Set** from the Journal and authenticates a **Bundle** — fetching any needed **Tessera tiles transparently** (anonymous, deterministic-addressed, root-checked, from any mirror), with **no live operator API** (`ZT-SCN-07`).

---

# Layer 4 — Repo topology & cross-repo connectivity

> Derived from `go.mod` requires + actual imports (`go list`), not prose.

## The dependency graph (who imports whom)

```
        attesta  (SDK — the foundation; imports no sibling repo)
        ▲   ▲   ▲
        │   │   └─────────────── ledger              imports attesta ONLY
        │   └────── attesta-tools (libs + services)  imports attesta
        │                  ▲
        └──────────────────┴──── judicial-network    imports attesta + attesta-tools/libs
```

| Repo | Imports (verified) | Role in the stack |
|---|---|---|
| **attesta** (SDK) | — (foundation) | The Smart Brain. Every repo imports it; it imports none of them. Houses the 4-layer trust spine (View A). |
| **ledger** | `attesta` **only** (`go.mod`; **0** files import attesta-tools) | The operator stack: network admission gate + Badger WAL + Tessera sequencer + gossipnet equivocation monitor. A self-contained SDK consumer. |
| **attesta-tools** | `attesta` | Operator/auditor **libs** (`libs/monitoring` heads-journal, `libs/crosslog`, `libs/gossipingest`, `libs/auditing/gossipverify` tile-mirrors, …) **+ services** (`services/auditor`, `services/witness`) — each service is its **own module** that **never imports the ledger**. |
| **judicial-network** | `attesta` **+** `attesta-tools/libs` (**71** non-test files) | The domain consumer: court business logic over the SDK trust spine + tools libs. |

**Two facts worth pinning:**
- **The ledger does *not* depend on attesta-tools** — it is a pure SDK consumer; the auditor/witness tooling sits *beside* it, not beneath it.
- **The witness & auditor services never import the ledger** (separation of duties enforced at the *module* boundary, not just by convention) — so detection/attestation cannot be coupled to sequencing.

## JN internal layers (derived — JN ships no canonical layer doc)

| JN layer | Packages | Maps to the SDK trust spine (View A) |
|---|---|---|
| **Domain** | `cases/`, `appeals/`, `parties/`, `escrow/`, `delegation/`, `jurisdiction/`, `policy/`, `enforcement/`, `topology/`, `schemas/` | Populates SDK **View C Layer 2** (schema & policy) with court schemas |
| **Verification / trust** | `verification/`, `verification/trust/` (`MultiJurisdictionTrust`) | **Spine Layer 2 impl**; consumes Spine Layers 3 & 4 |
| **API** | `api/` (verify handlers, judicial + cross-log-proof endpoints) | Drives **Spine Layer 4** composites (`VerifyCrossLog`) and **Layer 3** walkers |
| **Federation** | `consortium/` | **Spine Layer 4 / View C Layer 5** (cross-log) |
| **Composition root** | `cmd/network-api/` | Boots the trust provider + Heads Journal + foreign witness sets |

## End-to-end connectivity (one hop per line)

1. The **ledger** (SDK-only) sequences a Network's entries behind its admission gate and publishes cosigned heads over gossip.
2. **attesta-tools** `gossipingest`+`monitoring` ingest those heads into the **Heads Journal**; `services/auditor` re-verifies and slashes; `services/witness` cosigns on the commit path — all on **SDK** crypto/verifier, **none importing the ledger**.
3. The **JN** builds `MultiJurisdictionTrust` (**Spine Layer 2**) over the tools **Heads Journal** + **tile mirrors**, drives the SDK **WithTrust walkers** (**Layer 3**) and **cross-log composites** (**Layer 4**) from its **API** layer, and applies its **domain** packages for court policy.

> The throughline: a single **SDK trust spine** (View A) is instantiated by `anchor.MultiLog` in-process, by `MultiJurisdictionTrust` in the JN, and consumed by the ledger's admission gate — so cross-log verification resolves *identically* whoever runs it. That uniformity is the whole point of pushing trust into the SDK.
