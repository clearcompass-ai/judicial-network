# Attesta — Core Components (Architecture Reference)

> **Purpose.** A complete, code-grounded map of every core component of the
> product: what it is, where it lives, what it does, **what it deliberately does
> not do**, and why. Every path and behavior below is verified against source on
> this branch (per §4.3 *Code is Truth* of the Zero-Trust Mandates).

## The organizing principle

> **Infrastructure is dumb; truth is smart.** The system pushes all "thinking"
> (domain logic, cryptographic verification, policy) into the **SDK** and the
> **Auditors**, and keeps the **Ledger** and **Witness** structurally blind.
> That separation is what lets the network sustain **1,000+ TPS** (Goal/Scenario
> 8) while remaining zero-trust: a component that cannot evaluate truth cannot
> become a truth bottleneck, and a component that cannot read payloads cannot
> censor them.

**Component classes**

| Class | Components |
|---|---|
| **Actor** (identity/role) | Network · Exchange · Witness · Auditor (+ its specialization, the Judicial Network) |
| **Engine** | The SDK (Smart Brain) · The Ledger (Sequencer) |
| **Sub-system** | Tessera · Gossip Network · Heads Journal |
| **Artifact** (the nouns) | Entry/Envelope · Cosigned Tree Head · Bundle · Cross-Log Proof/Anchor · Witness Set/Quorum · Identity/DID |

---

# Dictionary (start here — plain English)

> The same components as the rest of this doc, but in everyday language. Each
> term gets **3 framings**: a one-line definition, a real-world analogy ("think
> of it as"), and how it **connects** to the others (with counts). If you read
> only one section of this document, read this one.

## The whole system in one breath

Picture a **county records office**:

- the **Network** is one specific record **book** (e.g., *"Tennessee Courts, Book #1"*);
- the **Exchange** is the **office** that runs that book — staff, front desk, building;
- the **Ledger** is the **clerk** who files each entry *in order* and never judges whether it's "good";
- the **Witnesses** are **notaries** who stamp each new page to prove *"this page truly follows the last"* — without reading what's on it;
- the **Auditors** are outside **inspectors** who re-check every stamp and number and raise the alarm if anything was forged;
- the **SDK** is the **rulebook** every one of them follows;
- **Tessera** is the **filing cabinet and the paper**;
- the **Gossip Network** is the **courier** that photocopies every stamped page to everyone;
- the **Heads Journal** is the **permanent vault** that keeps every stamped page forever.

## The terms — *definition · think of it as · connects to*

**Network** — one logbook with a permanent ID (`NetworkID`).
- *Think of it as:* one specific record book on the shelf.
- *Connects to:* run by **1** Exchange · sequenced by **1** Ledger · cosigned by a small **witness set** (N, with a K-of-N threshold) · watched by **many** Auditors.

**Exchange** — the company/identity that *operates* a Network.
- *Think of it as:* the records office that runs the book — but **cannot rewrite history**.
- *Connects to:* operates **1 or more** Networks · runs the Ledger + Witness infrastructure · is monitored (and slashable) by Auditors.

**Ledger** — the sequencer that orders bytes.
- *Think of it as:* the clerk who files entries in order and never judges them.
- *Connects to:* serves **1** Network · defers **all** judgment to the SDK · asks Witnesses to stamp each head · writes into Tessera.

**Witness** — a blind notary; one of **K-of-N** cosigners.
- *Think of it as:* a notary who stamps each page without reading it.
- *Connects to:* a Network has **N** Witnesses and needs **K** of them to agree · stamps **Tree Heads** · its stamps become the Auditor's evidence.

**Auditor** — independent monitor and fraud-catcher.
- *Think of it as:* an outside inspector who re-does all the math.
- *Connects to:* one Auditor can watch **many** Networks · reads Gossip + the Heads Journal · runs the SDK to render verdicts.

**Judicial Network (JN)** — an Auditor specialized for cross-network trust.
- *Think of it as:* an inspector for one court that *also* verifies references to other courts' books.
- *Connects to:* audits **1** home Network · references **many** foreign Networks.

**SDK** — the shared rulebook (all the smarts).
- *Think of it as:* the law everyone follows; the only thing that decides truth.
- *Connects to:* imported by **every** component (it runs nothing itself).

**Tessera** — the append-only log storage + static tiles.
- *Think of it as:* the filing cabinet and the paper.
- *Connects to:* **1** per Network · written by the Ledger · readable by anyone, even offline via public copies.

**Gossip Network** — pull-based copying of heads and findings.
- *Think of it as:* the courier photocopying stamped pages to everyone.
- *Connects to:* every Ledger **publishes** · every Auditor **pulls** (no one is trusted to self-report).

**Heads Journal** — the permanent vault of every cosigned head.
- *Think of it as:* the archive that never throws anything away.
- *Connects to:* written by the Auditor's reconciler · read for history / forks / burns · **never pruned**.

**Entry** — one filed record. **Tree Head** — the running fingerprint of the whole book so far. **Bundle** — a self-contained certified copy you can verify entirely on your own. **Witness Set** — the current roster of notaries (it rotates; old rosters are kept forever).

## How the key components interconnect (the counts)

| Relationship | Count | Plain English |
|---|---|---|
| Exchange → Network | **1 → many** | One office can run several books |
| Network → Exchange | **1 → 1** | A book has exactly one operating office |
| Network → Ledger → Tessera | **1 → 1 → 1** | One book, one clerk, one filing cabinet |
| Network → Witnesses | **1 → N** (need **K**) | A book is stamped by a small notary set; most must agree |
| Network → Auditors | **1 → many** | Anyone can independently inspect a book (more inspectors = safer) |
| Auditor → Networks | **1 → many** | One inspector can watch many books at once |
| JN → home / foreign Networks | **1 / many** | Audits its own book; verifies pointers into others |
| Network → Entries → Tree Heads | **1 → billions → many** | A book holds billions of pages and a running stamp per batch |
| Network → Witness Sets | **1 active + many historical** | The notary roster rotates; old rosters are kept for Year-15 proofs |

> **Worked example.** *"Tennessee Courts"* is **one Network**, run by **one Exchange** (the court's tech operator), sequenced by **one Ledger** into **one Tessera** log. Each new head is stamped by, for example, **5 Witnesses under a 3-of-5 threshold**. **Several independent Auditors** — plus **one Judicial Network** instance — watch it. If the operator ever signs two different roots at the same page number, *any one* Auditor catches it **from the Witnesses' own stamps** and **burns** the book. Nobody ever had to trust the operator to confess.

```
            Exchange  (operator — runs 1..N networks)
               │ runs
               ▼
            Network ──sequenced by──▶ Ledger ──writes──▶ Tessera (tiles)
               │                          │
               │ cosigned by              │ asks to stamp
               ▼                          ▼
       Witness Set (K-of-N) ───stamps───▶ Tree Head
               │  (stamps = evidence)
               ▼
            Gossip ──▶ Auditor / Judicial Network ──archives──▶ Heads Journal (forever)
                              │  runs the SDK (the rulebook)
                              ▼
                       verdict:  valid · burned · authority-as-of
```

> **Note on numbers.** Counts like *5 witnesses / 3-of-5* are illustrative — the
> threshold (K-of-N) is configured per Network in its founding charter, not
> fixed by the protocol. The *relationships* above (1:1, 1:many) are the
> invariants; the exact N and K are a deployment choice.

---

## Quick map

| # | Component | Class | Lives in | One-line duty |
|---|---|---|---|---|
| 1 | Network | Actor | `attesta/network/`, `crypto/cosign` (NetworkID) | The logbook; atomic unit with a permanent NetworkID |
| 2 | Exchange | Actor | `attesta/exchange/` | The operator running a Network (no authority to rewrite history) |
| 3 | Ledger | Engine | `ledger/` | Orders bytes — pure cryptographic sequencer |
| 4 | Witness | Actor | `attesta-tools/services/witness/` | Blindly cosigns tree heads (Detective, not Preventative) |
| 5 | Auditor | Actor | `attesta-tools/services/auditor/` | Re-runs the math; detects fraud; slashes |
| 6 | Judicial Network | Actor | `judicial-network/` | Domain-specialized Auditor for cross-network trust |
| 7 | SDK | Engine | `attesta/` | Owns ALL domain logic, crypto, schema, verification |
| 8 | Tessera | Sub-system | `tessera/`, `ledger/tessera/` | Append-only Merkle log + static tiles |
| 9 | Gossip Network | Sub-system | `attesta/gossip/`, `attesta-tools/libs/monitoring/` | Pull-based dissemination (the Transparency Clock) |
| 10 | Heads Journal | Sub-system | `attesta-tools/libs/monitoring/`, `auditor/.../store/` | Permanent archive of cosigned heads |

---

# Part A — The Four Ecosystem Actors

## 1. The Network — *The Logbook*

- **Duty.** Be the atomic unit of the chain: one specific append-only logbook with a permanent cryptographic fingerprint, the **NetworkID**, baked from its founding charter (bootstrap document).
- **Physics.** `NetworkID` is a 32-byte identifier in `attesta/crypto/cosign/` (`cosign.NetworkID`, `NetworkIDFromWire`); the founding charter / bootstrap topology lives in `attesta/network/`. The NetworkID is mixed into every cosignature digest, so it is mathematically inseparable from the head.
- **Mechanism.** The Network is not a running process — it's the *identity* of a log instance. Its NetworkID binds every signature, every witness set, and every bundle to *this* logbook and no other.
- **Boundaries — what it is NOT.** It is not the operator (that's the Exchange) and not the storage (that's Tessera). The Network can outlive its operator (Scenario 7: a dissolved Exchange leaves the Network's bundles still verifiable).
- **Why.** It is the subject of **cryptographic domain separation** (Scenario 5 / SDK Principle 11): a submission signed for Network A recomputes a different hash on Network B and fails — cross-network replay is structurally impossible. A `WitnessKeySet` built for NetworkID A cannot verify a head from NetworkID B.
- **Interacts with.** Witness Set (NetworkID-bound), Entry/Envelope (Destination + NetworkID binding), every signature.

## 2. The Exchange — *The Operator*

- **Duty.** Be the legal and operational identity that *runs* a Network — it provides the API surface, the infrastructure (servers, storage, bandwidth), and the business relationship.
- **Physics.** `attesta/exchange/` (e.g. `exchange/auth/signed_request.go` for operator-authenticated requests); the Ledger's admission API (`ledger/api/`) is the surface an Exchange operates.
- **Mechanism.** The Exchange accepts submissions, runs the Ledger + Witness infrastructure, and serves reads. It is the commercial entity in the trust graph.
- **Boundaries — what it is NOT.** The Exchange **lacks the cryptographic authority to rewrite history.** It can sequence and serve, but it cannot forge a witnessed head, cannot alter a sealed payload (doing so invalidates the signature + canonical hash), and cannot delete entries without violating the Maximum Merge Delay. An Exchange that lies is *caught by the Auditor*, not trusted by it.
- **Why.** It documents the "who operates it, and what they explicitly **cannot** do" boundary — the core of the zero-trust posture. Trust never rests on the operator's honesty; it rests on the recomputed K-of-N quorum and the Auditor's independent math.
- **Interacts with.** Ledger (operates it), Witness (requests cosignatures), Auditor (is monitored/slashed by it).

## 3. The Ledger — *The Dumb Sequencer*

- **Duty.** Order bytes. Receive a payload, hash it, sequence it, serve it. Nothing else.
- **Physics.** `ledger/` — admission (`api/submission.go`, `admission/`), the **Badger-backed WAL** (`ledger/wal/`, `wal/committer.go`), the sequencer (`sequencer/sequencer.go`), the builder (`builder/`), object-store tiles (`bytestore/{s3,gcs,publicurl}.go`), and the Tessera adapter (`ledger/tessera/`).
- **Mechanism — Two-Phase Write (Perfect CQRS).**
  1. **Liability Transfer (write).** Synchronous, unconditional append to the **Badger WAL**; the Ledger returns a **Signed Certificate Timestamp (SCT)** committing it to sequence the entry within the **Maximum Merge Delay (MMD)** (`sequencer/sequencer.go:17`). *(Note: this is an **SCT**, not "SLA".)*
  2. **Commit Clock (sequence).** Background workers tail the WAL, compute heavy crypto (BLS thresholds, SMT dirty-roots), and sequence into the Tessera log before the MMD expires.
  - **Agnostic extraction (IoC).** The read-path projector blindly extracts index keys via injected SDK logic; a structurally toxic payload emits an OTel error and **skips the index mutation** — it never stalls the WAL or crashes admission.
- **Boundaries — what it does NOT do.** It contains **ZERO domain logic.** It does **not** run `attesta/verifier/verify_complete.go`; it does not check if a court order is lawful or a license is active. It casts payloads to generic SDK interfaces and trusts the verdict (Ledger Principles 1, 4).
- **Why.** If the Ledger had to evaluate truth, it would bottleneck and fail the **1,000+ TPS** mandate (Scenario 8 / Ledger Principle 5 "Melt-Proof"). Reads and writes share **zero mutexes** (Ledger Principle 8); the Two Clocks (commit vs. transparency) are fully decoupled (Ledger Principle 12) so gossip degradation cannot pause ingestion.
- **Interacts with.** SDK (defers all validation), Witness (requests cosignatures via `witnessclient/`), Tessera (sequences into), Gossip (publishes heads/findings, fire-and-forget).

## 4. The Witness — *The Blind Notary*

- **Duty.** Lock the timeline. Lend cryptographic weight (one of **K-of-N**) attesting that a specific Tree Head was presented at a moment in time.
- **Physics.** `attesta-tools/services/witness/` — the cosign handler / blind-notary logic is in **`internal/serve/serve.go`** (wrapping `attesta/crypto/cosign.NewWitnessHandler`; signer built at `serve.go:150` via `NewECDSAWitnessSigner`, or BLS via `BuildSigner`). **`internal/witkey/witkey.go` is only key-material loading.** Entry point: `cmd/witness/main.go`.
- **Mechanism.** It reads the `cosign.WireRequest`, evaluates only the **Target Root** and **Sequence size**, and signs the dense log root. Its only state is a **RAM-only, per-process `lastSignedSize`** concurrent-misfire guard (`serve.go:245-302`) that refuses a *strictly smaller* tree size since boot — and resets on restart.
- **Boundaries — what it does NOT do (the architectural correction).** The Witness is **Detective, not Preventative** (Witness Principle W1). It does **NOT** prevent split-brain forks:
  - *"It does **NOT** — and architecturally must **not** — try to enforce the log's history"* (`serve.go:44-45`).
  - *"Size-only monotonicity **does not prevent a fork**"* — a malicious ledger at `lastSignedSize=100` can rewrite 1..99 and present a divergent head at 101, and the guard *"happily cosigns the fork"* (`serve.go:48-52`).
  - It cannot verify an RFC 6962 consistency proof — *"it has no log access"* (`serve.go:54`).
  - *"Rollback and fork detection are a **DETECTIVE control owned by the auditors**, not a preventative one owned by the witness"* (`serve.go:61`; `cmd/witness/main.go:26-27`).
  - It cannot read payloads, so it is **structurally prevented from censoring** specific content.
- **Why.** A Witness will blindly cosign **both sides** of a same-sequence fork — and *that is the point*: two independently-valid K-of-N cosignatures are the cryptographic **evidence** that lets the **Auditor** prove equivocation (Scenario 6). The Witness manufactures the evidence; the Auditor renders the verdict. A compromised witness only *fails to attest*; it cannot halt the network (W1).
- **Interacts with.** Ledger (cosigns its heads on the synchronous commit path, W8), SDK (`crypto/cosign` handler + signer), Auditor (whose detection consumes witness cosignatures).

## 5. The Auditor — *The Enforcer of Truth*

- **Duty.** Enforce physics, resolve cross-network trust, and detect fraud — asynchronously and **orthogonally** to the Ledger.
- **Physics.** `attesta-tools/services/auditor/`; it pulls public snapshots and runs the heavy SDK machinery: `attesta/verifier/verify_complete.go`, the reconciler at **`attesta-tools/libs/monitoring/gossip_reconciler.go`** *(tools-side, not `attesta/libs/` — that path does not exist)*.
- **Mechanism / responsibilities.**
  - **Equivocation Response** — `services/auditor/internal/equivocation/slasher.go:111` (+ the independent `scanner.go`): catches a conflicting RootHash at the same sequence, compiles a `KindEquivocationFinding`, and slashes/freezes the ledger's trust status locally.
  - **Cross-Log Verification** — `attesta/verifier/cross_log.go` + `attesta/anchor/anchor.go:213`: fetches and authenticates foreign state proofs against the *foreign* log's cosigned head (Scenario 1).
  - **Delegation & Policy Enforcement** — `attesta/verifier/policy_stage.go`: checks whether a specific `Signer_DID` actually held authority to issue the payload **at that exact moment in time (`asOf`)**.
- **Boundaries — what it does NOT do.** It does not sequence, does not hold the write path, and does not require the offending Ledger to self-report — it pulls and re-computes independently (Scenario 6).
- **Why.** This is where Separation of Duties lives: pushing "thinking" here keeps the Ledger dumb and fast. The Auditor is the detective tier that turns Witness evidence into burns/slashes.
- **Interacts with.** Gossip (pulls heads/findings), Heads Journal (its durable store), SDK (verification machinery), Witness (consumes cosignatures).

## 6. The Judicial Network (JN) — *The Domain-Specialized Auditor*

- **Duty.** A deployment/specialization of the Auditor role for **cross-network trust** in a specific domain (e.g. courts): resolve foreign-log authority, verify cross-log proofs, and enforce delegation/policy.
- **Physics.** `judicial-network/` — `verification/trust/multijurisdiction.go` (`MultiJurisdictionTrust`, the cross-log `LogTrustProvider`), the cross-log proof handlers (`api/verification/handlers/verify_cross_log.go`, `api/judicial/verification_appeals.go`), and the consortium/federation surface (`consortium/`).
- **Mechanism.** One JN instance audits **one** Network's authority chain but verifies *references into* foreign logs against the foreign log's own witnessed head (resolved via the Heads Journal at `asOf`).
- **Boundaries — what it does NOT do.** It does not operate the foreign Network and does not "pick" a fork — on a verified fraud proof it transitions the foreign log to **BURNED/FROZEN** and halts verification globally for that log (Cross-Network Fork Policy).
- **Why.** It is the canonical consumer of the SDK's trust machinery and its own deployable product. *(See `docs/gaps/` — JN-1…JN-4 track the remaining zero-trust hardening of this component.)*
- **Interacts with.** Heads Journal (foreign head resolution), Anchor/Cross-Log Proof (verifies), SDK verifier (authority walks).

---

# Part B — The Brain

## 7. The SDK — *The Smart Brain*

- **Duty.** Own **all** domain logic, cryptography, schema, and verification. Every "dumb" component (Ledger, Witness) and every enforcer (Auditor, JN) defers to it. It is the single Universal Source of Truth (SDK Principle 1).
- **Physics.** `attesta/` — the verification engine (`verifier/`: `verify_complete.go`, `policy_stage.go`, `cross_log.go`, `key_at_position.go`, `log_trust.go`), cryptography (`crypto/`: `cosign/`, `signatures/`, `escrow/`, `artifact/`), cross-log anchoring (`anchor/`), identity (`did/`: did:web, did:pkh/EIP-1271, key), the canonical wire format (`core/envelope/`), offline artifacts (`log/bundle/`), witness rotation (`witness/`), gossip findings (`gossip/`), schema/extractors (`schema/`), delegation/authority (`delegation/`, `authz/`), and shared types (`types/`).
- **Mechanism.** **Fail-closed by construction** (Principle 3): verification runs multi-tier evaluation in a single function frame and returns one typed error. **Parse, Don't Validate.** Identity is agnostic (Principle 9): web domains, public keys, and smart-contract wallets are equal peers. Post-quantum dispatch is per-signature on the declared algorithm (Scenario 10), within the **65,535-byte** wire cap (`core/envelope/tessera_compat.go:98`).
- **Boundaries — what it does NOT do.** It runs no servers and stores no state — it is a pure library of polymorphic interfaces. Infrastructure layers blindly drop whatever the SDK rejects.
- **Why.** Your other components literally "utilize the SDK machinery." Without the SDK, the SoD story has no subject — it is *where truth lives*. Open for extension, closed for modification (Principle 2).
- **Interacts with.** Everything — it is the dependency every other component imports.

---

# Part C — Core Sub-systems

## 8. Tessera — *The Log Storage Engine*

- **Duty.** Be the append-only Merkle log + static-tile storage beneath the Ledger.
- **Physics.** `tessera/` is the upstream **`github.com/transparency-dev/tessera`** engine; the Ledger integrates it via `ledger/tessera/` and serves tiles through `ledger/bytestore/` (S3/GCS/public URLs).
- **Mechanism.** Entries are sequenced into a dense Merkle tree; state is pre-computed into immutable `c2sp.org/tlog-tiles` tiles and pushed to Object Stores (Ledger Principle 10). The Ledger only *reads* tiles back; Tessera owns the write path.
- **Boundaries — what it does NOT do.** It is content-agnostic — leaves are 32-byte hashes, not payloads (§5.2). It enforces the **65,535-byte** entry cap (a c2sp.org/tlog-tiles spec invariant, not a knob).
- **Why.** Static tiles in public Object Stores are what make the **dissolved-ledger fallback** possible: in Year 12 a verifier authenticates Year-2 evidence with no operator API, from read-only tiles alone (Scenario 7). The 64 KiB cap is also the structural reason PQ cosign-quorums are bounded (§5.4).
- **Interacts with.** Ledger (sequences into it), Bundle (inclusion proofs are over its tiles), SDK verifier (recomputes leaf/interior hashes).

## 9. The Gossip Network — *The Transparency Fabric*

- **Duty.** Disseminate heads, findings, and equivocation proofs across peers, pull-based and fire-and-forget (the "Transparency Clock").
- **Physics.** `attesta/gossip/` (event kinds, findings, wire payloads, verify) + `attesta-tools/libs/monitoring/gossip_reconciler.go` (the ingest/reconcile pipeline) + `ledger/gossipnet/` (the ledger-resident peer monitor).
- **Mechanism.** Peers **pull** cryptographically-proven events via HTTP caches/CDNs (Ledger Principle 11); Lamport-time progression makes re-receipt idempotent (one write, zero panics — SDK Principle 14). Emit queues are non-blocking so the commit hot-path never stalls on a broadcast (Principle 13).
- **Boundaries — what it does NOT do.** It carries no authority — gossip is *transport*, not truth. A received finding is re-verified by the SDK before it is acted on.
- **Why.** It is how Witnesses, Auditors, and peers learn state **without trusting the Ledger to self-report** (Scenario 6). Gossip degradation cannot pause ingestion (the Two Clocks, Ledger Principle 12).
- **Interacts with.** Ledger (publishes), Auditor (pulls/reconciles), Heads Journal (reconciler writes verified heads into it), Equivocation findings (disseminated through it).

## 10. The Heads Journal — *The Cryptographic Bedrock*

- **Duty.** Durably archive every cosigned head ever observed, addressable historically and fork-aware.
- **Physics.** Interface + in-memory impl in `attesta-tools/libs/monitoring/heads_journal.go` (`heads_journal_memory.go`); production Postgres in `attesta-tools/services/auditor/internal/store/heads_journal.go`.
- **Mechanism.** Primary key **`(LogDID, Sequence, RootHash)`** (`store/heads_journal.go:110`) — so a fork (same sequence, different root) **stores both rows** and triggers the burn transition in one advisory-locked transaction. Read surface: `HeadAt(seq)`, `HeadAtTime(t)`, `HeadByRootHash`, `HeadsAtSequence`, `LatestHead`, `BurnStatus`; `ErrEquivocatedLog` on burned logs (`heads_journal.go:279`).
- **Boundaries — what it does NOT do.** It is a *witness, not a judge* — it records both forks and surfaces the collision; the equivocation responder decides slashing/freeze. It is **NEVER pruned** (no TTL, no PruneJob hook) — pruning would destroy historical cross-log verification.
- **Why.** It is the single substrate enabling **`asOf` history** (Scenario 3), **fork identification** (Scenario 4), **Year-15 reconstruction** (Scenario 2), and **burn fail-closed** (Cross-Network Fork Policy). ~250M rows over 15 years ≈ tens of GB — trivial; it is permanent cryptographic bedrock.
- **Interacts with.** Gossip reconciler (writes into it), Auditor/JN (read it for trust roots + burn status), the equivocation protocol (collision trigger).

---

# Part D — Core Data Artifacts (the nouns)

| Artifact | Where | What it is | Why it matters |
|---|---|---|---|
| **Entry / Envelope** | `attesta/core/envelope/` | Canonical signed unit: domain payload + control header (SignerDID, Destination, EventTime) + N signatures; ≤ **65,535 B**, JCS-canonical | The atom the Ledger sequences; Destination is bound into the signed hash (Scenario 5 replay defense) |
| **Cosigned Tree Head (STH)** | `attesta/crypto/cosign/` | The Merkle root + its K-of-N witness cosignatures, NetworkID-bound | The **Universal Anchor** every inclusion/authority proof is checked against (Alignment A1) |
| **Bundle** | `attesta/log/bundle/` | Self-contained offline artifact: entry + inclusion proof + cosigned head + SMT proof (+ witness hint) | The **Year-15 / dissolved-ledger** unit — verifies with no live network (Scenarios 2, 7); `FormatV1` is frozen (Scenario 12) |
| **Cross-Log Proof / Anchor** | `attesta/anchor/`, `verifier/cross_log.go` | An anchor entry embedding a foreign head + the cited entry's inclusion proof | Binds one log's entry into another's tree — the cross-network trust artifact (Scenario 1) |
| **Witness Set / Quorum** | `attesta/crypto/cosign/witness_key_set.go` | Immutable K-of-N keyset bound to a NetworkID + threshold; rotates via verified events | The two-tier quorum oracle (Alignments A2/A4); reconstructable historically (Scenario 2) |
| **Identity / DID** | `attesta/did/` | Signer identities: did:web, did:pkh/**EIP-1271** smart wallets, mTLS, role/vendor DIDs | First-class, agnostic identity (Scenario 11 / SDK Principle 9) |

---

# How they fit together

**The write path (synchronous — the Commit Clock).**
An **Exchange** accepts a submission for its **Network** → the **Ledger** validates it *only* by deferring to the **SDK**'s interfaces, appends to the **Badger WAL**, and returns an **SCT** → background workers sequence the **Entry** into **Tessera** and ask the **Witness** to cosign the new **Cosigned Tree Head**.

**The transparency path (asynchronous — the Transparency Clock).**
The **Gossip Network** disseminates each cosigned head and any findings, pull-based → the **Auditor** (or the domain-specialized **Judicial Network**) ingests them, records every head into the **Heads Journal**, and re-runs the **SDK** math. If it finds a conflicting RootHash at one sequence, it compiles a `KindEquivocationFinding` and **burns** the log; if asked to verify a **Cross-Log Proof** or an authority `asOf`, it resolves the historical **Witness Set** from the Journal and authenticates a **Bundle** entirely offline.

The two clocks never block each other — which is exactly why the system stays melt-proof at scale while remaining zero-trust.
