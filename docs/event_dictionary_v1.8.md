---
title: Judicial Network — Event Dictionary
version: 1.8
status: draft
---

# Judicial Network: Event Dictionary

## About This Document

The judicial-network records every substantive event on Attesta, an append-only, cryptographically signed log substrate — conceptually similar to Certificate Transparency logs. Entries are permanent and order-preserving; integrity is verifiable by anyone with access to the log.

This dictionary defines **what events the network records, who is authorized to sign them, and what prior log state each event depends on**. It does not prescribe how those events are validated, indexed, or queried — those concerns belong to the implementing code.

The dictionary is divided into four parts:

- **Part 1 — Actors.** The role model of human actors and their cryptographic relationship to the network.
- **Part 2 — Case Lifecycle Events** (§1–§10). Adversarial, operational, and factual milestones of individual disputes.
- **Part 3 — Administrative Events** (§11–§13). Structural reorganization, personnel, and governance of courts.
- **Part 4 — Technical Events** (§14–§16). Cryptographic, schema, and topology operations on the log substrate.

---

## Conventions

### Network / Exchange / Division Hierarchy

The judicial-network has a three-level structural hierarchy. The rest of this dictionary reads against these definitions:

- **Network** — A single shared Attesta log. All courts that write to a network share the same append-only sequence and the same anchor hierarchy. A network is the unit of cryptographic integrity. *Analogy: one Certificate Transparency log shared by many Certificate Authorities.*
- **Exchange** — A single court that writes to a network. Each exchange has its own institutional DID, its own Signers (Adjudicators, Clerks, Court Reporters), and its own delegation chain. Davidson County and Shelby County are separate exchanges that may share the same network. *Analogy: one CA writing to a CT log.*
- **Division** — A subdivision within an exchange (e.g., Criminal, Chancery, Business Court). Divisions share the exchange's Signers and delegation chain; they do not have independent cryptographic authority. Divisions are routing constructs, not security boundaries.

**Forking is a network operation, not a court operation.** A new court joining an existing network is an *exchange onboarding*. Forking creates a new *network* — typically motivated by horizontal scalability, jurisdictional independence, or governance separation (e.g., federal courts operating their own network).

### Identifiers and Conventions

**Event type identifiers.** Each event has a stable `snake_case` identifier used as the discriminator field in the payload. Identifiers are noun-form (e.g., `motion_summary_judgment`); the act of recording the event is implicit.

**Catch-all events.** Several motion subcategories include a `*_general` catch-all to bound the type system without losing fidelity for non-standard filings. Catch-all payloads MUST include a `custom_title` free-text field describing the specific motion or action.

**Rule citations.** TRCP — Tennessee Rules of Civil Procedure. TRCrP — Tennessee Rules of Criminal Procedure. TRAP — Tennessee Rules of Appellate Procedure. TRE — Tennessee Rules of Evidence. TSCR — Tennessee Supreme Court Rule. T.C.A. — Tennessee Code Annotated.

### Case Roots: Trial vs. Appellate

A **case root** is the foundational entry that anchors a single case's event history. Trial-court cases and appellate-court cases each have their own case roots:

- **Trial case root** — created by `case_initiation` at a trial-court exchange. Holds all trial-level events: pleadings, motions, discovery, verdict, judgment, post-judgment motions.
- **Appellate case root** — created by `appellate_case_initiation` at the Tennessee Court of Appeals exchange. Holds all appellate events: opinions, participations, disposition. Linked to the underlying trial case via cross-network reference.

This mirrors real-world docketing: trial-court Case 2023-CR-5678 and appellate Case 2024-CA-1234 are distinct cases with distinct dockets, even though they concern the same dispute. The appellate court's `appellate_disposition` flows back to the trial court's case root via `remand_affirmance` (cross-network reference).

### Case-Local Identifiers

Some events mint **case-local identifiers** — stable references that exist only within a single case root and have no meaning outside it. These identifiers let later events on the same case point to earlier ones unambiguously.

- `binding_id` — minted by `party_binding`. References a party (Plaintiff, Defendant, Respondent, State) within this case. Parties are not network entities and have no DIDs; the `binding_id` is the only public reference, and the underlying identity may be public or sealed.
- `appearance_id` — minted by `counsel_appearance`. References an attorney's representation of one or more parties within this case. Withdrawals point at this `appearance_id`.
- `opinion_id` — minted by `appellate_opinion_publication`. References a specific opinion within an appellate case root. Participation events point at this `opinion_id`.

Cross-case identity correlation (e.g., recognizing that a defendant in two unrelated cases is the same person) is the aggregator microservice's concern, not the log's. The log itself never links case-local identifiers across case roots.

### Event Prerequisites and Log State

A case root is a state machine. Most events on a case are valid only if specific prior entries already exist on that case root. Events fall into three categories:

- **Origin events** — create new state with no prerequisite. Examples: `case_initiation`, `judicial_appointment`.
- **Dependent events** — reference and depend on prior state. Invalid if the prerequisite is missing or no longer active. Examples: `counsel_withdrawal`, `responsive_pleading`, `notice_of_appeal`.
- **Terminal events** — close out state. May have prerequisites and may foreclose further events of certain types. Examples: `dismissal`, `expungement`.

Every dependent and terminal event is annotated below with **Requires:** lines in two formats:

- **Prose** — natural-language description of what must already be on the case root.
- **Structured** — machine-readable form: `event_type{field=value, ...}, status=...`. Multiple alternatives are joined with `OR`.

Each prerequisite is also marked **Hard** or **Advisory**:

- **Hard** — the validator MUST reject the event if the prerequisite is not satisfied. The log refuses entries that violate hard prerequisites.
- **Advisory** — the validator SHOULD accept the event but flag the missing prerequisite for the aggregator to surface. Real-world filings sometimes arrive out of order (a withdrawal lands before the appearance is fully docketed), and the log accommodates this without losing record fidelity. Advisory failures are visible to the aggregator and to anyone reading the log; they are not silenced.

> 🚩 **Developer flag — prerequisite validation policy.** *The validation policy walks the case root before accepting any dependent or terminal event. Hard prerequisites cause rejection; advisory prerequisites cause acceptance with a flag. Time-bounded prerequisites (e.g., `motion_reduction_of_sentence` 120-day window) are enforced by the same module. The exact list of which prerequisites are Hard vs. Advisory is set by the network in code; this dictionary makes the recommended classification.*

### Cryptographic Authority

Only Signers hold network keys (see Part 1). Every entry is signed by a Signer DID with active write authority for the relevant scope.

**Signers are scoped to their exchange.** A Davidson Adjudicator holds keys that act on behalf of the Davidson exchange; a Shelby Adjudicator holds keys that act on behalf of Shelby. Both may write to the same network, but neither has authority over the other's exchange.

**Filer cosignature requirement.** Filers (Prosecutors, Defense Counsel, Civil Attorneys, Fiduciaries, Guardians ad litem) cannot sign entries directly. Every entry submitted by a Filer MUST be ingested and cryptographically cosigned by a Signer.

> 🚩 **Developer flag — Filer cosignature mix.** *Which Signer is required to cosign which event type, when filed by which Filer, is defined by the network in code. The dictionary specifies that cosignature is required; the network's policy module defines the acceptable mixes.*

> 🚩 **Developer flag — cross-exchange cosignature validity.** *When many exchanges share a network, the cosignature policy module must distinguish events that require **intra-exchange** cosignature (e.g., `judicial_appointment` — Shelby Adjudicators do not certify Davidson appointments) from events where **cross-exchange** cosignatures are valid or required (e.g., case transfers, relay attestations). The dictionary identifies which events fall into each category implicitly through their semantics; code enforces the rule.*

### Developer Flags

Several places in this dictionary require an implementation choice — a threshold, quorum, acceptable cosignature mix, or grace period. These are marked with 🚩 and called out inline. The dictionary specifies *that* a decision is required; the network's code defines the specific value. **Appendix B inventories all developer flags for convenience.**

### Read-Side Separation

The Attesta log is the canonical, immutable, write-optimized source of truth. Search, indexing, reporting, and access-controlled views are provided by a separate aggregator microservice with its own database that consumes the log. The dictionary defines what is *written*; the aggregator defines what is *exposed*.

---

# Part 1 — Actors

The judicial network distinguishes three roles based on cryptographic relationship to the log. Every entry traces its provenance back to a Signer, even when Filer advocates or Parties are the substantive subjects of the entry.

**Signers are exchange-scoped.** Each exchange (court) has its own set of Signers. Multiple exchanges share the same network, but a Signer's authority is bounded to their own exchange.

## Signers *(The Key Holders)*

The only entities that hold network cryptographic keys.

- **Adjudicators** *(Judges, Magistrates, Chancellors, Justices)* — The ultimate authority within their exchange. Their keys sign definitive rulings: final judgments, decrees, warrants, appellate opinions, and Path C enforcement actions (sealing, unsealing, expungement).
- **Clerks & Deputy Clerks** — The cryptographic gatekeepers of their exchange. They hold the operational keys of the court, sign structural case entries (initiations, party bindings, transfers), and act as the sole proxy signers for all external documents. Without an automated case management system, every motion or brief is manually hashed and signed to the ledger by a Clerk.
- **Court Reporters** — The official record keepers for their exchange. Specialized keys used strictly to publish, encrypt, and sign certified hearing and trial transcripts.

## Filers *(Active Metadata Subjects)*

Legal professionals who drive litigation. They do not hold network keys, but they are network entities with their own DIDs (recorded in `attorney_did` and similar payload fields). Every event submitted by a Filer requires Signer cosignature.

- **Prosecutors / District Attorneys** — Submit charging instruments to the Clerk. Act as the ingestion node for the evidence chain of custody, receiving raw files from police and handing them to the Clerk for cryptographic hashing.
- **Defense Counsel & Civil Attorneys** — Submit motions, briefs, and pleadings to the Clerk on behalf of clients. Provide cryptographic cosignatures attesting receipt of restricted discovery.
- **Fiduciaries** *(Executors, Conservators, Guardians)* — Court-appointed individuals who legally manage the assets or well-being of another person or estate.
- **Guardians ad litem** — Independent attorneys appointed by the Adjudicator to represent the best interests of a vulnerable subject (minor, incapacitated adult).

## Parties *(Passive Metadata Subjects)*

The actual participants in the dispute. **Parties are not network entities and do not have DIDs.** They are recorded as case-local data inside `party_binding` events; the `binding_id` minted by that event is the only public reference; the underlying identity may be public or sealed.

- **Plaintiffs / Petitioners / The State** — The party initiating the conflict.
- **Defendants / Respondents** — The party defending against the allegations.
- **Pro Se Litigants** — Individuals representing themselves. They have a `binding_id` (as a party) but no `attorney_did` and no `counsel_appearance`. Filings on their behalf are signed by the Clerk with the `binding_id` as the responsible party reference.

## Authority Summary

| Role | Holds Keys | Has DID | Scoped To | Schema Role | Typical Events |
|---|---|---|---|---|---|
| Signer — Adjudicator | ✅ | ✅ | Exchange | `signed_by` | Final judgments, warrants, Path C orders, succession, appellate opinions |
| Signer — Clerk | ✅ | ✅ | Exchange | `signed_by` | Case initiation, party binding, motion ingestion (proxy) |
| Signer — Court Reporter | ✅ | ✅ | Exchange | `signed_by` | Transcript publications |
| Filer — Advocate | ❌ | ✅ | Network | `filed_by` / `attorney_did` | None directly; require Signer cosignature |
| Party | ❌ | ❌ | Case root | `binding_id` payload | None; bound as case-local metadata |

---

# Part 2 — Case Lifecycle Events

## 1. Genesis & Structuring

Foundational entries that create the case root and configure its initial state.

- **`case_initiation`** — The foundational entry that creates the case root: initial complaint, indictment, citation, or petition.
  *Origin event.*
- **`party_binding`** — Adds a Plaintiff, Defendant, Respondent, or the State to the case. **Mints a case-local `binding_id`** as the only public reference to this party. Party identity (public or sealed) lives entirely in the payload; parties have no DIDs.
  - **Requires (Hard):** prior `case_initiation` on this case root.
  - **Structured:** `case_initiation{}, status=active`
- **`counsel_appearance`** — Attorney goes on record as representing one or more parties. **Mints a case-local `appearance_id`.** Payload carries the `attorney_did` and a `represents` list of `binding_id` values from prior `party_binding` events on this case.
  - **Requires (Hard):** prior `case_initiation` on this case root.
  - **Requires (Advisory):** prior `party_binding` for each `binding_id` in the `represents` list, on this case root, status=active.
  - **Structured:** `case_initiation{}, status=active` AND for each `binding_id` in `represents`: `party_binding{binding_id}, status=active`
- **`counsel_withdrawal`** — Attorney exits a representation. References an `appearance_id` from a prior `counsel_appearance`.
  - **Requires (Hard):** prior `counsel_appearance` with the same `appearance_id` on this case root, not yet withdrawn.
  - **Structured:** `counsel_appearance{appearance_id}, status=active`
- **`judicial_assignment`** — Administrative routing of the case to a specific Adjudicator or division within the exchange.
  - **Requires (Hard):** prior `case_initiation` on this case root.
  - **Structured:** `case_initiation{}, status=active`
- **`case_track_designation`** — Classifies procedural speed (Expedited, Standard, Complex). Auto-generates downstream scheduling deadlines.
  - **Requires (Hard):** prior `case_initiation` on this case root.
  - **Structured:** `case_initiation{}, status=active`
- **`case_consolidation`** — Merges two separate dockets sharing common facts.
  - **Requires (Hard):** prior `case_initiation` on each merged case root.
  - **Structured:** `case_initiation{case_root}, status=active` for each consolidated root.
- **`case_severance`** — Splits one case into multiple separate trials.
  - **Requires (Hard):** prior `case_initiation` on this case root.
  - **Structured:** `case_initiation{}, status=active`

## 2. Pleadings & Pre-Trial Formations

- **`responsive_pleading`** — Defendant's formal answer to allegations (admit/deny civil claims).
  - **Requires (Hard):** prior `case_initiation` on this case root.
  - **Requires (Advisory):** the responding party bound via prior `party_binding` on this case root.
  - **Structured:** `case_initiation{}, status=active` AND `party_binding{binding_id=responding_party}, status=active`
- **`counterclaim`** — Defendant suing the plaintiff back.
  - **Requires (Hard):** prior `responsive_pleading` on this case root by the same defendant.
  - **Structured:** `responsive_pleading{by=binding_id}, status=active`
- **`crossclaim`** — Defendant suing a co-defendant.
  - **Requires (Hard):** prior `party_binding` for both co-defendants on this case root.
  - **Structured:** `party_binding{binding_id=claimant}, status=active` AND `party_binding{binding_id=cross_defendant}, status=active`
- **`plea_entry`** — Defendant declaring stance: Guilty, Not Guilty, or No Contest (Criminal).
  - **Requires (Hard):** prior `case_initiation` and `party_binding` for the defendant entering the plea.
  - **Structured:** `case_initiation{}, status=active` AND `party_binding{binding_id=defendant}, status=active`

## 3. Motions, Requests & Petitions

All formal requests for judicial action. Trigger workflows, tolling periods, or discovery obligations downstream.

**Default prerequisites for all motion events in §3A–§3I (unless otherwise stated):**

- **Requires (Hard):** prior `case_initiation` on this case root.
- **Requires (Advisory):** prior `party_binding` for the moving party.
- **Structured:** `case_initiation{}, status=active` AND `party_binding{binding_id=movant}, status=active`

Where a motion has additional prerequisites beyond the default, they are listed under the motion.

**Vocabulary constraint.** A motion event can only be filed using an `event_type` that this dictionary defines, or a `*_general` catch-all with a populated `custom_title`. The validator rejects motion events whose `event_type` is not in the dictionary's enum. Attorneys file from the dictionary's vocabulary, not free-form.

### 3A. Jurisdictional & Pleading Motions

- **`motion_dismiss_jurisdiction`** — Challenges subject matter jurisdiction (TRCP 12.02(1)), personal jurisdiction (12.02(2)), or geographic venue (12.02(3)).
- **`motion_dismiss_process_defects`** — Attacks insufficiency of process (12.02(4)) or service (12.02(5)).
- **`motion_dismiss_failure_to_state_claim`** — No legal remedy even if all alleged facts are true (12.02(6)).
- **`motion_dismiss_charging_defect`** — Defect in institution of prosecution or fatal error in indictment/presentment/information (criminal).
- **`motion_dismiss_no_probable_cause`** — Oral motion in General Sessions criminal preliminary hearings; requests dismissal before binding over to Grand Jury.
- **`motion_more_definite_statement`** — Forces clarification of vague pleading (TRCP 12.05) or criminal Bill of Particulars (TRCrP 7(c)).
- **`motion_to_strike`** — Removes redundant, immaterial, impertinent, or scandalous matter (TRCP 12.06).
- **`motion_amend_pleadings`** — Adds claims, defenses, or parties after the initial filing window (TRCP 15).
- **`motion_pleading_general`** *(catch-all)* — Non-standard request altering case foundation outside Rule 12 or 15.
  **Payload:** `custom_title` required (e.g., `"Motion to Strike Surplusage"`).

### 3B. Dispositive & Summary Motions

- **`motion_summary_judgment`** — No genuine disputes of material fact; movant entitled to win as a matter of law (TRCP 56.04).
- **`motion_judgment_on_pleadings`** — Decides the case based solely on complaint and answer (TRCP 12.03).
  - **Additional Requires (Hard):** prior `responsive_pleading` on this case root (pleadings closed).
  - **Structured:** `responsive_pleading{}, status=active`
- **`motion_default_judgment`** — Wins automatically because the opposing party failed to respond (TRCP 55).
  - **Additional Requires (Hard):** prior `party_binding` for the non-responding party.
  - **Structured:** `party_binding{binding_id=non_responding_party}, status=active`
- **`motion_state_dismissal`** — Prosecutor's request to drop criminal charges (TRCrP 48).
- **`motion_dismiss_unnecessary_delay`** — Dismisses a criminal case for speedy trial or prosecutorial delay violations.
- **`motion_dispositive_general`** *(catch-all)* — Non-standard request that *could* end the case.
  **Payload:** `custom_title` required (e.g., `"Motion to Dismiss for Lack of Standing"`).

### 3C. Equitable, Provisional & Class Remedies

- **`motion_tro_preliminary_injunction`** — Forces a party to do, or stop doing, an action immediately to prevent irreparable harm (TRCP 65).
- **`motion_attachment_receivership`** — Seizes property or appoints a neutral third party to manage assets during litigation.
- **`motion_class_certification`** — Elevates a lawsuit into a class action (TRCP 23.03).
- **`motion_equitable_general`** *(catch-all)* — Non-standard request for immediate intervention or structural change.
  **Payload:** `custom_title` required (e.g., `"Motion for Writ of Replevin"`).

### 3D. Discovery, Spoliation & Protection

- **`motion_compel_discovery`** — Forces a party to answer interrogatories, produce documents, or present a 30.02(6) corporate designee (TRCP 37.01) — or to produce criminal discovery (TRCrP 16).
  - **Additional Requires (Advisory):** prior `discovery_filing` representing the request that was not adequately answered.
  - **Structured:** `discovery_filing{}, status=active`
- **`motion_discovery_sanctions`** — Penalizes a party for failing to obey a discovery order (TRCP 37.02).
  - **Additional Requires (Hard):** prior `interlocutory_order` granting discovery (the order alleged to have been violated).
  - **Structured:** `interlocutory_order{type=discovery_compulsion}, status=active`
- **`motion_spoliation_sanctions`** — Penalizes a party for destroying evidence (TRCP 34A.02).
- **`motion_deem_facts_admitted`** — Locks in facts because the opposing party failed to timely respond to Requests for Admission (TRCP 36).
  - **Additional Requires (Advisory):** prior `discovery_filing` containing the Requests for Admission.
  - **Structured:** `discovery_filing{type=requests_for_admission}, status=active`
- **`motion_protective_order`** — Defensive request to shield a party from abusive or overly broad discovery (TRCP 26.03).
- **`motion_quash_subpoena`** — Invalidates a demand for testimony or documents (TRCP 45.02).
- **`motion_discovery_general`** *(catch-all)* — Request governing evidence exchange outside standard compel/protect motions.
  **Payload:** `custom_title` required (e.g., `"Motion to Permit Inspection of Premises"`).

### 3E. Trial-Prep & Evidentiary Motions

- **`motion_in_limine`** — Preemptively excludes prejudicial or irrelevant evidence before it reaches the jury.
- **`motion_suppress`** — Criminal request to exclude evidence obtained in violation of the Fourth, Fifth, or Sixth Amendments.
- **`motion_judicial_notice`** — Asks the judge to accept a well-known fact as true without formal proof (TRE 201).
- **`motion_special_jury_instructions`** — Submits customized legal instructions for the jury (TRCP 51 / TRCrP 30).
- **`motion_competency_evaluation`** — Suspends criminal proceedings until the defendant is evaluated for mental fitness (TRCrP 8.06).

### 3F. In-Trial Dispositive Motions

- **`motion_directed_verdict`** — Civil mid-trial request that no reasonable jury could find for the opposing party (TRCP 50).
  - **Additional Requires (Advisory):** prior `hearing_convened_concluded` indicating trial is in progress.
- **`motion_judgment_acquittal`** — Criminal request asserting the State failed to prove its case; judge must acquit (TRCrP 29).
  - **Additional Requires (Advisory):** prior `hearing_convened_concluded` indicating trial is in progress.
- **`motion_mistrial`** — Aborts the trial due to a fatal, incurable error or extreme prejudice.
  - **Additional Requires (Advisory):** prior `hearing_convened_concluded` indicating trial is in progress.

### 3G. Docket Management & Procedural Logistics

- **`motion_continuance`** — Delays a hearing or trial date.
  - **Additional Requires (Advisory):** prior `scheduling_order` setting the date sought to be moved.
  - **Structured:** `scheduling_order{}, status=active`
- **`motion_consolidation_severance`** — Merges multiple cases or defendants for trial (TRCP 42.01 / TRCrP 14), or splits them apart (TRCP 42.02).
- **`motion_substitution_parties`** — Replaces a party, typically triggered by a suggestion of death (TRCP 25.01; 90-day deadline).
  - **Additional Requires (Hard):** prior `party_binding` for the party to be substituted.
  - **Structured:** `party_binding{binding_id=substituted_party}, status=active`
- **`motion_change_of_venue`** — Moves a trial to a different county due to pretrial publicity (TRCrP 21).
- **`motion_withdraw_counsel`** — Attorney's request to be removed from the case.
  - **Additional Requires (Hard):** prior `counsel_appearance` for the requesting attorney, not yet withdrawn.
  - **Structured:** `counsel_appearance{appearance_id}, status=active`
- **`motion_disqualification_recusal`** — Demands the judge step down due to bias or conflict of interest (TSCR 10B). Has its own exclusive interlocutory appellate path bypassing TRAP 9 and 10.
  - **Additional Requires (Hard):** prior `judicial_assignment` identifying the targeted Adjudicator.
  - **Structured:** `judicial_assignment{adjudicator_did}, status=active`
- **`motion_juvenile_transfer_custody`** — Tries a minor as an adult, or reviews DJJ custody status.
- **`motion_bond_modification`** — Lowers bail or alters conditions of pre-trial release.
- **`motion_procedural_general`** *(catch-all)* — Request regarding case mechanics, timing, or logistics. *(Most "Other" motions land here.)*
  **Payload:** `custom_title` required (e.g., `"Motion to Allow Attorney to Appear via Zoom"`).

### 3H. Post-Trial / Post-Conviction Motions

All §3H events additionally require a prior disposition entry on this case root. Common structured prerequisite: `verdict{}, status=active` OR `final_judgment{}, status=active`.

- **`motion_new_trial`** — Throws out the verdict and retries the case (TRCP 59.01 / TRCrP 33, including 13th Juror claims).
  - **Additional Requires (Hard):** prior `verdict` or `final_judgment`.
  - **Structured:** `verdict{}, status=active` OR `final_judgment{}, status=active`
- **`motion_alter_amend_judgment`** — Changes the legal effect or mathematics of the final judgment (TRCP 59.04).
  - **Additional Requires (Hard):** prior `final_judgment`.
  - **Structured:** `final_judgment{}, status=active`
- **`motion_renewed_directed_verdict_jnov`** — Post-trial request to overrule the jury's verdict as a matter of law (TRCP 50.02 / TRCrP 29(c)).
  - **Additional Requires (Hard):** prior `verdict`.
  - **Structured:** `verdict{}, status=active`
- **`motion_arrest_of_judgment`** — Criminal post-trial request asserting the court lacked jurisdiction or the indictment failed to charge an offense (TRCrP 34).
  - **Additional Requires (Hard):** prior `verdict` or `final_judgment`.
  - **Structured:** `verdict{}, status=active` OR `final_judgment{}, status=active`
- **`motion_set_aside_relief_from_judgment`** — Undoes a judgment due to mistake, excusable neglect, or fraud (TRCP 55.02 / 60.02).
  - **Additional Requires (Hard):** prior `final_judgment` or `default_judgment`.
  - **Structured:** `final_judgment{}, status=active` OR `default_judgment{}, status=active`
- **`motion_reduction_of_sentence`** — Rigid 120-day window to reduce a sentence (TRCrP 35).
  - **Additional Requires (Hard):** prior `final_judgment` containing a sentence, within 120 days.
  - **Structured:** `final_judgment{type=sentence, age<=120d}, status=active`
- **`motion_correct_illegal_sentence`** — Asserts the sentence directly contravenes a statute (TRCrP 36.1).
  - **Additional Requires (Hard):** prior `final_judgment` containing a sentence.
  - **Structured:** `final_judgment{type=sentence}, status=active`
- **`motion_discretionary_costs`** — Winning civil party forces the loser to pay reporter and expert fees (TRCP 54.04).
  - **Additional Requires (Hard):** prior `final_judgment` identifying the prevailing party.
  - **Structured:** `final_judgment{}, status=active`
- **`petition_coram_nobis`** — Newly discovered evidence that could have changed the trial outcome (T.C.A. § 40-26-105). 1-year SOL; trial convictions only.
  - **Additional Requires (Hard):** prior `final_judgment` resulting from a `verdict` (not a `settlement_plea_agreement`).
  - **Structured:** `final_judgment{disposition=verdict}, status=active`
- **`petition_post_conviction_relief`** — Collateral attack on a conviction, typically alleging ineffective assistance of counsel (T.C.A. § 40-30-101).
  - **Additional Requires (Hard):** prior `final_judgment` with a criminal conviction.
  - **Structured:** `final_judgment{type=criminal_conviction}, status=active`
- **`motion_post_trial_general`** *(catch-all)* — Non-standard request after the verdict that may impact appeals or execution.
  - **Additional Requires (Hard):** prior `verdict` or `final_judgment`.
  **Payload:** `custom_title` required (e.g., `"Motion for Installment Payment Plan on Judgment"`).

### 3I. Appellate Bridge Motions

- **`motion_interlocutory_appeal`** — Asks the trial judge for permission to immediately appeal a mid-case ruling (TRAP 9).
  - **Additional Requires (Hard):** prior `interlocutory_order` (the ruling sought to be appealed).
  - **Structured:** `interlocutory_order{}, status=active`
- **`motion_extraordinary_appeal`** — Direct request to the appellate court to intervene (TRAP 10).
- **`motion_stay_of_execution_pending_appeal`** — Stops enforcement of a judgment, debt collection, or sentence while appeal is pending (TRCP 62 / TRAP 7).
  - **Additional Requires (Hard):** prior `notice_of_appeal` on this case root.
  - **Structured:** `notice_of_appeal{}, status=active`

## 4. Discovery & Evidence

Substantive evidentiary entries (distinct from the discovery *motions* in §3D).

- **`discovery_filing`** — Submission of interrogatories, witness lists, or sworn depositions into the record.
  - **Requires (Hard):** prior `case_initiation` on this case root.
- **`evidence_admittance`** — Formal acceptance of a physical or digital artifact into the trial record. Provenance flows through the prosecutor's chain of custody before Clerk hashing.
  - **Requires (Hard):** prior `case_initiation` on this case root.
- **`access_grant`** — Cryptographic granting of access to a restricted piece of evidence to opposing counsel or the judge.
  - **Requires (Hard):** prior `evidence_admittance` for the artifact.
  - **Structured:** `evidence_admittance{evidence_id}, status=active`
- **`competency_evaluation_order`** — Order commanding a medical evaluation of a party's fitness to stand trial.
  - **Requires (Hard):** prior `motion_competency_evaluation` OR sua sponte issuance by an Adjudicator.
  - **Structured:** `motion_competency_evaluation{}, status=active` OR `null{sua_sponte=true}`

## 5. Hearings & Logistics

- **`scheduling_order`** — Establishes the official timeline (trial dates, discovery deadlines).
  - **Requires (Hard):** prior `case_initiation` on this case root.
- **`hearing_convened_concluded`** — Clerk's minute entry recording that a proceeding took place.
  - **Requires (Advisory):** prior `scheduling_order` containing the hearing date.
- **`transcript_publication`** — Court Reporter publishes the certified verbatim record.
  - **Requires (Hard):** prior `hearing_convened_concluded` on this case root.
  - **Structured:** `hearing_convened_concluded{hearing_id}, status=active`

## 6. Court Orders & Enforcement

Adjudicator-signed entries.

- **`interlocutory_order`** — Ruling on a motion that keeps the case moving forward without ending it.
  - **Requires (Hard):** prior motion event on this case root that this order rules on.
  - **Structured:** `motion_*{motion_id}, status=active`
- **`protective_restraining_order`** — Commands a party to stay away from someone, or forbids destruction of assets.
  - **Requires (Hard):** prior `case_initiation` on this case root.
- **`warrant_issuance_return`** — Authorizes arrest or search; subsequent record of execution.
- **`sealing_unsealing_order`** *(Path C Enforcement)* — Cryptographically hides a document, party, or docket from public view, or reverses that action.
  - **Requires (Hard):** prior entry that is the target of the seal or unseal (e.g., a specific event, party, or the case root itself). For an `unsealing_order`, requires a prior `sealing_order` on the same target.

## 7. Adjudication

Trial-court resolutions. Appellate resolutions are in §7B.

- **`verdict`** — Official conclusion of the facts, decided by jury or judge.
  - **Requires (Hard):** prior `case_initiation` on this case root.
- **`final_judgment`** — Definitive legal end of the case (sentencing, monetary award, injunction, divorce decree). Permissive on the path to judgment: may follow a `verdict`, a `settlement_plea_agreement`, a granted dispositive motion, or judgment on the pleadings.
  - **Requires (Hard):** prior `case_initiation` on this case root.
  - **Structured:** `case_initiation{}, status=active`
- **`default_judgment`** — Plaintiff wins automatically because the defendant failed to respond.
  - **Requires (Hard):** prior `motion_default_judgment` granted.
  - **Structured:** `motion_default_judgment{}, status=granted`
- **`dismissal`** — Case is thrown out by the court (with or without prejudice).
  - **Requires (Hard):** prior `case_initiation` on this case root.
- **`settlement_plea_agreement`** — Parties resolve the dispute themselves; the court accepts the agreement.
  - **Requires (Hard):** prior `case_initiation` and `party_binding` for all parties to the agreement.

## 7B. Appellate Opinions and Disposition

Events that operate on **appellate case roots** at the Tennessee Court of Appeals exchange. An appellate case root is created by `appellate_case_initiation` and is distinct from the trial case root it reviews. The appellate court's `appellate_disposition` flows back to the trial court's case root via `remand_affirmance` (§8) using cross-network reference.

The Tennessee Court of Appeals hears appeals in three-judge panels. An opinion is recorded as two distinct event classes that compose freely:

1. **`appellate_opinion_publication`** — the opinion document itself, with its type and (typically) author.
2. **`appellate_opinion_participation`** — each judge's relationship to that opinion.

The author's authorship is implied by `author_did` on the publication event; other judges write their own participation events. A single judge in a single case can author one opinion, join part of another, and dissent from a third — all expressed as composable participation entries against the relevant publication entries.

**Composite positions are derived, not stored.** A judge's overall position in the case (concurred / dissented / did not participate / authored majority / etc.) is computed by the aggregator from participation entries across all the case's opinions. The log records the atomic relationships; the aggregator composes them.

### 7B.1 Appellate Case Root

- **`appellate_case_initiation`** — Foundational entry creating an appellate case root at the Tennessee Court of Appeals exchange. Carries `trial_case_ref` (cross-network pointer to the trial case root being reviewed) and a `review_type` (one of: `direct_appeal`, `interlocutory_appeal`, `extraordinary_appeal`).
  *Origin event for appellate case roots.*
  - **Requires (Advisory):** prior `notice_of_appeal` on the referenced trial case root. *Cross-network: the trial-side `notice_of_appeal` may not yet be visible when the appellate court dockets the appeal; the log accepts and the aggregator flags.*

### 7B.2 Opinions

- **`appellate_opinion_publication`** — Publication of an opinion by the panel. **Mints a case-local `opinion_id`.** Payload carries:
  - `opinion_type` — one of: `majority`, `plurality`, `per_curiam`, `memorandum`, `concurrence`, `concurrence_in_judgment`, `concurrence_in_part`, `concurrence_in_part_concurrence_in_judgment`, `dissent`, `dissent_in_part`, `concurrence_in_part_dissent_in_part`. The Tennessee Court of Appeals operates in three-judge panels; signed opinions are the norm and `per_curiam` is rare.
  - `author_did` — the authoring Adjudicator's DID, or `null` for `per_curiam`.
  - `parts` — optional list of part identifiers (e.g., `["I", "II", "III"]`) for opinions that are structurally subdivided to support join-by-section.
  - Opinion text or a content hash.
  - **Requires (Hard):** prior `appellate_case_initiation` on this appellate case root.
  - **Structured:** `appellate_case_initiation{}, status=active`

  > 🚩 **Developer flag — opinion type enum.** *The set of `opinion_type` values accepted by `appellate_opinion_publication` is defined by the network in code. The dictionary lists the canonical types for the Tennessee Court of Appeals.*

- **`appellate_opinion_participation`** — A judge's relationship to a specific opinion. Payload carries:
  - `opinion_id` — references the publication event.
  - `judge_did` — the participating Adjudicator's DID.
  - `role` — one of: `joined`, `joined_in_part`, `joined_except_as_to`, `did_not_join`, `recused`, `did_not_participate`. (The `authored` role is not used here; authorship is captured by `author_did` on the publication event.)
  - `parts` — list of part identifiers when `role` is `joined_in_part` or `joined_except_as_to`; null otherwise.
  - **Requires (Hard):** prior `appellate_opinion_publication` for the referenced `opinion_id`.
  - **Structured:** `appellate_opinion_publication{opinion_id}, status=active`

  > 🚩 **Developer flag — participation role enum.** *The set of participation roles is defined by the network in code. The dictionary lists the canonical roles.*

### 7B.3 Disposition

- **`appellate_disposition`** — The bottom-line case outcome the panel reaches. Carries:
  - `outcome` — one of: `affirmed`, `reversed`, `vacated`, `remanded`, `affirmed_in_part_reversed_in_part`, `dismissed`.
  - `panel` — list of participating judge DIDs (typically three).
  - `vote_tally` — informational summary (e.g., `"3-0"`, `"2-1"`). Authoritative source remains the participation events.
  - **Requires (Hard):** prior `appellate_opinion_publication` of at least one merits-level opinion (`majority`, `plurality`, `per_curiam`, or `memorandum`) on this appellate case root.
  - **Structured:** `appellate_opinion_publication{opinion_type IN [majority, plurality, per_curiam, memorandum]}, status=active`

  > 🚩 **Developer flag — disposition outcome enum.** *The set of `outcome` values accepted by `appellate_disposition` is defined by the network in code. The dictionary lists the canonical outcomes.*

## 8. Post-Judgment & Ongoing Oversight

- **`notice_of_appeal`** — Party officially declares appeal to the Tennessee Court of Appeals. Triggers creation of an `appellate_case_initiation` at the Court of Appeals exchange (cross-network).
  - **Requires (Hard):** prior `final_judgment`, `default_judgment`, or `dismissal` on this case root.
  - **Structured:** `final_judgment{}, status=active` OR `default_judgment{}, status=active` OR `dismissal{}, status=active`
- **`remand_affirmance`** — Entry pushed down from the appellate log: higher court agrees, or sends back for correction. Originates as an `appellate_disposition` on the appellate case root and is mirrored to the trial case root via cross-network reference.
  - **Requires (Advisory):** prior `notice_of_appeal` on this case root. *Cross-network entries from appellate logs may legitimately arrive before the local `notice_of_appeal` is fully docketed; the log accepts and the aggregator flags.*
  - **Structured:** `notice_of_appeal{}, status=active`
- **`post_judgment_enforcement`** — Wage garnishment, probation revocation, etc.
  - **Requires (Hard):** prior `final_judgment` or `default_judgment`.
- **`expungement`** — Permanent cryptographic destruction of the case record. *Statutory waiting periods, eligibility checks, and disposition gating are concerns of the aggregator and the filing UI; the log enforces only that the case exists and has not already been expunged.*
  - **Requires (Hard):** prior `case_initiation` on this case root.
  - **Requires (Hard):** no prior `expungement` on this case root (cannot expunge twice).
  - **Structured:** `case_initiation{}, status=active` AND NOT `expungement{}, status=active`
- **`fiduciary_accounting`** — Annual ledger submitted by a fiduciary showing how they spent a ward's or estate's money.
  - **Requires (Hard):** prior `letters_of_administration` granting fiduciary authority on this case root.
  - **Structured:** `letters_of_administration{fiduciary_did}, status=active`
- **`asset_disposition_order`** — Court approval allowing a fiduciary to sell a major asset.
  - **Requires (Hard):** prior `letters_of_administration` granting fiduciary authority.

## 9. Alternative Dispute Resolution & Diversion

- **`adr_referral`** — Court diverts the case to a mediator, settlement judge, or benefit review process.
  - **Requires (Hard):** prior `case_initiation` on this case root.
- **`confidential_settlement_statement`** — Restricted submission outlining negotiation positions to the settlement judge.
  - **Requires (Hard):** prior `adr_referral` on this case root.
  - **Structured:** `adr_referral{}, status=active`
- **`adr_disposition`** — Mediation failed (returns to docket) or succeeded (triggers final settlement).
  - **Requires (Hard):** prior `adr_referral` on this case root.
- **`agreed_summary_trial`** — Specialized expedited proceeding with high/low damage caps and waived appeals.
  - **Requires (Hard):** prior `case_initiation` and `responsive_pleading` on this case root.

## 10. Fiduciary & Proxy Appointments *(Chancery & Probate)*

- **`reference_to_master`** — Judge delegates a complex factual issue to a court appointee for investigation and report.
  - **Requires (Hard):** prior `case_initiation` on this case root.
- **`appointment_guardian_ad_litem`** — Court appoints an independent attorney to represent a vulnerable subject's best interests.
  - **Requires (Hard):** prior `party_binding` for the vulnerable party.
  - **Structured:** `party_binding{binding_id=vulnerable_party}, status=active`
- **`letters_of_administration`** — Formal cryptographic grant of authority to a fiduciary (Executor, Conservator, Guardian) to act on behalf of an estate or ward.
  - **Requires (Hard):** prior `case_initiation` on this case root.

---

# Part 3 — Administrative Events

Events that govern the existence, personnel, and governance of courts, separate from individual cases.

## 11. Structural Reorganization & Expansion

The court's blueprint at the institutional level. Note the structural distinction: **`exchange_onboarding`** brings a new court onto an existing network; **`scope_division_creation`** creates a subdivision within an existing exchange; the cross-network operation (forking a new network) lives in §16.

- **`exchange_onboarding`** — Onboards a new court (a new exchange) onto the existing network. Creates the exchange's institutional DID, bootstraps its initial Signers, and registers it with the network's anchor hierarchy. The new exchange writes to the same shared log as all other exchanges.
  *Origin event.*
- **`scope_division_creation`** — Creates a new division *within* an existing exchange (e.g., establishing a Business Court within a county court). Divisions share the parent exchange's Signers and delegation chain.
  - **Requires (Hard):** prior `exchange_onboarding` for the parent exchange.
  - **Structured:** `exchange_onboarding{exchange_did}, status=active`
- **`specialty_court_designation`** — Carves out a specialized docket from existing divisions and routes specific schemas to it.
  - **Requires (Hard):** prior `scope_division_creation` for the affected division.
- **`jurisdictional_consolidation`** — Merges two existing exchanges within the same network (e.g., folding Probate into Chancery). Records the merging of scopes and the transfer of active case roots.
  - **Requires (Hard):** prior `exchange_onboarding` for each exchange being consolidated.

## 12. Judicial Appointments, Succession & Personnel

The lifecycle of Signer cryptographic authority — appointment (creation), succession (transfer), and revocation (termination). All events in this section are **intra-exchange**: Signers within an exchange certify changes to that exchange's authority set.

### 12A. Appointments *(new authority)*

Initial creation of write authority for a person who did not previously hold a Signer key on this network. **Every appointment requires cosignature from existing Signers within the same exchange** to prevent unilateral authority creation. The real-world process by which a person becomes eligible for the role (election, gubernatorial appointment, hiring) is irrelevant to the network — what matters is that the exchange's existing Signers cryptographically attest to the new authority before it becomes active.

> 🚩 **Developer flag — appointment cosignature thresholds.** *The exact cosignature requirement for each appointment event (e.g., unanimous, supermajority, simple majority of sitting Adjudicators within the exchange) is defined by the network in code, not in this dictionary. Each appointment event below requires its own threshold decision.*

- **`judicial_appointment`** — Initial Judicial Appointment. First-time creation of an Adjudicator's write authority on the exchange. Requires intra-exchange cosignature from current sitting Adjudicators per the network's appointment threshold.
  - **Requires (Hard):** prior `exchange_onboarding` for the target exchange.
- **`clerk_appointment`** — Creates a new Signer for case ingestion and proxy signing within the exchange.
  - **Requires (Hard):** prior `exchange_onboarding` for the target exchange.
- **`magistrate_appointment`** — An Adjudicator delegates limited write authority to a magistrate, scoped to specific case types or pretrial matters.
  - **Requires (Hard):** prior `judicial_appointment` for the delegating Adjudicator.
  - **Structured:** `judicial_appointment{adjudicator_did=delegator}, status=active`
- **`court_reporter_appointment`** — Issues the specialized cryptographic key used exclusively for `transcript_publication`.
  - **Requires (Hard):** prior `exchange_onboarding` for the target exchange.
- **`deputy_appointment`** — A Signer delegates limited operational authority to a deputy. Bound by the parent's scope; revoked automatically if the parent is revoked.
  - **Requires (Hard):** prior appointment event for the delegating Signer (e.g., `clerk_appointment`, `court_reporter_appointment`).

### 12B. Succession *(authority transfer)*

- **`judicial_succession_standard`** — Planned transition: the outgoing Adjudicator's write authority is terminated and the Division's authority transfers to the incoming Adjudicator's DID. Signed by the outgoing Adjudicator (own succession) where possible.
  - **Requires (Hard):** prior `judicial_appointment` for the outgoing Adjudicator, status=active.
  - **Structured:** `judicial_appointment{adjudicator_did=outgoing}, status=active`
- **`emergency_continuity_of_authority`** — Sudden death or catastrophic incapacitation of the root authority figure within an exchange. Triggers a predetermined continuity protocol to mathematically prove the vacancy and mint root authority for the statutory successor.
  - **Requires (Hard):** prior `judicial_appointment` for the affected Adjudicator, status=active.

  > 🚩 **Developer flag — continuity threshold.** *The M-of-N threshold for emergency continuity (which Signers within the exchange, and how many, must cosign to certify a vacancy) is defined by the network in code.*

- **`pro_tem_emergency_appointment`** — An Adjudicator becomes temporarily unavailable. The Presiding Judge writes a time-bound or case-bound delegation granting temporary authority to a visiting Adjudicator.
  - **Requires (Hard):** prior `judicial_appointment` for the unavailable Adjudicator, status=active.

### 12C. Termination *(authority revocation)*

- **`authority_revocation_disciplinary`** — A Signer is removed for cause. Immediately severs the actor's cryptographic ability to sign filings.
  - **Requires (Hard):** prior appointment event for the Signer being revoked, status=active.
- **`term_expiration`** — Graceful end of a fixed-term mandate when no successor has been seated.
  - **Requires (Hard):** prior appointment event for the Signer whose term is expiring, status=active.
- **`voluntary_resignation`** — Signer steps down mid-mandate.
  - **Requires (Hard):** prior appointment event for the resigning Signer, status=active.

## 13. Governance & Consortium Operations

The law of the network — how an exchange interacts with other exchanges sharing the same network.

- **`facility_closure`** — An exchange is closed for routine or unforeseen logistical reasons.
  - **Requires (Hard):** prior `exchange_onboarding` for the exchange being closed.
- **`emergency_disaster_tolling`** — Catastrophic event shuts down an exchange's facility indefinitely. Pauses all statute-of-limitation timers and scheduling deadlines until lifted.
  - **Requires (Hard):** prior `exchange_onboarding` for the affected exchange.
- **`local_rule_promulgation`** — An exchange's Adjudicators collectively change procedural rules.
  - **Requires (Hard):** prior `exchange_onboarding` for the promulgating exchange.

  > 🚩 **Developer flag — rule promulgation quorum.** *The voting threshold required for `local_rule_promulgation` (which Adjudicators must cosign, and how many) is defined by the network in code.*

---

# Part 4 — Technical Events

Events that operate on the log substrate itself rather than on cases or personnel directly.

## 14. Cryptographic & Key Maintenance

Key lifecycle events internal to a single exchange's authority set.

- **`institutional_key_rotation`** — Routine security upgrade. A Signer rotates the underlying cryptographic keypair without losing their established DID identity.
  - **Requires (Hard):** prior appointment event establishing the rotating Signer.
- **`temporal_shard_archiving`** — A network's log grows too large for efficient operation. The active log is frozen, archived, and a Genesis entry is written to start a fresh log that cryptographically links back to the final state of the old one.
  *Origin event for the new log; references the archived log's final tip.*
- **`mofn_escrow_recovery_execution`** — Disaster recovery. Designated officials use their escrowed threshold shares to reconstruct the exchange's authority on new hardware.
  - **Requires (Hard):** prior `exchange_onboarding` for the exchange being recovered.

  > 🚩 **Developer flag — escrow recovery threshold.** *The M-of-N threshold for escrow recovery (how many escrow shareholders must cooperate to reconstruct authority) is defined by the network in code.*

- **`cms_bridge_migration`** — An exchange switches case management software vendors. Revokes the old vendor's API key authority and delegates automated filing powers to the new vendor.
  - **Requires (Hard):** prior `exchange_onboarding` for the migrating exchange.

## 15. Schema Lifecycle

Schemas are first-class entries on the log, not infrastructure. Any exchange may publish, adopt, or evolve a schema; the network processes all entries identically regardless of which schema they reference.

- **`schema_publication`** — Exchange publishes a new schema as a versioned, signed entry. Defines public/private fields and an optional `predecessor` reference for evolution chains.
  *Origin event (or referential, if `predecessor` is set).*
- **`schema_adoption`** — Exchange formally adopts an existing schema, allowing it to process payloads conforming to it.
  - **Requires (Hard):** prior `schema_publication` for the adopted schema (on this network or a referenced parent network).
  - **Structured:** `schema_publication{schema_id}, status=active`
- **`schema_amendment`** — Evolves a schema by publishing a successor version with a `predecessor` reference.
  - **Requires (Hard):** prior `schema_publication` for the predecessor schema.
- **`schema_deprecation`** — Marks a schema as deprecated. Existing entries remain valid; new entries against the deprecated schema are rejected after a grace period.
  - **Requires (Hard):** prior `schema_publication` for the schema being deprecated.

  > 🚩 **Developer flag — deprecation grace period.** *How long after `schema_deprecation` new entries against the schema continue to be accepted is defined by the network in code.*

## 16. Network Topology & Forking

Events that operate on the network itself — creating new networks, anchoring across networks, and moving cases or attestations between networks.

**Forks are new networks, not new courts.** Onboarding a new court onto the existing network is `exchange_onboarding` (§11); creating a new network is `network_fork` here. A fork is motivated by horizontal scalability (the existing network has grown too large for efficient operation), jurisdictional independence (e.g., a federal court system operating outside a state network), or governance separation (a sub-consortium that needs its own anchor hierarchy).

- **`network_fork`** — Instantiates a new network — a new shared Attesta log with its own anchor hierarchy. Used when forking is motivated by scalability, jurisdictional independence, or governance separation. Specialty courts that require their own log set, federal courts joining the broader network, and large-scale shard operations all use this event.
  *Origin event for the new network.*
- **`anchor_registration`** — Establishes a periodic publishing interval that mirrors a network's log state to a parent log for cross-network verification via compound proofs.
  *Origin event (one per parent log).*

  > 🚩 **Developer flag — anchor publishing interval.** *How frequently `anchor_registration` events are published, and to which parent logs, is defined by the network in code.*

- **`mirror_creation`** — Eagerly mirrors a delegation chain or schema reference so that downstream consumers can verify entries authored by officers introduced earlier on the log.
  - **Requires (Hard):** prior entry being mirrored (a delegation or schema event).
- **`mirror_revocation`** — Tears down a mirror when the underlying delegation is revoked. Cascades automatically from `authority_revocation_disciplinary`.
  - **Requires (Hard):** prior `mirror_creation` for the mirror being revoked.
  - **Structured:** `mirror_creation{mirror_id}, status=active`
- **`relay_attestation`** — Attests to a verified entry from another log (typically across networks). Used for cross-network case transfers, cross-jurisdiction order recognition, and historical migration.
  *Origin event on this log; references a remote log entry via compound proof.*
- **`case_transfer_outbound`** — An exchange releases a case to another exchange or another network.
  - **Requires (Hard):** prior `case_initiation` on this case root.
  - **Structured:** `case_initiation{}, status=active`
- **`case_transfer_inbound`** — An exchange accepts a case from another exchange or another network. Creates a new case root with `transfer_ref` pointing to the originating log.
  - **Requires (Hard):** prior `relay_attestation` referencing the originating case.
  - **Structured:** `relay_attestation{ref=originating_case}, status=active`
- **`bulk_historical_import`** — Heavyweight migration: a new exchange or new network imports a predecessor's historical cases. Each imported case is a new root entry referencing the original via cross-log pointer.
  - **Requires (Hard):** prior `relay_attestation` for each imported case.

---

# Appendix A — Catch-All Event Inventory

All `*_general` catch-all events. Each requires a `custom_title` payload field.

| Event Type | Section | Example `custom_title` |
|---|---|---|
| `motion_pleading_general` | 3A | `"Motion to Strike Surplusage"` |
| `motion_dispositive_general` | 3B | `"Motion to Dismiss for Lack of Standing"` |
| `motion_equitable_general` | 3C | `"Motion for Writ of Replevin"` |
| `motion_discovery_general` | 3D | `"Motion to Permit Inspection of Premises"` |
| `motion_procedural_general` | 3G | `"Motion to Allow Attorney to Appear via Zoom"` |
| `motion_post_trial_general` | 3H | `"Motion for Installment Payment Plan on Judgment"` |

# Appendix B — Developer Flags Inventory

Every place this dictionary defers a decision to the network's implementing code. The dictionary specifies *that* a decision is required; code defines the specific value or policy.

| # | Flag | Section | Decision Required |
|---|---|---|---|
| 1 | Filer cosignature mix | Conventions | Which Signer may cosign which event types when filed by which Filer |
| 2 | Cross-exchange cosignature validity | Conventions | Which events require **intra-exchange** cosignature only vs. which permit or require **cross-exchange** cosignatures |
| 3 | Prerequisite validation policy | Conventions | Which prerequisites are Hard (rejection on miss) vs. Advisory (acceptance with flag); time-bounded prerequisite enforcement |
| 4 | Judicial appointment threshold | §12A | Cosignature requirement for `judicial_appointment` |
| 5 | Clerk appointment threshold | §12A | Cosignature requirement for `clerk_appointment` |
| 6 | Court Reporter appointment threshold | §12A | Cosignature requirement for `court_reporter_appointment` |
| 7 | Magistrate appointment authority | §12A | Whether a single Adjudicator may appoint a magistrate alone, or whether cosignature is also required |
| 8 | Emergency continuity threshold | §12B | M-of-N threshold for `emergency_continuity_of_authority` |
| 9 | Rule promulgation quorum | §13 | Voting threshold for `local_rule_promulgation` |
| 10 | Escrow recovery threshold | §14 | M-of-N threshold for `mofn_escrow_recovery_execution` |
| 11 | Schema deprecation grace period | §15 | How long after `schema_deprecation` new entries against the schema are still accepted |
| 12 | Anchor publishing interval | §16 | Frequency of `anchor_registration` events and the parent log set |
| 13 | Catch-all `custom_title` policy | App. A | Free-text vs. enum-controlled vocabulary; minimum/maximum length |
| 14 | Opinion type enum | §7B.2 | Set of `opinion_type` values accepted by `appellate_opinion_publication` |
| 15 | Participation role enum | §7B.2 | Set of roles accepted by `appellate_opinion_participation` |
| 16 | Disposition outcome enum | §7B.3 | Set of `outcome` values accepted by `appellate_disposition` |

---

# Change Log

## v1.8

**Theme:** Scope §7B to the Tennessee Court of Appeals. Removes SCOTUS-specific events and multi-level appellate chaining language; trims enums to the values that actually apply to a three-judge intermediate appellate panel hearing civil appeals.

- **Conventions / Case Roots** — Removed multi-level appeal chaining language. Appellate case roots live at the Tennessee Court of Appeals exchange.
- **§7B intro** — Reframed around three-judge panels and the Tennessee Court of Appeals; removed seriatim and SCOTUS-style references.
- **§7B.2 `appellate_opinion_publication`** — Trimmed `opinion_type` enum: removed `seriatim` (historical SCOTUS practice), `special_concurrence` (state-court-terminology footnote not used in TN). Noted that signed opinions are the norm in TN intermediate appellate practice and `per_curiam` is rare. Removed `cert_subtype` and any references to certiorari.
- **§7B.1 `appellate_case_initiation`** — Trimmed `review_type` enum to three values: `direct_appeal`, `interlocutory_appeal`, `extraordinary_appeal`. Removed `certiorari` (TN Court of Appeals has no cert stage).
- **§7B.3 `appellate_disposition`** — Trimmed `outcome` enum: removed `cert_denied`, `cert_granted`, `cert_dismissed`. Updated example `vote_tally` to reflect three-judge panels (`"3-0"`, `"2-1"`). Updated merits-opinion prerequisite to drop `seriatim` from the accepted set.
- **§7B.4** — Removed entirely. `cert_stage_opinion` and `in_chambers_opinion` were SCOTUS-specific events with no equivalent in TN intermediate appellate practice.
- **§8 `notice_of_appeal`** — Updated to reference the Tennessee Court of Appeals specifically.
- **Appendix B** — Flag count unchanged at 16. Each remaining enum flag (opinion type, participation role, disposition outcome) reflects the trimmed TN-specific values.

## v1.7

**Theme:** Appellate opinions and disposition (separate appellate case root model).

- Added "Case Roots: Trial vs. Appellate" subsection in Conventions.
- Added `opinion_id` to case-local identifiers.
- Added §7B with `appellate_case_initiation`, `appellate_opinion_publication`, `appellate_opinion_participation`, `appellate_disposition`, plus (subsequently removed in v1.8) `cert_stage_opinion` and `in_chambers_opinion`.
- Updated `notice_of_appeal` and `remand_affirmance` descriptions to reference cross-network appellate flow.
- Added Flags 14, 15, 16 (opinion type, participation role, disposition outcome enums).

## v1.6

**Theme:** De-overengineering. Trims false constraints from prerequisites where real-world events legitimately race or where statutory eligibility belongs in the aggregator/UI rather than the log.

- §3 Motions — Added vocabulary-constraint paragraph stating attorneys file motions from the dictionary's defined `event_type` enum only.
- §3D `motion_quash_subpoena` — Removed editorial caveat about subpoena origination.
- §7 `final_judgment` — Removed Advisory prerequisite for prior `verdict` or `settlement_plea_agreement`.
- §8 `expungement` — Replaced disposition-gating prerequisite with a simpler "exists and not previously expunged" rule.
- §8 `remand_affirmance` — Demoted `notice_of_appeal` prerequisite from Hard to Advisory.

## v1.5

**Theme:** Role naming, party model, and event prerequisites.

- Replaced "Tier 1 / Tier 2 / Tier 3" with **Signers / Filers / Parties** throughout.
- Made explicit that Parties are not network entities and have no DIDs; they live as case-local data inside `party_binding` events.
- Added `binding_id` and `appearance_id` as case-local identifiers.
- Restructured counsel relationships to support multi-defendant, multi-attorney, and shared-counsel scenarios via concurrent `counsel_appearance` events.
- Introduced "Event Prerequisites and Log State" classifying events as Origin / Dependent / Terminal with Hard/Advisory `Requires:` annotations.

## v1.4

**Theme:** Network / Exchange / Division hierarchy.

- Added Network / Exchange / Division hierarchy subsection in Conventions.
- Added cross-exchange cosignature validity flag.
- Added `exchange_onboarding` to §11 for new courts joining an existing network.
- Renamed `court_provisioning` → `network_fork` in §16 and reframed forking as a network operation.
- Marked all §12 personnel events as intra-exchange.

## v1.3

- Reframed Attesta as the append-only signed log substrate (CT-Log-style); removed all phase / SDK / ledger / Pydantic references.
- Stripped prescriptive code recommendations from Implementation Notes.
- Added inline 🚩 developer flags consolidated into Appendix B.
- §12A appointments reframed: political process irrelevant to the network; cosignature is what matters.

## v1.2

- Restructured Part 3 (Administrative: §11 Structural, §12 Personnel, §13 Governance) and Part 4 (Technical: §14 Crypto/Keys, §15 Schema, §16 Topology).
- Added §12A judicial appointments separate from succession and termination.
- §15 introduced schema lifecycle as first-class events; §16 introduced forking primitives.

## v1.1

- Added Part 1 — Actors with three-role model (cryptographic signers, advocates, parties).
- Added Filer cosignature requirement.
- Introduced aggregator microservice as the canonical read-side separation.

## v1.0

- Initial event dictionary draft. Four parts: Actors, Case Lifecycle, Administrative, Technical. Catch-all events with `custom_title` payload field for non-standard motions.

---

*End of Event Dictionary v1.8.*
