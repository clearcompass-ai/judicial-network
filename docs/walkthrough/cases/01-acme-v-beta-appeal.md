# Case 1, Act II · Appeal to TN Court of Appeals

The centerpiece of the walkthrough: two entries land on the **second
ledger** (`$COA`, port 8081). One of them carries a public reference
back to the trial-court entry on the **first ledger** (`$DAVIDSON`,
port 8080) — the protocol's cross-exchange composition mechanism in
action.

Each step uses the same four-part pattern documented in
[01-acme-v-beta-trial.md](01-acme-v-beta-trial.md): v1.8 citation →
actor role → submit → evidence curl + "what we proved" narrative.

Pre-flight: Act I (5 entries on Davidson) complete. `$EDWARDS`,
`$CLERK`, `$BETA_CFO` exported. `$DAVIDSON`, `$COA`, `$NETWORK_API`
exported. You're in `~/attesta/keys`.

## The cross-exchange seam

Every entry's `ControlHeader` carries an `EvidencePointers` list of
`(log_did, sequence)` tuples that name entries on other logs. The
receiving ledger caps the list at 10
([`ledger/api/middleware/evidence_cap.go:20`](../../../../ledger/api/middleware/evidence_cap.go))
but enforces nothing semantic — it's not the ledger's job to verify
that the cited remote entry exists or means what the citing entry
claims. The audit is left to whoever consumes the citing entry.
v1.8 §"Case Roots: Trial vs. Appellate" makes this concrete: "the
appellate court's `appellate_disposition` flows back to the trial
court's case root via `remand_affirmance` (cross-network
reference)."

Schema field at `sdk/core/envelope/control_header.go:127`
(`ControlHeader.EvidencePointers`).

## v1.8 conformance notes

Two known gaps documented here so future-walkthrough readers see
them before they hit them in code:

- **`appellate_case_initiation` schema missing.** v1.8 §7B.1 says
  an `appellate_case_initiation` event should be the foundational
  entry on an appellate case root. JN does not yet have an
  `appellate_case` schema — the walkthrough's first COA entry is
  the disposition itself (Step 5). Tracked separately. The
  cross-network reference pattern is structurally unaffected.
- **Ordering inversion.** v1.8 §7B.3 requires
  `appellate_disposition` to follow at least one merits-level
  `appellate_opinion_publication`. The walkthrough here lands the
  disposition first (Step 5) and the opinion second (Step 6) —
  operationally common in TN COA practice, but a v1.8 ordering
  inversion. When JN admission adds strict v1.8 prerequisite
  enforcement (🚩 developer flag in the dictionary), this flow
  reorders.

## Step 5 — COA disposition

**v1.8 citation.** §7B.3 `appellate_disposition` — *The bottom-line
case outcome the panel reaches. Carries outcome (one of: affirmed,
reversed, vacated, remanded, affirmed_in_part_reversed_in_part,
dismissed), panel (list of participating judge DIDs), and vote_tally.*

**Actor role.**

| Role | v1.8 Part 1 | DID method | Variable |
|---|---|---|---|
| Primary signer | **T1** Signer — Adjudicator (appellate justice) | did:key | `$EDWARDS` |
| Cosigner | **T1** Signer — Clerk (COA clerk) | did:key | `$CLERK` |

Per v1.8 Part 1 "Adjudicators", justices hold network keys and sign
"definitive rulings: final judgments, decrees, warrants, appellate
opinions". `did:key` is the canonical encoding for institutional
court keys; web3 wallets are out-of-pattern for judicial Signers
(see §02's actor-role table).

**Schema.** `schemas/appellate_disposition.go:36`
(`AppellateDispositionPayload`), `:118`
(`SerializeDispositionPayload`).

**Submit.**

```bash
cat > coa-disposition.spec.json <<EOF
{
  "schema":      "appellate_disposition",
  "destination": "did:web:state:tn:coa",
  "primary_signer_key": "justice-edwards.key.json",
  "cosigner_keys":      ["clerk-brown.key.json"],
  "evidence_pointers": [
    {"log_did": "did:web:state:tn:davidson", "sequence": 1}
  ],
  "payload": {
    "outcome":    "affirmed",
    "panel":      ["$EDWARDS"],
    "vote_tally": "1-0",
    "case_ref":   "2024-CV-001",
    "filed_date": "2024-12-01"
  }
}
EOF

$ judicial-cli submit --endpoint $COA --spec coa-disposition.spec.json
canonical_hash=8e1d3c2f9a5b6e4d7c8f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
status=accepted (HTTP 202)

$ judicial-cli wait --endpoint $COA --hash 8e1d3c2f9a5b6e4d7c8f...
state=sequenced sequence=1
```

Note the two changes from every previous step:

1. `--endpoint $COA` — second ledger.
2. `evidence_pointers` — the cross-exchange reference.

**Evidence (a) — confirm the cross-pointer survived round-trip
through canonical serialization:**

```bash
$ judicial-cli get --endpoint $COA --seq 1 | jq '.header.evidence_pointers'
[
  {
    "log_did":  "did:web:state:tn:davidson",
    "sequence": 1
  }
]
```

Per v1.8 §"Cryptographic Authority", the cross-pointer participates
in the canonical hash of this entry. Justice Edwards's signature
commits to the exact pointer above; no honest mutation can
post-hoc change which Davidson sequence this disposition
references.

**Evidence (b) — follow the pointer back to the trial-court entry
on a DIFFERENT ledger:**

```bash
$ judicial-cli get --endpoint $DAVIDSON --seq 1 \
    | jq '{schema: .header.schema_name, signer: .header.signer_did, cosigners: [.signatures[].signer_did]}'
{
  "schema":    "civil_case",
  "signer":    "did:key:zQ3sh...CLERK",
  "cosigners": ["did:key:zQ3sh...CLERK", "did:key:zQ3sh...COOPER"]
}
```

Two ledgers, no shared state, mediated only by the public
cross-pointer.

**Evidence (c) — verify JN's domain API recognizes the
appellate-disposition outcome:**

```bash
$ curl -fsS $NETWORK_API/v1/judicial/cases/2024-CV-001 \
    -H "X-Caller-DID: $EDWARDS" \
    -H "X-Cases-Log-DID: did:web:state:tn:davidson" \
    | jq '{docket, status, has_appellate_disposition: (.appellate_disposition != null)}'
{"docket":"2024-CV-001","status":"active","has_appellate_disposition":true}
```

**Code anchor.** `api/judicial/cases.go::caseLookupHandler` →
`cases/docket_query.go::LookupDocket`.

## Step 6 — Opinion publication

**v1.8 citation.** §7B.2 `appellate_opinion_publication` —
*Publication of an opinion by the panel. Mints a case-local
`opinion_id`. Payload carries `opinion_type` (majority, plurality,
per_curiam, memorandum, concurrence, dissent, etc.), `author_did`
(or null for per_curiam), optional `parts` list, and opinion text
or a content hash.*

**Actor role.**

| Role | v1.8 Part 1 | DID method | Variable |
|---|---|---|---|
| Primary signer | **T1** Signer — Adjudicator (opinion author) | did:key | `$EDWARDS` |
| Cosigner | **T1** Signer — Clerk | did:key | `$CLERK` |

`author_did` on the payload matches the primary signer.

**Schema.** `schemas/appellate_opinion_publication.go:35`
(`AppellateOpinionPublicationPayload`), `:123`
(`SerializeOpinionPublicationPayload`).

**Submit.**

```bash
cat > coa-opinion.spec.json <<EOF
{
  "schema":      "appellate_opinion_publication",
  "destination": "did:web:state:tn:coa",
  "primary_signer_key": "justice-edwards.key.json",
  "cosigner_keys":      ["clerk-brown.key.json"],
  "evidence_pointers": [
    {"log_did": "did:web:state:tn:coa", "sequence": 1}
  ],
  "payload": {
    "opinion_id":   "op-coa-2024-001",
    "opinion_type": "majority",
    "author_did":   "$EDWARDS",
    "parts":        ["facts", "discussion", "conclusion"],
    "content_hash": "sha256:5a3e6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f50",
    "case_ref":     "2024-CV-001",
    "filed_date":   "2024-12-01"
  }
}
EOF

judicial-cli submit --endpoint $COA --spec coa-opinion.spec.json
```

The opinion lands at COA sequence 2 with `EvidencePointers` citing
COA:1 (the disposition this opinion explains).

**Evidence — confirm the opinion's structure and author-identity
chain:**

```bash
$ judicial-cli get --endpoint $COA --seq 2 \
    | jq '.payload | {opinion_id, opinion_type, author: .author_did, parts, content_hash}'
{
  "opinion_id":   "op-coa-2024-001",
  "opinion_type": "majority",
  "author":       "did:key:zQ3sh...EDWARDS",
  "parts":        ["facts","discussion","conclusion"],
  "content_hash": "sha256:5a3e6b7c..."
}
```

What we proved (per v1.8):

- `opinion_id` minted as the case-local identifier per v1.8
  §"Case-Local Identifiers" — future
  `appellate_opinion_participation` entries cite this `opinion_id`
  and only resolve within this case root.
- `author_did` carries Justice Edwards's DID and matches the
  primary signer above — v1.8 §7B.2 invariant satisfied.
- `content_hash` commits to the off-log opinion document; any
  later edit changes this hash, which the log already committed.
  Tamper-evidence for documents stored elsewhere.

## Step 6b — Optional: Beta CFO's web3 acknowledgment (Polygon)

A representative example of a defendant principal acknowledging the
appellate outcome from their own wallet on a different EVM chain.
This is OPTIONAL — the appeal is resolved with Step 6; this step
demonstrates that web3 cosignatures across different chains
co-exist on the same log.

**v1.8 citation.** No specific event; this is a §"Read-Side
Separation" attestation pattern — a party acknowledging an outcome
from their wallet for downstream audit purposes. JN models it as a
generic `evidence_artifact` with `evidence_type=acknowledgment`.

**Actor role.**

| Role | v1.8 Part 1 | DID method | Wallet chain | Variable |
|---|---|---|---|---|
| Primary signer | **T1** Signer — Clerk (filing receipt) | did:key | — | `$CLERK` |
| Cosigner | **T3** Party (Beta's CFO) | did:pkh:eip155:**137** | **Polygon** | `$BETA_CFO` |

**Schema.** `schemas/evidence_artifact.go:75`
(`EvidenceArtifactPayload`).

**Submit.**

```bash
cat > beta-cfo-acknowledgment.spec.json <<EOF
{
  "schema":      "evidence_artifact",
  "destination": "did:web:state:tn:coa",
  "primary_signer_key": "clerk-brown.key.json",
  "cosigner_keys":      ["beta-cfo.key.json"],
  "evidence_pointers": [
    {"log_did": "did:web:state:tn:coa", "sequence": 1}
  ],
  "payload": {
    "evidence_id":         "ack-beta-cfo-2024-001",
    "evidence_type":       "acknowledgment",
    "classification":      "ordinary",
    "filed_by":            "$BETA_CFO",
    "case_ref":            "2024-CV-001",
    "description":         "Beta Corp CFO acknowledgment of disposition (Polygon wallet)",
    "content_digest":      "sha256:c4a8...",
    "artifact_encryption": "umbral_pre",
    "grant_authorization_mode": "open",
    "grant_entry_required":     true,
    "grant_requires_audit_entry": true,
    "chain_of_custody_required": false
  }
}
EOF
judicial-cli submit --endpoint $COA --spec beta-cfo-acknowledgment.spec.json
```

**Evidence — confirm Polygon wallet signature is on-log with the
correct chain identity:**

```bash
$ judicial-cli get --endpoint $COA --seq 3 \
    | jq '.signatures[] | {signer: .signer_did, algo: .algo_id, chain: (.signer_did | capture("eip155:(?<id>\\d+):").id // null)}'
{"signer":"did:key:zQ3sh...CLERK",                "algo":1,"chain":null}
{"signer":"did:pkh:eip155:137:0x5c8d92ab4fe6...","algo":3,"chain":"137"}
```

The Polygon wallet (chain id 137) signed via EIP-191 (algo 3) on
the same ledger that admits Ethereum mainnet wallets (chain id 1,
ACME CEO in trial Step 4). Two different EVM chains attesting on
the same case at different stages — exactly the multi-network
pattern v1.8 §"Parties" supports.

## End state

```bash
$ curl -fsS $DAVIDSON/v1/tree/head | jq '.size'
6
$ curl -fsS $COA/v1/tree/head | jq '.size'
3                                  # 2 if you skipped Step 6b
```

| Log | # | Schema | v1.8 § | Primary signer | Cosigner | Cross-ref |
|---|---|---|---|---|---|---|
| Davidson | 1 | `civil_case` | §1 case_initiation | Signer-Clerk | Filer-Attorney | — |
| Davidson | 2 | `party_binding` | §1 party_binding | Signer-Clerk | Filer-Attorney | — |
| Davidson | 3 | `party_binding` | §1 party_binding | Signer-Clerk | Filer-Attorney | — |
| Davidson | 4 | `counsel_appearance` | §1 counsel_appearance | Filer-Attorney | Signer-Clerk | — |
| Davidson | 5 | `counsel_appearance` | §1 counsel_appearance | Filer-Attorney | Signer-Clerk | — |
| Davidson | 6 | `evidence_artifact` | §4 evidence_admittance | Signer-Clerk | ****T3** Party (Eth-mainnet)** | — |
| COA | 1 | `appellate_disposition` | §7B.3 | Signer-Adjudicator | Signer-Clerk | **→ Davidson:1** |
| COA | 2 | `appellate_opinion_publication` | §7B.2 | Signer-Adjudicator | Signer-Clerk | → COA:1 |
| COA | 3 | `evidence_artifact` (ack) | §4 evidence_admittance | Signer-Clerk | ****T3** Party (Polygon)** | → COA:1 |

**9 DIDs across 2 EVM chains (Ethereum + Polygon) + 6 court did:key
identities. 2 exchanges. 1 cross-exchange reference. 2 signing
primitives on the same logs. Every party-principal cosignature
verifies through the SDK's PKHVerifier regardless of chain.**

## Why this matters

The cross-pointer mechanism makes federation trivial. **The
multi-chain wallet pattern makes party attestation trivial.**
Neither requires shared admin credentials, synchronized clocks, or
a shared schema registry. Both are part of the same protocol
shape: signed canonical bytes admitted to a Merkle log via HTTP.
**Case 2** demonstrates the harder intra-exchange operations: sealed
minor bindings, judicial succession, delegation revocation, and
parents on two more EVM chains (Base + Optimism).

## Continue

[Case 2: *In re Anderson*](02-in-re-anderson.md).
