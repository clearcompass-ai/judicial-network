# Case 1, Act II · Appeal to TN Court of Appeals

This is the centerpiece of the walkthrough. Two entries land on the
**second operator** (`$COA`, port 8081), and one of them carries
a public reference back to the trial-court entry on the **first
operator** (`$DAVIDSON`, port 8080) — the protocol's
cross-exchange composition mechanism.

Pre-flight: Act I (5 entries on Davidson) complete.
`$EDWARDS`, `$CLERK` exported. You're in `~/ortholog/keys`.

## The cross-exchange seam

The SDK gives every entry's `ControlHeader` a list of
**`EvidencePointers`** — `(log_did, sequence)` tuples that name
entries on other logs. The operator on the receiving end caps the
list at 10
([`operator/api/middleware/evidence_cap.go:20`](../../../../ortholog-operator/api/middleware/evidence_cap.go))
but enforces nothing beyond that — it's not the operator's job to
verify that the cited remote entry exists or means what the citing
entry claims. The audit is left to whoever consumes the citing
entry. That's the "dumb writes" architecture making cross-exchange
composition trivial: any entry can name any other entry on any
operator's log, with no prior trust setup, no cross-credentials, no
shared schema.

Schema field at `sdk/core/envelope/control_header.go:127`.

## Step 5 — COA disposition (`AppellateDispositionPayload`)

**Legally.** A three-judge panel of the Tennessee Court of Appeals
hears the case (we narrate as 1 judge for brevity). The disposition
is the panel's binding ruling: *affirmed, reversed, vacated,*
*remanded*, or various combinations. It must be filed on the COA
log because that's where the appellate authority sits, but it must
also pin the trial-court entry it disposes of — that pin is the
`EvidencePointers` reference.

**Schema:** `jn/schemas/appellate_disposition.go:34` / `:115`.

**Spec:**

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

judicial-cli submit --endpoint $COA --spec coa-disposition.spec.json
```

Note the **two changes** from every previous step:

1. `--endpoint $COA` — we're talking to the second operator.
2. `evidence_pointers` — the cross-exchange reference.

Output:

```
canonical_hash=8e1d3c2f9a5b6e4d7c8f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
status=accepted (HTTP 202)
sct={...COA OPERATOR SCT...}
```

Wait for it to land at COA sequence 1:

```bash
$ judicial-cli wait --endpoint $COA --hash 8e1d3c2f9a5b6e4d7c8f...
state=sequenced sequence=1
```

## Step 5b — Verify the cross-pointer survived

This is the moment of truth. The disposition was admitted by COA's
operator, sequenced into COA's Merkle log, and stored in COA's GCS
bucket. But the `EvidencePointers` field inside the entry header —
naming a sequence on a *different operator's* log — should be
exactly what we sent.

```bash
$ judicial-cli get --endpoint $COA --seq 1 | jq '.header.evidence_pointers'
[
  {
    "log_did":  "did:web:state:tn:davidson",
    "sequence": 1
  }
]
```

There it is.

**Now follow the pointer back.** The COA operator can't help you
with this — Davidson is a different operator with no relationship
to COA. You go to Davidson directly:

```bash
$ judicial-cli get --endpoint $DAVIDSON --seq 1 | jq '.header.signer_did, (.signatures[].signer_did)'
"did:key:zQ3sh...CLERK"
"did:key:zQ3sh...CLERK"
"did:key:zQ3sh...COOPER"
```

You just performed an audit move that **two operators with no shared
state** collaborated on, mediated only by the public cross-pointer.
This is the property the entire protocol is designed to provide:
*citable evidence across federation boundaries with no trust setup
between operators.*

## Step 6 — Opinion publication (`AppellateOpinionPublicationPayload`)

**Legally.** Justice Edwards publishes the written majority opinion.
The entry doesn't carry the opinion text — those bytes go to whatever
document store the court uses (often a private S3 bucket with public
read). The entry carries:

- `opinion_id` — a stable identifier the parties cite in further
  filings.
- `opinion_type` — `majority`, `concurring`, `dissenting`, etc.
- `content_hash` — sha256 of the canonical opinion document. **Any
  subsequent edit to the document text changes this hash, which
  the log already committed**; the log thus makes opinion text
  tamper-evident even though the text isn't on-log.
- `parts` — the structural sections (`facts`, `discussion`,
  `conclusion`).
- An `evidence_pointers` reference to the disposition this opinion
  explains (intra-log this time — both at COA).

**Schema:** `jn/schemas/appellate_opinion_publication.go:33` /
`:119`.

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

The opinion lands at COA sequence 2. Its `EvidencePointers` cite
COA sequence 1 (the disposition this opinion explains).

## End state

```bash
$ curl -fsS $DAVIDSON/v1/tree/head | jq '.size'
6
$ curl -fsS $COA/v1/tree/head | jq '.size'
2
```

| Log | # | Schema | Primary signer | Cosigner | Cross-ref |
|---|---|---|---|---|---|
| Davidson | 1 | `civil_case` | clerk (did:key) | cooper (did:key) | — |
| Davidson | 2 | `party_binding` | clerk | cooper | — |
| Davidson | 3 | `party_binding` | clerk | davis | — |
| Davidson | 4 | `counsel_appearance` | cooper | clerk | — |
| Davidson | 5 | `counsel_appearance` | davis | clerk | — |
| Davidson | 6 | `evidence_artifact` (web3) | clerk | **acme-ceo (did:pkh)** | — |
| COA | 1 | `appellate_disposition` | edwards | clerk | **→ Davidson:1** |
| COA | 2 | `appellate_opinion_publication` | edwards | clerk | → COA:1 |

**7 real DIDs (5 did:key court + 2 did:pkh web3 wallets). 2
exchanges. 1 cross-exchange reference. 2 different signing
primitives (64-byte SDK-native + 65-byte EIP-191 wallet) coexisting
on the same log. Every signature real. Every entry on a real
running operator. Every step reproducible from this file alone.**

## Why this matters

In a real federated deployment — say the U.S. federal courts plus 50
state appellate systems plus the Department of Justice plus various
pro-bono case-tracking nonprofits — operators don't have shared
admin credentials, don't have synchronized clocks, and don't have a
shared schema registry. What they have is the protocol: signed
canonical bytes with cross-pointers, served over HTTP with a Merkle
log behind every operator. This case showed that the cross-pointer
half works. **Case 2 will show how the system handles the most
delicate intra-exchange operations: sealed minor bindings, judicial
succession, delegation revocation.**

## Continue

[Case 2: *In re Anderson*](02-in-re-anderson.md).
