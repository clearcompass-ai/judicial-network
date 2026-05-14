# Case 2, Act I · Family filing with a sealed minor + parental web3 acknowledgments

Five entries on the Davidson log. We open the family case, capture
parental acknowledgments from **two different EVM-chain wallets**
(mother on Base, father on Optimism), bind the minor child under
seal, record counsel appearance, and capture Judge Lewis's
delegation to the docket.

Each step follows the canonical four-part pattern from
[01-acme-v-beta-trial.md](01-acme-v-beta-trial.md): v1.8 citation →
actor role → submit → evidence curl.

Pre-flight: §01 + §02 done; Case 2 overview read; the three new
court-personnel keys (`judge-lewis`, `magistrate-owens`,
`atty-murphy`) minted in §02; `$ANDERSON_MOTHER` and
`$ANDERSON_FATHER` exported from §02's web3 enrollment.
`$NETWORK_API` is exported.

## Step 1 — File the family case

**v1.8 citation.** §1 `case_initiation` (FAMILY variant — divorce +
contested custody). v1.8 makes no distinction between civil /
family / juvenile at the dictionary level — they're all
`case_initiation` events with different `case_type` payload
discriminators. JN's separate schemas (`CivilCasePayload`,
`FamilyCasePayload`, `JuvenileCasePayload`) surface domain
validation at the type-level rather than runtime.

**Actor role.**

| Role | v1.8 Part 1 | DID method | Variable |
|---|---|---|---|
| Primary signer | **T1** Signer — Clerk | did:key | `$CLERK` |
| Cosigner | **T2** Filer — Civil Attorney (Murphy, mother's counsel) | did:key | `$MURPHY` |

**Schema.** `schemas/family_case.go:35` (`FamilyCasePayload`), `:84`
(`SerializeFamilyCasePayload`).

**Submit.**

```bash
cd ~/attesta/keys
cat > family-filing.spec.json <<EOF
{
  "schema":      "family_case",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "clerk-brown.key.json",
  "cosigner_keys":      ["atty-murphy.key.json"],
  "payload": {
    "docket_number": "2024-FAM-003",
    "case_type":     "divorce",
    "case_sub_type": "contested_custody",
    "filed_date":    "2024-05-10",
    "status":        "active"
  }
}
EOF

judicial-cli submit --endpoint $DAVIDSON --spec family-filing.spec.json
judicial-cli wait --endpoint $DAVIDSON --hash <hash from above>
```

The case lands at the next available Davidson sequence (if you ran
Case 1 first, this is sequence 7+1; if fresh, sequence 1).
Subsequent steps reference *N* meaning "previous step's sequence + 1".

**Evidence — confirm the case root exists with the right subtype:**

```bash
$ curl -fsS $NETWORK_API/v1/judicial/cases/2024-FAM-003 \
    -H "X-Caller-DID: $CLERK" \
    -H "X-Cases-Log-DID: did:web:state:tn:davidson" \
    | jq '{docket, status, type: .case_type, sealed: .is_sealed, root_seq: .case_root_pos.sequence}'
{
  "docket":   "2024-FAM-003",
  "status":   "active",
  "type":     "divorce",
  "sealed":   false,
  "root_seq": <N>
}
```

`sealed: false` at the case-root level — the case itself is NOT
sealed. The minor binding in Step 3 is where sealing applies (at
the *party* level, not the case level — v1.8 §6).

**Code anchor.** `api/judicial/cases.go::caseLookupHandler` →
`cases/docket_query.go::LookupDocket`.

## Step 2 — Parental acknowledgments (web3, two EVM chains)

Both parents acknowledge the filing from their personal wallets.
This is the multi-chain demonstration: **mother on Base (chain id
8453), father on Optimism (chain id 10)**, both verifying on the
same ledger through the same SDK PKHVerifier path.

**v1.8 citation.** No specific event; this is the §"Read-Side
Separation" attestation pattern that Case 1 used in trial Step 4
(ACME CEO web3 affidavit). Parents-as-Parties don't have v1.8
Signer authority, but they can attach wallet-signed acknowledgments
as authentication overlays.

**Actor role.**

| Role | v1.8 Part 1 | DID method | Wallet chain | Variable |
|---|---|---|---|---|
| Primary signer | **T1** Signer — Clerk (filing receipt) | did:key | — | `$CLERK` |
| Cosigner | **T3** Party (mother) | did:pkh:eip155:**8453** | **Base** | `$ANDERSON_MOTHER` |

(Father's acknowledgment is a separate entry with same shape, swap
`anderson-mother.key.json` → `anderson-father.key.json` and
binding_id accordingly.)

**Schema.** `schemas/evidence_artifact.go:75`
(`EvidenceArtifactPayload`).

**Submit mother's acknowledgment (Base wallet):**

```bash
cat > ack-mother.spec.json <<EOF
{
  "schema":      "evidence_artifact",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "clerk-brown.key.json",
  "cosigner_keys":      ["anderson-mother.key.json"],
  "payload": {
    "evidence_id":         "ack-anderson-mother-001",
    "evidence_type":       "acknowledgment",
    "classification":      "ordinary",
    "filed_by":            "$ANDERSON_MOTHER",
    "case_ref":            "2024-FAM-003",
    "description":         "Mother acknowledgment of family-case filing (Base wallet)",
    "content_digest":      "sha256:1a2b...",
    "artifact_encryption": "umbral_pre",
    "grant_authorization_mode": "open",
    "grant_entry_required":     true,
    "grant_requires_audit_entry": true,
    "chain_of_custody_required": false
  }
}
EOF
judicial-cli submit --endpoint $DAVIDSON --spec ack-mother.spec.json

# Same shape for father (Optimism wallet)
cat > ack-father.spec.json <<EOF
{
  "schema":      "evidence_artifact",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "clerk-brown.key.json",
  "cosigner_keys":      ["anderson-father.key.json"],
  "payload": {
    "evidence_id":         "ack-anderson-father-001",
    "evidence_type":       "acknowledgment",
    "classification":      "ordinary",
    "filed_by":            "$ANDERSON_FATHER",
    "case_ref":            "2024-FAM-003",
    "description":         "Father acknowledgment of family-case filing (Optimism wallet)",
    "content_digest":      "sha256:2b3c...",
    "artifact_encryption": "umbral_pre",
    "grant_authorization_mode": "open",
    "grant_entry_required":     true,
    "grant_requires_audit_entry": true,
    "chain_of_custody_required": false
  }
}
EOF
judicial-cli submit --endpoint $DAVIDSON --spec ack-father.spec.json
```

**Evidence — confirm both parental wallet chains are on-log:**

```bash
$ for SEQ in <N+1> <N+2>; do
    judicial-cli get --endpoint $DAVIDSON --seq $SEQ \
        | jq '.signatures[1] | {signer: .signer_did, algo: .algo_id, chain: (.signer_did | capture("eip155:(?<id>\\d+):").id)}'
done
{"signer":"did:pkh:eip155:8453:0x...","algo":3,"chain":"8453"}   # Base
{"signer":"did:pkh:eip155:10:0x...",  "algo":3,"chain":"10"}     # Optimism
```

Two parents, two distinct EVM chains, same family case. The
protocol's CAIP-10-native handling means adding a new chain costs
zero protocol changes — just enroll a wallet on that chain.

## Step 3 — Bind the minor under seal

**v1.8 citation.** §1 `party_binding` + §6
`sealing_unsealing_order` *structural seal at binding time.* v1.8
treats sealing as a §6 enforcement action; JN models the "sealed at
birth" pattern as a distinct schema
(`PartyBindingSealedPayload`) where the sealing is encoded
structurally in the schema choice rather than as a separate §6
entry.

**Critical sealing-authority pattern.** v1.8 §6 says
`sealing_unsealing_order` is an Adjudicator-signed Path C
enforcement action. JN's `party_binding_sealed` accordingly
**requires a judge cosignature**, not just the clerk's filing
authority.

**The minor has NO DID.** Per v1.8 Part 1 "Parties are Passive
Metadata Subjects" + JN's minor-protection policy, the child's
identity lives entirely in the payload (and behind the vendor's
re-encryption authority); they do not get a DID, web3 or
otherwise.

**Actor role.**

| Role | v1.8 Part 1 | DID method | Variable |
|---|---|---|---|
| Primary signer | **T1** Signer — Clerk | did:key | `$CLERK` |
| Cosigner | **T1** Signer — Adjudicator (Judge Lewis) | did:key | `$LEWIS` |

**Schema.** `schemas/party_binding_sealed.go:20`
(`PartyBindingSealedPayload`), `:61`
(`SerializePartyBindingSealedPayload`).

**Submit.**

```bash
cat > bind-minor-sealed.spec.json <<EOF
{
  "schema":      "party_binding_sealed",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "clerk-brown.key.json",
  "cosigner_keys":      ["judge-lewis.key.json"],
  "payload": {
    "vendor_did":               "did:web:state:tn:davidson:family-vendor",
    "binding_id":               "minor-anderson-001",
    "case_ref":                 "2024-FAM-003",
    "role":                     "minor_subject",
    "status":                   "active",
    "artifact_encryption":      "umbral_pre",
    "grant_authorization_mode": "sealed",
    "grant_entry_required":     true,
    "grant_requires_audit_entry": true,
    "encrypted_mapping_cid":    "bafy...placeholder-for-walkthrough"
  }
}
EOF
judicial-cli submit --endpoint $DAVIDSON --spec bind-minor-sealed.spec.json
```

**Note who cosigns:** Judge Lewis, *not* an attorney or party.
Sealing requires v1.8 §Part 1 Adjudicator authority. Tennessee code
§36-1-125 governs juvenile records access; the schema's structural
shape encodes the §6 sealing semantics.

**Evidence (a) — confirm the binding is queryable AND the sealing
signal surfaces:**

```bash
$ curl -fsS "$NETWORK_API/v1/judicial/parties/bindings/by-id/minor-anderson-001" \
    -H "X-Caller-DID: $CLERK" \
    -H "X-Cases-Log-DID: did:web:state:tn:davidson" \
    | jq '{id: .binding_id, role, case: .case_ref, sealed, encryption: .artifact_encryption}'
{
  "id":         "minor-anderson-001",
  "role":       "minor_subject",
  "case":       "2024-FAM-003",
  "sealed":     true,
  "encryption": "umbral_pre"
}
```

`sealed: true` — JN's read API recognizes the sealed-binding schema
and surfaces the sealing signal. The endpoint does NOT return the
encrypted mapping CID's plaintext — that lives behind the vendor's
re-encryption authority per §36-1-125.

**Evidence (b) — confirm the chain-of-authority survived
round-trip:**

```bash
$ judicial-cli get --endpoint $DAVIDSON --seq <N+3> \
    | jq '{primary: .header.signer_did, all_signers: [.signatures[].signer_did], payload_sealed: (.payload.grant_authorization_mode == "sealed")}'
{
  "primary":        "did:key:zQ3sh...CLERK",
  "all_signers":    ["did:key:zQ3sh...CLERK", "did:key:zQ3sh...LEWIS"],
  "payload_sealed": true
}
```

What we proved (per v1.8): clerk primary (case-structuring action),
judge cosigner (v1.8 §6 sealing authority),
`grant_authorization_mode=sealed`. The walkthrough never decrypts
anything; the ledger never decrypts anything. The structural
declaration plus cosigner-identity check IS the audit trail.

**Code anchor.** `api/judicial/parties.go::partyBindingFindHandler`.

## Step 4 — Counsel appearance

**v1.8 citation.** §1 `counsel_appearance` — *Attorney goes on
record as representing one or more parties. Mints a case-local
`appearance_id`. Payload carries `attorney_did` and a `represents`
list of `binding_id` values.*

**Actor role.**

| Role | v1.8 Part 1 | DID method | Variable |
|---|---|---|---|
| Primary signer | **T2** Filer — Civil Attorney (Murphy) | did:key | `$MURPHY` |
| Cosigner | **T1** Signer — Clerk | did:key | `$CLERK` |

**Schema.** `schemas/counsel_appearance.go:51`
(`CounselAppearancePayload`), `:156`
(`SerializeCounselAppearancePayload`).

**Submit.**

```bash
cat > appearance-murphy.spec.json <<EOF
{
  "schema":      "counsel_appearance",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "atty-murphy.key.json",
  "cosigner_keys":      ["clerk-brown.key.json"],
  "payload": {
    "appearance_id": "ap-murphy-001",
    "attorney_did":  "$MURPHY",
    "represents":    ["minor-anderson-001"],
    "case_ref":      "2024-FAM-003",
    "filed_date":    "2024-05-12",
    "status":        "active"
  }
}
EOF
judicial-cli submit --endpoint $DAVIDSON --spec appearance-murphy.spec.json
```

`represents` references the sealed binding by its public ID — even
though the underlying identity is sealed, the case-local
`binding_id` is the v1.8-mandated public reference.

**Evidence — confirm the case's binding list surfaces the right
parties:**

```bash
$ curl -fsS "$NETWORK_API/v1/judicial/parties/bindings?case_ref=2024-FAM-003" \
    -H "X-Caller-DID: $CLERK" \
    -H "X-Cases-Log-DID: did:web:state:tn:davidson" \
    | jq '{count: (.bindings | length), ids: [.bindings[].binding_id], sealed_ids: [.bindings[] | select(.sealed == true) | .binding_id]}'
{
  "count":      1,
  "ids":        ["minor-anderson-001"],
  "sealed_ids": ["minor-anderson-001"]
}
```

Only the minor is bound. The parents acknowledge from their wallets
(Step 2) but don't get `binding_id`s — they're Parties per v1.8 and
their wallet attestations live as separate `evidence_artifact`
entries, not party bindings.

## Step 5 — Initial judicial delegation

**v1.8 citation.** §13 *Administrative Events* — Network-level
role catalog + delegation graph. JN models this as the
`judicial_delegation` schema.

**Legally.** Tennessee family-court rules require a recorded
assignment from the Chief Judge's office naming the specific judge
hearing a custody case. The chief issues a delegation — a
time-bounded grant of authority — naming the judge for this docket.
We narrate Lewis self-binding because we don't have a CJ DID in
this 4-actor cast; production would have `did:key:zQ3sh-CJ-...` as
`granter_did`.

**Actor role.**

| Role | v1.8 Part 1 | DID method | Variable |
|---|---|---|---|
| Primary signer | **T1** Signer — Adjudicator (Judge Lewis) | did:key | `$LEWIS` |
| Cosigner | **T1** Signer — Clerk | did:key | `$CLERK` |

**Schema.** `schemas/judicial_delegation.go:79`
(`JudicialDelegationPayload`).

**Submit.**

```bash
cat > delegation-lewis.spec.json <<EOF
{
  "schema":      "judicial_delegation",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "judge-lewis.key.json",
  "cosigner_keys":      ["clerk-brown.key.json"],
  "payload": {
    "schema_id":   "judicial-delegation-v1",
    "granter_did": "$LEWIS",
    "grantee_did": "$LEWIS",
    "role":        "judge",
    "scope":       ["2024-FAM-003"],
    "issued_at":   "2024-05-13T09:00:00Z",
    "expires_at":  "2025-05-13T09:00:00Z",
    "rationale":   "Family-division assignment for 2024-FAM-003"
  }
}
EOF
judicial-cli submit --endpoint $DAVIDSON --spec delegation-lewis.spec.json
```

**Record `S_DELEG`** — the sequence number where this entry lands.
Act II's succession entry cites it.

**Evidence — confirm the delegation is queryable via the ledger's
delegate_did index:**

```bash
$ curl -fsS "$DAVIDSON/v1/query/delegate_did/$LEWIS" \
    | jq '.entries | length, [.[] | .sequence_number]'
1
[<S_DELEG>]
```

JN's `LedgerDelegationResolver` would walk this chain at read-time
policy evaluation; the index is live and correct.

**Code anchor.** Ledger's
`api/queries.go::NewQueryDelegateDIDHandler` (consumed by JN's
`verification/ledger_delegate_query.go::QueryByDelegateDID`).

## End-of-act state

```bash
$ curl -fsS $DAVIDSON/v1/tree/head | jq '.size'
# size before Case 2 + 5

$ curl -fsS "$NETWORK_API/v1/judicial/cases/2024-FAM-003" \
    -H "X-Caller-DID: $CLERK" \
    -H "X-Cases-Log-DID: did:web:state:tn:davidson" \
    | jq '{docket, status, sealed_parties: (.sealed_party_count // 0)}'
{"docket":"2024-FAM-003","status":"active","sealed_parties":1}
```

| In-case # | Schema | v1.8 § | Primary | Cosigner | Wallet chain |
|---|---|---|---|---|---|
| 1 | `family_case` | §1 case_initiation | Signer-Clerk | Filer-Attorney | — |
| 2 | `evidence_artifact` (ack) | §4 evidence_admittance | Signer-Clerk | ****T3** Party (mother)** | **Base (8453)** |
| 3 | `evidence_artifact` (ack) | §4 evidence_admittance | Signer-Clerk | ****T3** Party (father)** | **Optimism (10)** |
| 4 | `party_binding_sealed` | §1 + §6 sealing | Signer-Clerk | Signer-Adjudicator (Lewis) | — |
| 5 | `counsel_appearance` | §1 counsel_appearance | Filer-Attorney | Signer-Clerk | — |
| 6 | `judicial_delegation` | §13 admin | Signer-Adjudicator (Lewis) | Signer-Clerk | — |

## What just happened

You opened a family-court case with **two parental web3
acknowledgments on two distinct EVM chains** (Base + Optimism),
plus a sealed minor binding. Each parental wallet's signature is
on-log alongside the court-personnel `did:key` signatures, all
verifying through the same SDK dispatcher. The minor has no DID by
design (v1.8 Part 1 + minor-protection policy); their identity
lives behind the vendor's re-encryption authority.

Every step's evidence curl confirmed both the on-log entry AND the
JN domain API's projection of it. v1.8 §"Read-Side Separation" is
the structural promise; this walkthrough demonstrates it works
end-to-end across two EVM chains plus the institutional did:key
realm.

## Continue

Open **[02-anderson-succession.md](02-anderson-succession.md)** for
the juvenile referral, judicial succession, and revocation —
exercising v1.8 §13 administrative events at the delegation graph
level.
