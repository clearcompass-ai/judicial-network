# Case 1, Act I · Trial in Davidson Chancery

Five domain-meaningful entries on the Davidson log, each demonstrating
a distinct **Event Dictionary v1.8** event, signed by a distinct
**v1.8 Part 1 role**, and **provable via a JN domain-API curl** after
the fact. By the end of this file `curl -fsS $DAVIDSON/v1/tree/head |
jq '.size'` returns `6` (5 trial entries + 1 evidence artifact) and
every entry has been independently confirmed against its intended
v1.8 semantics.

Pre-flight: §01 + §02 done. `$CLERK`, `$COOPER`, `$DAVIS`, `$ADAMS`,
`$ACME_CEO` are exported. `$DAVIDSON=http://localhost:8080` and
`$NETWORK_API=http://localhost:8082` are exported. You're in
`~/attesta/keys`.

## Evidence pattern

Every step has **four parts** — read them in order:

1. **v1.8 citation** — the event-dictionary section that governs this
   event. Every event in this walkthrough resolves to a v1.8 entry;
   if the dictionary moves, the walkthrough moves with it.
2. **Actor role** — who acts, identified by v1.8 Part 1 role
   (Signer / Filer / Party). The Authority Summary table in v1.8
   pins which roles can sign which events.
3. **Submit** — the `judicial-cli submit` spec + command. The CLI
   itself is schema-agnostic; the spec carries the typed payload.
4. **Evidence** — a curl against JN's domain API
   (`$NETWORK_API`) that proves the event landed AND serves its
   v1.8-declared purpose. Each evidence curl uses an existing
   endpoint in `api/judicial/*.go`; the API contract is pinned by
   `api/judicial/cases_test.go` and adjacent test files.

If an evidence step fails, the on-log entry exists but JN's domain
API hasn't caught up — a real bug, not a documentation gap. Surface
it.

## Step 1 — File the civil case

**v1.8 citation.** §1 `case_initiation` — *Origin event. Foundational
entry that creates the case root.* This is a CIVIL variant in v1.8's
sense (Tennessee Rules of Civil Procedure; T.C.A. §27 controls).

**Actor role.**

| Role on this entry | v1.8 Part 1 | DID method | Variable |
|---|---|---|---|
| Primary signer | **T1** Signer — Clerk | did:key | `$CLERK` |
| Cosigner | **T2** Filer — Civil Attorney | did:key | `$COOPER` |

Per v1.8 §"Filer cosignature requirement", `cooper` cannot sign
directly — every entry submitted *by* a Filer requires a Signer's
ingest cosignature. Here Cooper cosigns the Clerk's filing entry,
which is the inverse pattern (Signer-led + Filer-attested) used for
case initiation.

**Schema.** `schemas/civil_case.go:32` (`CivilCasePayload`), `:87`
(`SerializeCivilCasePayload`).

**Submit.**

```bash
cd ~/attesta/keys
cat > civil-filing.spec.json <<EOF
{
  "schema":      "civil_case",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "clerk-brown.key.json",
  "cosigner_keys":      ["cooper.key.json"],
  "payload": {
    "docket_number": "2024-CV-001",
    "case_type":     "contract",
    "filed_date":    "2024-01-15",
    "status":        "active",
    "plaintiff":     "ACME Industries, Inc.",
    "defendant":     "Beta Corp LLC",
    "claim_amount":  "1200000.00"
  }
}
EOF

$ judicial-cli submit --endpoint $DAVIDSON --spec civil-filing.spec.json
canonical_hash=4b8c1d8e3f7a9b2c5e6d4f8a1b3c9d2e5f7a8b1c4d6e9f0a3b5c7d8e1f2a4b6c
status=accepted (HTTP 202)
sct={"version":1,"signer_did":"did:key:zQ3sh-LEDGER-DAVIDSON",...}

$ judicial-cli wait --endpoint $DAVIDSON \
    --hash 4b8c1d8e3f7a9b2c5e6d4f8a1b3c9d2e5f7a8b1c4d6e9f0a3b5c7d8e1f2a4b6c
state=sequenced sequence=1
```

**Evidence.** Confirm the case root materialized AND JN's domain API
indexed the docket number to the on-log sequence:

```bash
$ curl -fsS $NETWORK_API/v1/judicial/cases/2024-CV-001 \
    -H "X-Caller-DID: $CLERK" \
    -H "X-Cases-Log-DID: did:web:state:tn:davidson" \
    | jq '{docket: .docket_number, status, sealed: .is_sealed, revoked: .is_revoked, root_seq: .case_root_pos.sequence, type: .case_type}'
{
  "docket":  "2024-CV-001",
  "status":  "active",
  "sealed":  false,
  "revoked": false,
  "root_seq": 1,
  "type":    "contract"
}
```

What we proved (per v1.8):

- `status=active` — the case-root state machine is in the v1.8 §1
  starting state. Dependent events (party_binding, counsel_appearance)
  can now reference this root.
- `sealed=false` — no v1.8 §6 `sealing_unsealing_order` applies; the
  record is public per Tennessee civil-court default.
- `root_seq=1` — JN's read-side resolved the docket to the on-log
  sequence number. The aggregator microservice's docket → case-root
  index works.

**Code anchor for the evidence endpoint.**
`api/judicial/cases.go:90` (`caseLookupHandler`) →
`cases/docket_query.go:LookupDocket` → returns `DocketQueryResult`
including the four fields above.

## Step 2 — Bind the parties

**v1.8 citation.** §1 `party_binding` — *Adds a Plaintiff, Defendant,
Respondent, or the State to the case. Mints a case-local
`binding_id` as the only public reference.* Per v1.8 Part 1
"Parties", parties have no DIDs; the `binding_id` is the public
identifier.

**Requires (Hard).** Prior `case_initiation` on this case root —
satisfied by Step 1.

**Actor role per binding.**

| Binding | Primary signer | Cosigner |
|---|---|---|
| Plaintiff (ACME) | **T1** Signer — Clerk | **T2** Filer — Civil Attorney (Cooper) |
| Defendant (Beta) | **T1** Signer — Clerk | **T2** Filer — Civil Attorney (Davis) |

Both bindings are clerk-signed because v1.8 §1 case structuring is a
Clerk function. Each side's attorney cosigns the binding of their
own client — operational discipline, not a v1.8 requirement.

**Schema.** `schemas/party_binding.go:69` (`PartyBindingPayload`),
`:153` (`SerializePartyBindingPayload`).

**Submit (plaintiff):**

```bash
cat > bind-plaintiff.spec.json <<EOF
{
  "schema":      "party_binding",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "clerk-brown.key.json",
  "cosigner_keys":      ["cooper.key.json"],
  "payload": {
    "binding_id":  "bind-acme-001",
    "party_class": "plaintiff",
    "party_name":  "ACME Industries, Inc.",
    "case_ref":    "2024-CV-001",
    "case_seq":    1
  }
}
EOF
judicial-cli submit --endpoint $DAVIDSON --spec bind-plaintiff.spec.json
```

**Submit (defendant):** swap `cooper.key.json` → `davis.key.json`,
`bind-acme-001` → `bind-beta-001`, `plaintiff` → `defendant`, party
name to `"Beta Corp LLC"`. Sequences 2 and 3.

**Evidence — confirm both bindings are queryable by their case-local
`binding_id`:**

```bash
$ for B in bind-acme-001 bind-beta-001; do
    curl -fsS "$NETWORK_API/v1/judicial/parties/bindings/by-id/$B" \
        -H "X-Caller-DID: $CLERK" \
        -H "X-Cases-Log-DID: did:web:state:tn:davidson" \
        | jq -c '{id: .binding_id, class: .party_class, case: .case_ref, sealed}'
done
{"id":"bind-acme-001","class":"plaintiff","case":"2024-CV-001","sealed":false}
{"id":"bind-beta-001","class":"defendant","case":"2024-CV-001","sealed":false}
```

What we proved:

- The case-local `binding_id` resolves to a structured party record
  via JN's domain index. v1.8's "the `binding_id` is the only public
  reference" is enforced at the read side: this endpoint NEVER
  surfaces a raw party DID (there isn't one to surface — v1.8 Part 1
  is explicit that parties have no DIDs).
- `sealed=false` — public case, plain party records. Compare to
  `bind-anderson-minor-001` in Case 2, which surfaces a sealing
  signal.

**Code anchor.** `api/judicial/parties.go::partyBindingFindHandler`.

## Step 3 — Counsel appearances

**v1.8 citation.** §1 `counsel_appearance` — *Attorney goes on record
as representing one or more parties. Mints a case-local
`appearance_id`. Payload carries `attorney_did` and a `represents`
list of `binding_id` values.*

**Requires (Hard).** Prior `case_initiation` on this case root.
**Requires (Advisory).** Prior `party_binding` for each `binding_id`
in `represents`. The validator should accept and the aggregator flags
any missing — v1.8 §"prerequisite validation policy" — but our
flow has both bindings already on the log, so no advisory fires.

**Critical authority change.** The primary signer is **the attorney
themselves**, NOT the Clerk. v1.8 Part 1 explicitly notes that Filers
"do not hold network keys"; this means Cooper's DID must be a *did:key*
he controls (not a Filer-pattern DID without keys). The walkthrough
adopts the convention that `did:key` attorneys hold network keys, and
the Clerk's cosignature is the "Filer cosignature requirement" pattern
inverted: when an attorney IS the signer (because she holds her own
key for this network), the Clerk attests receipt.

**Schema.** `schemas/counsel_appearance.go:51`
(`CounselAppearancePayload`), `:156`
(`SerializeCounselAppearancePayload`).

**Submit (Cooper):**

```bash
cat > appearance-cooper.spec.json <<EOF
{
  "schema":      "counsel_appearance",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "cooper.key.json",
  "cosigner_keys":      ["clerk-brown.key.json"],
  "payload": {
    "appearance_id": "ap-cooper-001",
    "attorney_did":  "$COOPER",
    "represents":    ["bind-acme-001"],
    "case_ref":      "2024-CV-001",
    "case_seq":      1,
    "filed_date":    "2024-01-16",
    "status":        "active"
  }
}
EOF
judicial-cli submit --endpoint $DAVIDSON --spec appearance-cooper.spec.json
```

**Submit (Davis):** swap keys + binding + ids (same shape).

Sequences 4 and 5.

**Evidence — confirm both appearances are visible AND linked back to
the right bindings:**

```bash
$ curl -fsS "$NETWORK_API/v1/judicial/parties/bindings?case_ref=2024-CV-001" \
    -H "X-Caller-DID: $CLERK" \
    -H "X-Cases-Log-DID: did:web:state:tn:davidson" \
    | jq '.bindings | length, [.[] | .binding_id]'
2
["bind-acme-001","bind-beta-001"]
```

(The two appearances are sequenced; the case-binding list is the
authoritative index of who's in the case. Per-attorney
`counsel_appearance` lookup is a future endpoint — flagged in v1.8
§"Read-Side Separation" as aggregator concern.)

**Code anchor.** `api/judicial/parties.go::partyBindingListHandler`.

## Step 4 — Evidence artifact signed from a wallet

**v1.8 citation.** §4 `evidence_admittance` — *Formal acceptance of a
physical or digital artifact into the trial record. Provenance flows
through the prosecutor's chain of custody before Clerk hashing.*

JN's `evidence_artifact` schema is the civil-case analogue (no
prosecutor; the filing party's attorney delivers the artifact, the
Clerk hashes it, the originating party may cosign as a separate
attestation to the artifact's authenticity).

**Actor role.**

| Role | v1.8 Part 1 | DID method | Variable |
|---|---|---|---|
| Primary signer | **T1** Signer — Clerk | did:key | `$CLERK` |
| Cosigner | **T3** Party (wallet-holding plaintiff principal) | did:pkh:eip155 | `$ACME_CEO` |

The web3 moment: ACME's CEO signs from his Ethereum wallet using
EIP-191 personal_sign. The protocol accepts two distinct signature
algorithms on the same entry; both verify through the SDK's per-method
DID dispatcher with no special-case handling.

**Note on v1.8 Part 1 classification.** A party-principal who signs
from a wallet is unusual in v1.8's Authority Summary — Parties are
"Passive Metadata Subjects" without DIDs. This walkthrough demonstrates
the *adoption pattern* whereby a party voluntarily binds their
wallet DID to an evidence artifact as an authentication signal
(not as a v1.8 Signer key). The Clerk's primary signature is the
operative authority; the CEO's cosignature is the corporate
attestation overlay.

**Schema.** `schemas/evidence_artifact.go:75` (`EvidenceArtifactPayload`),
`:141` (`SerializeEvidencePayload`).

**Submit.**

```bash
cat > affidavit-acme-ceo.spec.json <<EOF
{
  "schema":      "evidence_artifact",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "clerk-brown.key.json",
  "cosigner_keys":      ["acme-ceo.key.json"],
  "payload": {
    "evidence_id":               "ex-acme-affidavit-001",
    "evidence_type":             "affidavit",
    "classification":            "ordinary",
    "filed_by":                  "$ACME_CEO",
    "case_ref":                  "2024-CV-001",
    "description":               "CEO affidavit re: contract formation, dated 2024-01-22",
    "content_digest":            "sha256:9b1c4e7d...",
    "artifact_encryption":       "umbral_pre",
    "grant_authorization_mode":  "open",
    "grant_entry_required":      true,
    "grant_requires_audit_entry": true,
    "chain_of_custody_required": true
  }
}
EOF
judicial-cli submit --endpoint $DAVIDSON --spec affidavit-acme-ceo.spec.json
```

Sequence 6.

**Evidence (a) — two signature algorithms on one entry, both
verified through the SDK dispatcher:**

```bash
$ judicial-cli get --endpoint $DAVIDSON --seq 6 \
    | jq '.signatures[] | {signer: .signer_did, algo: .algo_id, sig_len: (.bytes | length / 2)}'
{"signer": "did:key:zQ3sh...CLERK",          "algo": 1, "sig_len": 64}
{"signer": "did:pkh:eip155:1:0x7ad817...",   "algo": 3, "sig_len": 65}
```

`algo: 1` = `SigAlgoECDSA` (secp256k1, 64 bytes R||S). `algo: 3` =
`SigAlgoEIP191` (65 bytes r||s||v). The single ledger admits both.

**Evidence (b) — confirm the payload survived the round-trip with
the chain-of-custody invariants intact:**

```bash
$ judicial-cli get --endpoint $DAVIDSON --seq 6 \
    | jq '.payload | {evidence: .evidence_id, classification, chain_required: .chain_of_custody_required, filed_by, grant_mode: .grant_authorization_mode}'
{
  "evidence":       "ex-acme-affidavit-001",
  "classification": "ordinary",
  "chain_required": true,
  "filed_by":       "did:pkh:eip155:1:0x7ad817...",
  "grant_mode":     "open"
}
```

What we proved:

- The payload deserializes cleanly — every field set in the spec
  round-trips through the SDK's canonical envelope.
- `chain_required=true` — v1.8 §4 chain-of-custody invariant is
  structurally declared on the artifact. Subsequent v1.8 §4
  `access_grant` entries can compose against this artifact.
- `filed_by` carries the web3 wallet DID — proving the EIP-191
  signature path bound the artifact to a specific Ethereum identity
  end-to-end.

For a forensic custody-chain audit (multiple `access_grant` hops),
use `GET /v1/judicial/verification/custody-chain?artifact_cid=…&log_did=…`
(takes the artifact CID + log DID rather than the case-local
`evidence_id`; see `api/judicial/verification.go::verifyCustodyChainHandler`).

**Code anchor.** `api/judicial/verification.go::verifyCustodyChainHandler`
+ ledger's `GET /v1/entries/{seq}` (driven by `judicial-cli get`).

## Step 5 — Read-time policy stage (PR-2 demonstration)

**v1.8 citation.** None — this is a *protocol-level* verification,
not a domain event. Demonstrates that attesta v1.5.0's
`AdmissionEnforced` declaration + v1.4.0's `VerifyComplete` Stage 6
work end-to-end against JN entries.

**Actor role.** No actor; this is a read-side audit by anyone with
network access — exactly the v1.8 §"Read-Side Separation" pattern.

**What this exercises.** Every JN schema declares its
`AttestationPolicies` with `AdmissionEnforced=false` (see
`schemas/attestation_policies.go::policy()`). At admission, the
ledger's `LedgerPolicyResolver` correctly skips Stage 6. At read
time, JN's verifier (with the feature flag on) runs Stage 6 against
any cosignatures that have arrived since the entry landed.

For the trial entries above (steps 1-4), the schemas don't declare
any policies that the spec adopts via `AttestationPolicyName`, so
Stage 6 short-circuits cleanly to "no policy adopted" — confirming
the resolver's three-branch contract (skip / reject / enforce).

**Submit-side: none.** Step 4 already landed entry seq=6.

**Evidence — run Stage 6 with the flag on:**

```bash
$ JN_VERIFY_POLICY_STAGE_ENABLE=true ./bin/network-api &
$ sleep 1

$ curl -fsS "$NETWORK_API/v1/verify/complete/did:web:state:tn:davidson/1" \
    | jq '{all_green, signatures_ok: .report.Signatures.AllVerified, policy_present: (.report.Policy != null), policy_skipped: (.report.Policy == null)}'
{
  "all_green": true,
  "signatures_ok": true,
  "policy_present": false,
  "policy_skipped": true
}
```

What we proved:

- `all_green: true` — every other SDK stage (Signatures + Authority +
  Origin) passed.
- `policy_skipped: true` — the entry adopts no policy
  (`Header.AttestationPolicyName == nil`); Stage 6 cleanly skipped.
  This is the load-bearing invariant from PR-2 (see
  `verification/policy_stage.go::BuildPolicyStageParams`, returns
  `(nil, nil)` on the no-policy short-circuit).

**Code anchor.** `api/verification/handlers/verify_complete.go` (the
handler) + `verification/policy_stage.go` (the orchestrator).

## Step 6 — Layer 3 witness tree-head cosignatures (external transparency)

**v1.8 citation.** Not a domain event — this is the attesta v1.5.1
external-transparency mechanism. v1.8 §"About This Document" promises:
*"integrity is verifiable by anyone with access to the log."* That
guarantee is concretely backed by **witness tree-head cosignatures**,
which are signed by independent operators over the whole Merkle root
— not over individual entries.

**Signature-layer clarification.** Steps 1–5 exercised Layer 1
(per-entry signatures in `entry.Signatures[]`) and Layer 2 (payload
metadata like `attorney_did`, `filed_by`). Step 6 closes the loop
with Layer 3 (witness tree-head cosignatures). See
[../02-real-dids.md §"Three signature layers"](../02-real-dids.md)
for the v1.8 + attesta v1.5.1 grounding of this distinction.

**Actor role.** No case actor; the witnesses are the network's
external operators, configured at ledger boot via
`LEDGER_GENESIS_WITNESS_SET`. They are NOT v1.8 Part 1 Signers
(those are exchange-scoped key holders); witnesses are network-level
transparency operators in the CT-log-monitor pattern.

**Evidence — confirm the tree head at size=6 carries witness
quorum cosignatures:**

```bash
$ curl -fsS $DAVIDSON/v1/tree/head | jq '{
    size,
    root_hash: (.root_hash[0:16] + "..."),
    witnesses: [.cosignatures[] | {did: .signer_did, alg: .algo_id}],
    quorum_met: ((.cosignatures | length) >= 2)
}'
{
  "size":       6,
  "root_hash":  "e2c4abcd123456...",
  "witnesses": [
    {"did": "did:web:tn:witness-a", "alg": 1},
    {"did": "did:web:tn:witness-b", "alg": 1}
  ],
  "quorum_met": true
}
```

What we proved:

- The Davidson tree head at size=6 carries ≥K independent witness
  signatures (K=2 default; configurable via
  `LEDGER_WITNESS_QUORUM_K`).
- A forked or tampered log would produce a different `root_hash`;
  any witness comparing the head it previously cosigned with the
  head this ledger now publishes would catch the divergence and
  refuse to re-cosign. **External transparency is concretely
  backed**, not just claimed.
- The witness cosignatures are over the WHOLE log, not per-entry —
  this is the v1.8 §"Read-Side Separation" / attesta v1.5.1 Layer 3
  mechanism, NOT the v1.8 Part 1 "Filer cosignature" pattern (which
  is per-entry in `Signatures[]`).

**Code anchors.**

- Ledger `api/tree.go::NewTreeHeadHandler` — publishes the
  cosigned tree head.
- Ledger `cmd/ledger/boot/wire/wire.go::wireWitnessCosigner` —
  wires the HeadSync goroutine that collects witness signatures.
- attesta `crypto/cosign/WitnessKeySet` — declares the witness set
  + quorum-K + BLS aggregate verifier.

## End-of-act state

```bash
$ curl -fsS $DAVIDSON/v1/tree/head | jq '.size, .root_hash, (.cosignatures | length)'
6
"e2c4..."
2

$ curl -fsS "$NETWORK_API/v1/judicial/cases/2024-CV-001" \
    -H "X-Caller-DID: $CLERK" \
    -H "X-Cases-Log-DID: did:web:state:tn:davidson" \
    | jq '{docket, status, root_seq: .case_root_pos.sequence, origin_state: .origin_state}'
{"docket":"2024-CV-001","status":"active","root_seq":1,"origin_state":"active"}
```

All three signature layers green:

| Layer | Evidence at end of act |
|---|---|
| **L1** entry signatures | All 6 entries carry T1 Signer signatures (Clerk on civil_case, bindings; attorneys + Clerk on counsel_appearance per JN extension; Clerk + Party-wallet on evidence_artifact) |
| **L2** payload attestations | `attorney_did`, `filed_by`, `binding_id`, `attestation_policy_name` fields populated and queryable via JN's domain API |
| **L3** witness cosigs | tree_head.cosignatures ≥ K=2 witness operators |

`origin_state: active` — v1.8 §1 says the case-root state machine is
"active" after `case_initiation` and stays there until a Terminal
Event (`dismissal`, `final_judgment` + post-trial, `expungement`).
We're nowhere near that; the appeal in Act II only proceeds *after*
a `final_judgment` (which we elide for narrative brevity per the
overview file's §"What's NOT in this case").

## What just happened, in one breath

Five v1.8 events landed: one `case_initiation` (CIVIL variant), two
`party_binding` (Plaintiff + Defendant), two `counsel_appearance`,
plus one `evidence_admittance` (web3 cosignature path). Each one was
signed by the right v1.8 Part 1 role (Clerk-led for case structuring;
attorney-led for counsel_appearance); each one was confirmed via JN's
domain API to have landed AND to serve its v1.8-declared purpose;
the read-side `VerifyComplete` Stage 6 cleanly skips for entries
that adopt no policy. The ledger never inspected the domain
payload — it sequenced canonical bytes whose interior happens to be
JSON about Tennessee civil procedure. The JN domain API DID inspect,
index, and surface those payloads — that's the clean separation
between protocol layer and domain layer.

## Continue

Open **[01-acme-v-beta-appeal.md](01-acme-v-beta-appeal.md)** for the
cross-exchange appeal — the COA disposition carries an
`EvidencePointers` reference back to Davidson:1, demonstrating v1.8
§7B.3 + §8 `remand_affirmance` cross-network composition.
