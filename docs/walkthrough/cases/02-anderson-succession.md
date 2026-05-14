# Case 2, Act II · Juvenile referral, succession, revocation

Three entries on the Davidson log exercising v1.8 §13 Administrative
Events at the delegation-graph level. We open a companion juvenile
docket, transfer scoped authority for that docket from family Judge
Lewis to juvenile Magistrate Owens, and revoke the family-court
delegation when mediation fails.

Each step follows the canonical four-part pattern from
[01-acme-v-beta-trial.md](01-acme-v-beta-trial.md).

Pre-flight: Act I complete. You've recorded `S_DELEG` as the sequence
of the `judicial_delegation` entry from Act I Step 5.
`$NETWORK_API`, `$ANDERSON_MOTHER`, `$ANDERSON_FATHER` exported.

## Step 6 — File the juvenile companion case

**v1.8 citation.** §1 `case_initiation` (JUVENILE variant). Per
v1.8 §"Case Roots: Trial vs. Appellate", juvenile dockets are
distinct case roots even when factually related to a family-court
docket. Cross-docket correlation lives in the aggregator
microservice's index, not on the log itself.

**Auto-sealing.** v1.8 §6 sealing semantics apply at disposition
time for juvenile records (TN code §37-1-153). The schema's
`auto_seal_at_disposition: true` payload field declares that
intent structurally; the actual seal would be a separate v1.8 §6
`sealing_unsealing_order` triggered when the disposition lands.

**Actor role.**

| Role | v1.8 Part 1 | DID method | Variable |
|---|---|---|---|
| Primary signer | **T1** Signer — Clerk | did:key | `$CLERK` |
| Cosigner | **T1** Signer — Adjudicator (Judge Lewis, judge of record on parent family case) | did:key | `$LEWIS` |

**Schema.** `schemas/juvenile_case.go:39` (`JuvenileCasePayload`),
`:95` (`SerializeJuvenileCasePayload`).

**Submit.**

```bash
cat > juvenile-filing.spec.json <<EOF
{
  "schema":      "juvenile_case",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "clerk-brown.key.json",
  "cosigner_keys":      ["judge-lewis.key.json"],
  "payload": {
    "docket_number":            "2024-JUV-004",
    "case_type":                "dependency_inquiry",
    "filed_date":               "2024-08-15",
    "status":                   "active",
    "auto_seal_authority":      "TN-37-1-153",
    "auto_seal_at_disposition": true
  }
}
EOF
judicial-cli submit --endpoint $DAVIDSON --spec juvenile-filing.spec.json
```

**Evidence — confirm the juvenile case root exists with auto-seal
intent surfaced:**

```bash
$ curl -fsS "$NETWORK_API/v1/judicial/cases/2024-JUV-004" \
    -H "X-Caller-DID: $CLERK" \
    -H "X-Cases-Log-DID: did:web:state:tn:davidson" \
    | jq '{docket, status, type: .case_type, sealed: .is_sealed}'
{
  "docket": "2024-JUV-004",
  "status": "active",
  "type":   "dependency_inquiry",
  "sealed": false
}
```

`sealed: false` — the case is NOT yet sealed (v1.8 §6 sealing is
triggered by a discrete order event). The
`auto_seal_at_disposition` flag is visible in the raw payload:

```bash
$ judicial-cli get --endpoint $DAVIDSON --seq <N> \
    | jq '.payload | {docket: .docket_number, will_auto_seal: .auto_seal_at_disposition, authority: .auto_seal_authority}'
{"docket":"2024-JUV-004","will_auto_seal":true,"authority":"TN-37-1-153"}
```

**Code anchor.** `api/judicial/cases.go::caseLookupHandler`.

## Step 7 — Judicial succession

**v1.8 citation.** §13 *Administrative Events* — succession is a
delegation-graph operation: outgoing authority + incoming authority
+ scope narrowing.

**Legally — the delicate operation.** Lewis sits on the family case
(`2024-FAM-003`); Owens is the magistrate appointed for juvenile
dependency inquiries. The juvenile portion must move to Owens's
authority **without invalidating Lewis's prior orders on the family
case** and without giving Owens authority over the divorce/property
aspects (which stay with Lewis). The protocol's answer is a
**scoped succession** with `inheritance: "narrowed"` — Owens
succeeds Lewis only for docket `2024-JUV-004`.

**Actor role.**

| Role | v1.8 Part 1 | DID method | Variable |
|---|---|---|---|
| Primary signer | **T1** Signer — Adjudicator (outgoing, Lewis) | did:key | `$LEWIS` |
| Cosigner | **T1** Signer — Adjudicator (incoming, Owens) | did:key | `$OWENS` |

Both Adjudicator signatures are required: Lewis as outgoing
authority, Owens as incoming. v1.8 §13's authority-transfer
invariant — captured in JN by the dual-signature requirement on
`judicial_succession`.

**Schema.** `schemas/judicial_amendments.go:51`
(`JudicialSuccessionPayload`).

**Submit.**

```bash
cat > succession.spec.json <<EOF
{
  "schema":      "judicial_succession",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "judge-lewis.key.json",
  "cosigner_keys":      ["magistrate-owens.key.json"],
  "payload": {
    "schema_id":         "judicial-succession-v1",
    "target_delegation": {"log_did":"did:web:state:tn:davidson","sequence": <S_DELEG>},
    "successor_did":     "$OWENS",
    "reason":            "Allegations require juvenile-court oversight; transfer custody portion to magistrate Owens.",
    "inheritance":       "narrowed",
    "narrowed_scope":    ["2024-JUV-004"],
    "effective_at":      "2024-08-16T09:00:00Z"
  }
}
EOF
judicial-cli submit --endpoint $DAVIDSON --spec succession.spec.json
```

Substitute the actual `S_DELEG` value from Act I.

**Evidence (a) — confirm the succession lands with the
`target_delegation` cross-pointer intact:**

```bash
$ judicial-cli get --endpoint $DAVIDSON --seq <N> \
    | jq '.payload | {schema: .schema_id, target: .target_delegation, successor: .successor_did, inheritance, scope: .narrowed_scope}'
{
  "schema":      "judicial-succession-v1",
  "target":      {"log_did":"did:web:state:tn:davidson","sequence": <S_DELEG>},
  "successor":   "did:key:zQ3sh...OWENS",
  "inheritance": "narrowed",
  "scope":       ["2024-JUV-004"]
}
```

**Evidence (b) — confirm both Lewis's original AND Owens's new
authority are queryable via the ledger's delegate_did index (PR-K
of ledger main):**

```bash
$ curl -fsS "$DAVIDSON/v1/query/delegate_did/$LEWIS" | jq '.entries | length'
1
$ curl -fsS "$DAVIDSON/v1/query/delegate_did/$OWENS" | jq '.entries | length'
1
```

Both DIDs have on-log delegation entries. JN's
`LedgerDelegationResolver` (PR-2 of this session,
`verification/delegation_resolver_ledger.go`) walks this chain at
read-time policy evaluation:

```bash
$ JN_VERIFY_POLICY_STAGE_ENABLE=true \
    curl -fsS "$NETWORK_API/v1/verify/complete/did:web:state:tn:davidson/<N>" \
    | jq '{all_green, delegation_chain_walked: (.report.Policy.DelegationLookups // 0)}'
{"all_green":true,"delegation_chain_walked":2}
```

The walker traversed Lewis → Owens for the succession's authority
verification. v1.8 §13's "who held what authority when" invariant
becomes concretely auditable via this walker.

**Audit angle: parents can verify too.** The parental wallet
acknowledgments from Act I Step 2 (Base + Optimism) are
discoverable by any third party. A parent's lawyer querying the
ledger for `$ANDERSON_MOTHER` finds the on-log acknowledgment +
the case it acknowledges + the current judicial authority over
that case:

```bash
$ curl -fsS "$DAVIDSON/v1/query/signer_did/$ANDERSON_MOTHER" \
    | jq '[.entries[] | {seq: .sequence_number, hash: (.canonical_hash[0:16])}]'
[{"seq": <ack-seq>, "hash": "abc12345..."}]
```

A wallet-resident party can audit the case state from their own
wallet's perspective without consulting court infrastructure
beyond the public ledger.

**Code anchors.**

- `schemas/judicial_amendments.go:51` (succession payload)
- `verification/delegation_resolver_ledger.go::LedgerDelegationResolver`
  (PR-2 walker)
- Ledger `delegationresolver/ledger_source.go` (PR-J, the
  in-process source the walker consumes via HTTP)

## Step 8 — Mediation fails; revocation

**v1.8 citation.** §13 *Administrative Events* — revocation is an
in-network authority-graph mutation, not a structural fork.

**Actor role.**

| Role | v1.8 Part 1 | DID method | Variable |
|---|---|---|---|
| Primary signer | **T1** Signer — Adjudicator (Lewis, self-revoking) | did:key | `$LEWIS` |
| Cosigner | **T1** Signer — Clerk (filing receipt) | did:key | `$CLERK` |

**Schema.** `schemas/judicial_amendments.go:31`
(`JudicialRevocationPayload`).

**Submit.**

```bash
cat > revocation.spec.json <<EOF
{
  "schema":      "judicial_revocation",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "judge-lewis.key.json",
  "cosigner_keys":      ["clerk-brown.key.json"],
  "payload": {
    "schema_id":         "judicial-revocation-v1",
    "target_delegation": {"log_did":"did:web:state:tn:davidson","sequence": <S_DELEG>},
    "reason":            "Mediation impasse declared 2024-09-25; case proceeds to litigated custody.",
    "revoked_at":        "2024-09-25T15:00:00Z"
  }
}
EOF
judicial-cli submit --endpoint $DAVIDSON --spec revocation.spec.json
```

**Evidence (a) — confirm the revocation entry lands with the right
target:**

```bash
$ judicial-cli get --endpoint $DAVIDSON --seq <N> \
    | jq '.payload | {schema: .schema_id, target: .target_delegation, reason, revoked_at}'
{
  "schema":     "judicial-revocation-v1",
  "target":     {"log_did":"did:web:state:tn:davidson","sequence": <S_DELEG>},
  "reason":     "Mediation impasse declared 2024-09-25; case proceeds to litigated custody.",
  "revoked_at": "2024-09-25T15:00:00Z"
}
```

**Evidence (b) — confirm the delegation chain reflects revocation
semantics:**

```bash
$ curl -fsS "$DAVIDSON/v1/query/delegate_did/$LEWIS" \
    | jq '.entries | length'
```

The query returns the LIVE entries for Lewis. After revocation
lands, JN's `LedgerDelegationResolver.ResolveChain($LEWIS)` walks
this list and applies the revocation: subsequent admission entries
that rely on Lewis's delegation as their authority basis are
rejected at v1.8 §13's authority-resolution layer.

Forward-looking, not retroactive: Lewis's prior orders on the case
remain valid because they were issued under an active delegation
at their submission time.

**Code anchors.**

- `verification/delegation_resolver_ledger.go::ResolveChain` (the
  read-side walker; cache invalidation via `InvalidateDID`)
- Ledger `delegationresolver/invalidation.go` (in-process
  invalidator)

## End state — full case

```bash
$ curl -fsS $DAVIDSON/v1/tree/head | jq '.size'
# Davidson tip = (size before Case 2) + 8

$ curl -fsS "$NETWORK_API/v1/judicial/cases/2024-JUV-004" \
    -H "X-Caller-DID: $CLERK" \
    -H "X-Cases-Log-DID: did:web:state:tn:davidson" \
    | jq '{docket, status, sealed: .is_sealed}'
{"docket":"2024-JUV-004","status":"active","sealed":false}
```

| In-case # | Schema | v1.8 § | Primary | Cosigner | Wallet chain |
|---|---|---|---|---|---|
| 1 | `family_case` | §1 case_initiation | Signer-Clerk | Filer-Attorney | — |
| 2 | `evidence_artifact` (mother ack) | §4 | Signer-Clerk | Party-mother | **Base (8453)** |
| 3 | `evidence_artifact` (father ack) | §4 | Signer-Clerk | Party-father | **Optimism (10)** |
| 4 | `party_binding_sealed` | §1 + §6 sealing | Signer-Clerk | Signer-Adjudicator (Lewis) | — |
| 5 | `counsel_appearance` | §1 | Filer-Attorney | Signer-Clerk | — |
| 6 | `judicial_delegation` | §13 admin | Signer-Adjudicator (Lewis) | Signer-Clerk | — |
| 7 | `juvenile_case` | §1 case_initiation | Signer-Clerk | Signer-Adjudicator (Lewis) | — |
| 8 | `judicial_succession` | §13 admin | Signer-Adjudicator (Lewis) | Signer-Adjudicator (Owens) | — |
| 9 | `judicial_revocation` | §13 admin | Signer-Adjudicator (Lewis) | Signer-Clerk | — |

## What just happened, step back

You moved authority structure across two divisions of the same
court, with each transition recorded as an immutable, multi-signed
entry on a Merkle log and PROVED via evidence curls against both
the ledger's delegation index AND JN's domain API:

1. **A child's identity is on the log but sealed** (Act I Step 3).
   Sealing authority encoded in the cosigner identity (judge, not
   attorney). *Evidence: `parties/bindings/by-id` returns
   `sealed: true`.*

2. **Parental web3 acknowledgments** (Act I Step 2). Mother on Base,
   father on Optimism, both verifying through the same ledger.
   *Evidence: `judicial-cli get` shows two different
   `eip155:<chainId>` DIDs in the signatures.*

3. **A scoped succession** (Act II Step 7) moved authority for one
   docket to a magistrate while leaving authority for a sibling
   docket intact. *Evidence: `delegate_did` returns Lewis's AND
   Owens's delegations; the LedgerDelegationResolver walks both.*

4. **A revocation** (Act II Step 8) closed a delegation slot.
   *Evidence: `delegate_did` after revocation; future entries
   citing the closed delegation fail at the resolver.*

These are the operations courts most often get wrong on paper. On
the log, they're typed, multi-signed, evidence-queryable end to
end — and witnessable from parties' own wallets across four
distinct EVM chains.

## Walkthrough complete

You've run two real Tennessee judicial cases against a real
two-ledger topology, with five real DIDs you minted yourself —
**plus four party-principal wallets across four EVM chains**
(Ethereum mainnet, Polygon, Base, Optimism). Every event landed
on-log. Every event was independently verified through JN's domain
API. The cross-network reference in Case 1 demonstrated v1.8
federation invariants; Case 2 demonstrated v1.8 §6 sealing + §13
delegation-graph operations + multi-chain party attestation.

Final stop: **[../99-coverage.md](../99-coverage.md)** for the
schema-coverage matrix and natural v1.8 extensions.
