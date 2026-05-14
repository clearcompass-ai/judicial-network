# Case 2, Act II · Juvenile referral, succession, revocation

Three entries on the Davidson log. We open a companion juvenile
docket, transfer scoped authority for that docket from family
Judge Lewis to juvenile Magistrate Owens, and revoke the family-
court delegation when mediation fails.

Pre-flight: Act I complete. You've recorded `S_DELEG` as the sequence
number of the `judicial_delegation` entry from Act I Step 4.

## Step 5 — File the juvenile companion case (`JuvenileCasePayload`)

**Legally.** Three months into the case, allegations surface that
require juvenile-court oversight (e.g., dependency, neglect, or
related). Davidson opens a companion juvenile docket — same physical
court system, different division with its own rules and sealing
defaults. The juvenile schema sets `auto_seal_at_disposition: true`
to enforce TN code §37-1-153's automatic sealing of juvenile
disposition records.

**Schema:** `jn/schemas/juvenile_case.go:39` / `:90`.

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

Lewis cosigns: she's still the judge of record, opening the companion
docket as a continuation of `2024-FAM-003`. The succession in the
next step is what hands authority over the new docket to the
juvenile-division magistrate.

## Step 6 — Judicial succession (`JudicialSuccessionPayload`)

**Legally — the delicate operation.** Lewis is sitting on the family
case (`2024-FAM-003`); Owens is the magistrate appointed for
juvenile dependency inquiries. The juvenile portion of the case
must move to Owens's authority **without invalidating Lewis's prior
orders on the family case** and without giving Owens authority over
the divorce/property aspects (which remain with Lewis). The
protocol's answer is a **scoped succession** with `inheritance:
"narrowed"` — Owens succeeds Lewis only for docket
`2024-JUV-004`, not for `2024-FAM-003`.

**Schema:** `jn/schemas/judicial_amendments.go:51`.

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

Substitute the actual `S_DELEG` value. Both Lewis and Owens sign:
Lewis as the outgoing authority, Owens as the incoming one. After
this entry lands, an authority resolver walking the chain for
action on `2024-JUV-004` finds Owens; for action on `2024-FAM-003`
it finds Lewis. **The same delegation, narrowed.**

This is what makes the entry log valuable for governance: an
external auditor — say, a law-school clinic studying authority
transfer in TN family courts — can walk every
`judicial_succession` entry in this log, group by docket, and
produce a report of "who held what authority when" without ever
calling the courthouse. The entries are typed, multi-signed, and
chronologically ordered.

## Step 7 — Mediation fails; revocation (`JudicialRevocationPayload`)

**Legally.** Six weeks later, the parties report mediation impasse.
The family-court delegation is revoked — in a fuller cast there'd
be a separate court-appointed mediator with their own delegation
(from the chief judge) that would be the actual revocation target;
we narrate the revocation as terminating Lewis's delegation itself
to keep the cast at four. In production the target would be a
`mediator` delegation with its own `S_MEDIATOR` sequence number.

**Schema:** `jn/schemas/judicial_amendments.go:31`.

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

After this entry lands, the authority resolver returns a closed
status for that delegation slot. New entries cannot rely on it as
their authority basis. Lewis's prior orders on the case remain
valid — revocation is forward-looking, not retroactive — but Lewis
cannot issue new orders under that delegation without a new
delegation entry naming her again.

## End state — full case

```bash
$ curl -fsS $DAVIDSON/v1/tree/head | jq '.size'
# Davidson tip = (size before Case 2) + 7
```

| In-case # | Schema | Primary | Cosigner | What it says |
|---|---|---|---|---|
| 1 | `family_case` | clerk | murphy | divorce + custody opens |
| 2 | `party_binding_sealed` | clerk | **lewis** | child bound, name sealed |
| 3 | `counsel_appearance` | murphy | clerk | murphy of record |
| 4 | `judicial_delegation` | lewis | clerk | lewis sits on `FAM-003` |
| 5 | `juvenile_case` | clerk | lewis | companion `JUV-004` opens |
| 6 | `judicial_succession` | lewis | **owens** | owens succeeds for `JUV-004` only |
| 7 | `judicial_revocation` | lewis | clerk | lewis's delegation closed |

## What just happened, step back

You moved authority structure across two divisions of the same
court, with each transition recorded as an immutable, multi-signed
entry on a Merkle log. Specifically:

1. **A child's identity is on the log but sealed**, with the sealing
   authority encoded in the cosigner identity (judge, not attorney).
   An audit can confirm sealing happened under judicial authority
   without ever decrypting the child's identity.
2. **A scoped succession** moved authority for one docket to a
   magistrate while leaving authority for a sibling docket intact —
   both outgoing and incoming judges signed the transfer.
3. **A revocation** closed a delegation slot, leaving an
   audit-visible record of *why* (mediation impasse) and *when*
   (precise timestamp).

These are the operations courts most often get wrong on paper. On
the log, they're typed and verifiable.

## Walkthrough complete

You've run two real Tennessee judicial cases against a real
two-ledger topology, with five real DIDs you minted yourself,
including one that crossed exchanges with a public cross-pointer
audit-followable in two ledgers that don't share state.

Final stop: **[../99-coverage.md](../99-coverage.md)** for the
schema-coverage matrix and natural extensions.
