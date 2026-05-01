# Case 2, Act I · Family filing with a sealed minor

Four entries on the Davidson log. We open the family case, bind the
minor child *under seal*, record counsel appearance, and capture
Judge Lewis's delegation to the docket.

Pre-flight: §01 + §02 done; Case 2 overview read; the three new keys
(`judge-lewis`, `magistrate-owens`, `atty-murphy`) minted; their
DIDs exported as shell variables.

## Step 1 — File the family case (`FamilyCasePayload`)

**Legally.** A divorce + custody case opens with the clerk acting
on receipt and the responsible attorney attesting as counsel of
record. In our narrative the mother's attorney files; in a real
case both parties would file separately.

**Schema:** `jn/schemas/family_case.go:31` / `:79`.

```bash
cd ~/ortholog/keys
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

The case lands at the next available sequence on the Davidson log.
If you ran Case 1 first, this is sequence 6; if you started fresh
(`make dev-down && make dev-up`), sequence 1. The remaining steps
will use *N* meaning "previous step's sequence + 1" — substitute
real numbers as you go.

## Step 2 — Bind the minor (`PartyBindingSealedPayload`)

**Legally.** The child's identity must be on the log so future
custody disposition can attribute "the child" unambiguously, but
**not in plaintext on a public log**. Tennessee code §36-1-125
governs juvenile records access. The system's answer is a **sealed
binding**: the entry exposes only a binding ID, encryption metadata,
and a vendor DID — typically the family-court vendor that holds the
encrypted real-name mapping under controlled re-encryption (umbral
proxy re-encryption keys held by court personnel under judicial
order).

**Schema:** `jn/schemas/party_binding_sealed.go:17` / `:55`.

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

**Note who cosigns:** Judge Lewis, *not* the attorney. Sealing a
binding requires judicial authority — the attorney can request
sealing, but only the judge's signature on the entry actually seals
it. This is the structural difference between a routine
`PartyBindingPayload` (clerk + attorney, no sealing) and a
`PartyBindingSealedPayload` (clerk + judge, sealing): **the cosigner
identity carries the sealing authority**, encoded in the entry's
shape rather than as an ad-hoc field.

What's on the log: the binding ID, the vendor DID, the encryption
metadata, and the encrypted-mapping CID. What's NOT on the log: the
child's name. Anyone with read access to the log sees that *some*
minor exists for case `2024-FAM-003`; only those holding the right
re-encryption authority (per the vendor's policy) can resolve the
binding ID to a name.

## Step 3 — Counsel appearance (`CounselAppearancePayload`)

Standard pattern (same shape as Case 1):

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

Murphy primary; clerk cosigns as filing receipt. `represents` lists
binding IDs — note the attorney's appearance can reference the
sealed minor binding by its public ID, even though the underlying
identity is sealed.

## Step 4 — Initial judicial delegation (`JudicialDelegationPayload`)

**Legally.** Family-court rules in Tennessee require that the
specific judge hearing a custody case have a recorded assignment
from the Chief Judge's office. The chief issues a *delegation* — a
time-bounded grant of authority — naming the judge for this docket.
We model this with Lewis self-binding because we don't have a CJ
DID in this 4-actor cast; in a real deployment the granter would
be `did:key:zQ3sh-CJ-...`.

**Schema:** `jn/schemas/judicial_delegation.go:76`.

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

**Important:** note the sequence number this entry lands at. Call
it `S_DELEG`. The succession step in Act II cites it. In a freshly-
booted topology (no Case 1) `S_DELEG = 4`.

## End-of-act state

```bash
$ curl -fsS $DAVIDSON/v1/tree/head | jq '.size'
# size before this case + 4
```

| In-case # | Schema | Primary | Cosigner | Authority |
|---|---|---|---|---|
| 1 | `family_case` | clerk | murphy | clerk's filing authority + counsel attestation |
| 2 | `party_binding_sealed` | clerk | lewis | judge's sealing authority |
| 3 | `counsel_appearance` | murphy | clerk | attorney self-attestation |
| 4 | `judicial_delegation` | lewis | clerk | judicial assignment |

## What just happened

You opened a family-court case with a sealed minor binding. The
operator never decrypted anything — the encrypted mapping CID is
just an opaque string in the entry payload, treated as bytes by
the wire layer. The judicial authority for sealing is encoded
**structurally** in the entry: which DID cosigned. An automated
audit can verify that every `party_binding_sealed` entry in the
log was cosigned by a DID that resolved-as-judge in the role
catalog at the time of cosigning, without ever needing to access
any sealed identity material.

## Continue

Open **[02-anderson-succession.md](02-anderson-succession.md)** for
the juvenile referral, judicial succession, and revocation.
