# Case 1, Act I · Trial in Davidson Chancery

Five entries on the Davidson log. We open the case, bind the parties,
and record both attorneys' appearances. By the end of this file
`curl -fsS $DAVIDSON/v1/tree/head | jq '.size'` returns `5`.

Pre-flight: §01 + §02 done. `$CLERK`, `$COOPER`, `$DAVIS` are
exported. You're in `~/ortholog/keys`.

## Step 1 — File the case (`CivilCasePayload`)

**Legally.** The clerk receives ACME's complaint and opens a case
file. In the digital log, opening the case is publishing a
`CivilCasePayload` whose primary signer is the clerk. The
plaintiff's attorney cosigns to attest the filing on the
plaintiff's behalf — Tennessee electronic-filing rule §27 requires
both the filer (clerk acting on receipt) and the responsible
attorney of record on every initial filing.

**Schema:** `jn/schemas/civil_case.go:29` (struct), `:79`
(`SerializeCivilCasePayload`).

**Build the spec:**

```bash
cd ~/ortholog/keys
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
```

**Submit:**

```bash
$ judicial-cli submit --endpoint $DAVIDSON --spec civil-filing.spec.json
canonical_hash=4b8c1d8e3f7a9b2c5e6d4f8a1b3c9d2e5f7a8b1c4d6e9f0a3b5c7d8e1f2a4b6c
status=accepted (HTTP 202)
sct={"version":1,"signer_did":"did:key:zQ3sh-OPERATOR-DAVIDSON",...}
```

The operator returned an SCT — a binding promise to sequence within
MMD (24h dev default). The Sequencer goroutine picks the entry up
immediately; within ~500 ms it lands at sequence 1.

**Watch it land:**

```bash
$ judicial-cli wait --endpoint $DAVIDSON \
    --hash 4b8c1d8e3f7a9b2c5e6d4f8a1b3c9d2e5f7a8b1c4d6e9f0a3b5c7d8e1f2a4b6c
state=sequenced sequence=1
```

**Inspect:**

```bash
$ judicial-cli get --endpoint $DAVIDSON --seq 1 | jq '.signatures | length'
2
```

Two signatures (clerk + cooper). The civil case is officially open.
A quick GCS-bucket inspection confirms the entry landed:

```bash
$ curl -fsS 'http://localhost:4443/storage/v1/b/davidson-entries/o' | jq '.items | length'
1
```

That one object **is** the entry; its content is the canonical
wire bytes.

## Step 2 — Bind the parties (`PartyBindingPayload` ×2)

**Legally.** The case caption names ACME and Beta Corp; party-binding
entries make those names machine-resolvable to identifiers in the
system. Without these, a downstream motion that says "the plaintiff"
is ambiguous to any automated audit.

**Schema:** `jn/schemas/party_binding.go:66` / `:151`.

**Plaintiff binding** (clerk + cooper):

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

**Defendant binding** (clerk + davis — the defense attorney attests
from their side):

```bash
cat > bind-defendant.spec.json <<EOF
{
  "schema":      "party_binding",
  "destination": "did:web:state:tn:davidson",
  "primary_signer_key": "clerk-brown.key.json",
  "cosigner_keys":      ["davis.key.json"],
  "payload": {
    "binding_id":  "bind-beta-001",
    "party_class": "defendant",
    "party_name":  "Beta Corp LLC",
    "case_ref":    "2024-CV-001",
    "case_seq":    1
  }
}
EOF
judicial-cli submit --endpoint $DAVIDSON --spec bind-defendant.spec.json
```

Sequences 2 and 3. Confirm:

```bash
$ curl -fsS $DAVIDSON/v1/tree/head | jq '.size'
3
```

## Step 3 — Counsel appearances (`CounselAppearancePayload` ×2)

**Legally.** Cooper and Davis enter formal appearances attesting
their representation. The primary signer is **the attorney
themselves** — this is the key authority change versus filings.
Cooper's signature on his own appearance entry is the legal
attestation that he represents ACME in this case. The clerk
cosigns as filing receipt.

**Schema:** `jn/schemas/counsel_appearance.go:48` / `:151`.

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

Repeat for Davis (swap `cooper.key.json` ↔ `davis.key.json`,
`bind-acme-001` → `bind-beta-001`, `ap-cooper-001` →
`ap-davis-001`, `attorney_did` accordingly). Sequences 4 and 5.

## Step 4 — Witness affidavit signed from a wallet (`EvidenceArtifactPayload`, web3 DID)

**Legally.** Mid-trial, ACME's CEO submits a sworn affidavit
attesting to the contract-formation facts. ACME's corporate signing
authority is a multi-sig wallet on Ethereum (the company's
`acme-ceo` DID is the EOA that controls the wallet for routine
attestations). The clerk records receipt; the CEO signs the
affidavit entry with their **wallet** — the same key that holds
the company's on-chain assets — using EIP-191 personal-sign.

This is the walkthrough's web3 moment: a real Ethereum-form
signature on the same log as the court personnel's `did:key`
signatures, both verifying through the same SDK dispatcher with
no special-case handling.

**Schema:** `jn/schemas/evidence_artifact.go:71` / `:135`.

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

**What just happened technically.** The CLI saw `did_method:
"pkh-eip155"` in the cosigner key file, dispatched to the
EIP-191 path: wrapped the canonical-hash digest in EIP-191 prefix
(`\x19Ethereum Signed Message:\n32` + 32 hash bytes → keccak256),
signed with `SignEthereumRecoverable` (65 bytes r||s||v), and
attached `AlgoID: SigAlgoEIP191` (0x0003). The operator admitted
the entry without ever inspecting the DID method — just bytes.

**Verify the signature shape on the log:**

```bash
$ judicial-cli get --endpoint $DAVIDSON --seq 6 \
    | jq '.signatures[] | {signer: .signer_did, algo: .algo_id, sig_len: (.bytes | length / 2)}'
{
  "signer": "did:key:zQ3sh...CLERK",
  "algo": 1,
  "sig_len": 64
}
{
  "signer": "did:pkh:eip155:1:0x7ad817...",
  "algo": 3,
  "sig_len": 65
}
```

Two signatures on a single entry, two different signing primitives,
two different DID methods — all verifying through the operator's
single per-method DID dispatcher when an SDK-level audit reads the
log later.

The "evidence" object now exists in the `davidson-entries` GCS
bucket:

```bash
$ curl -fsS 'http://localhost:4443/storage/v1/b/davidson-entries/o' \
    | jq '.items | length'
6
```

## Trial concludes

We skip the in-trial entries (motions, orders, exhibits) for
narrative brevity — the same primary+cosigner pattern repeats. After
a four-day bench trial Judge Adams enters judgment for ACME for
$800K plus statutory interest. Beta Corp files a notice of appeal.

The case now moves to the Court of Appeals — a different operator,
on `:8081`. Same CLI; different `--endpoint`.

## End-of-act state

```bash
$ curl -fsS $DAVIDSON/v1/tree/head | jq '.size, .root_hash'
6
"e2c4..." # the Merkle root over the 6 trial-court entries
```

`davidson-entries` GCS bucket: 6 objects (one per sequenced entry).
`coa-entries`: still empty.

## What just happened, in one breath

You filed five domain-meaningful judicial entries through a real
binary protocol — clerk-attested civil filing, two party bindings
attested by opposing counsel, two attorney appearances self-attested
under their own keys. Each entry is a multi-signature canonical
envelope; each signature was produced by an actual secp256k1 key
you minted yourself; each is now sequenced into a Merkle log whose
head you can fetch via curl. The operator never inspected the
domain payload — it sequenced canonical bytes whose interior
*happens* to be JSON about Tennessee civil procedure. That's the
clean separation between the protocol layer and the domain layer.

## Continue

Open **[01-acme-v-beta-appeal.md](01-acme-v-beta-appeal.md)** for
the cross-exchange appeal.
