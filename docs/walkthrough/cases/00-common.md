# The common layer — what every case is built from

Step 0 ([§00](../00-identity-infra.md)) mints every actor's identity
**once**. This file is the layer directly above it: the *shared
machinery* every `cases/*` walkthrough reuses. A case never re-mints
identities and never hand-rolls a wire envelope — it is just an ordered
sequence of **one action** (write an entry) and **one check** (verify
what landed), over a fixed **vocabulary** of schemas and a fixed
**roster** of actors.

Read this once. Then each case file is short: it supplies the *story*,
the *payloads*, and the *roles* — the machinery is all here.

---

## Pre-flight (once per shell)

```bash
# 1. Step 0: identities (idempotent — safe to re-run).
make identity
. .run/identities/manifest.env        # exports $COURT_DID, $<ACTOR>_DID/_KEY/_CERT

# 2. The stack: ledger(s) + JN tools.  See §01.
make -C ../ledger dev-up              # ledgers: Davidson :8080, COA :8081
make walkthrough-up                   # JN tools + builds ./bin/judicial-cli

# 3. Endpoints the cases reference.
export DAVIDSON=http://localhost:8080
export COA=http://localhost:8081
```

Sourcing the manifest is the whole handoff from Step 0: every actor is
now a pair of shell vars — `$JUDGE_ADAMS_KEY` (the signing key file) and
`$JUDGE_ADAMS_DID` (its DID) — plus an mTLS client cert
`$JUDGE_ADAMS_CERT` for calling the JN API. Cases refer to actors by
their manifest **name** (`judge-adams`), not by path.

---

## The one action: write an entry

Every entry any case writes — a filing, a binding, an order, an
appellate disposition — goes through a single script:

```bash
./scripts/submit-entry.sh \
    --signer  judge-adams \           # primary signer (Signatures[0], Header.SignerDID)
    --attest  clerk-brown \           # co-signer / attestation (repeatable)
    --schema  tn-disclosure-order-v1 \
    --destination "$COURT_DID" \      # the log this entry is written to
    --payload ./order.json            # the domain JSON (schema-shaped)
```

It resolves the actor names to key files via the manifest, builds the
`SubmitSpec`, and submits it through `judicial-cli submit`. That's the
**common action** — `cases/*` differ only in the four inputs (who signs,
who attests, which schema, which payload).

| Flag | Meaning |
|---|---|
| `--signer <name>` | Primary signer. Becomes `Signatures[0]` and `Header.SignerDID`. Required. |
| `--attest <name>` | A co-signer / attester. **Repeatable** — pass once per attestation. |
| `--schema <uri>` | One of the registered schema URIs (table below). Required. |
| `--destination <did>` | The destination log (`$COURT_DID`, or another court's DID for cross-exchange). Required. |
| `--payload <file>` | The domain JSON, shaped to the schema's struct. Required. |
| `--evidence <did>:<seq>` | A cross-reference to a prior entry (`EvidencePointers`). **Repeatable**, cap 10. |
| `--endpoint <url>` | Ledger endpoint (default `$LEDGER_ENDPOINT` or `http://localhost:8080`). |
| `--dry-run` | Print the `SubmitSpec` and exit — no ledger required. Use it to learn the shape. |

### The core pattern: judge signs, clerk attests

`--signer judge-adams --attest clerk-brown` is the judicial order
pattern. It is **not** workflow discipline — it is policy the verifier
*enforces*. An order entry that arrives without the required clerk
attestation is **rejected** by the jurisdiction's cosignature/
attestation rule (`verification/cosignature_check.go`,
`verification/attestation_check.go`, `policy/cosignature_mix.go`). The
"ensure the clerk attested" requirement is structural, not a checklist.

Try the shape before you have a ledger running:

```bash
./scripts/submit-entry.sh --signer judge-adams --attest clerk-brown \
    --schema tn-disclosure-order-v1 --destination "$COURT_DID" \
    --payload ./order.json --dry-run
```

---

## The one check: verify what landed

`submit-entry.sh` prints `canonical_hash=<hex>` on success. That hash is
the handle for the read side — all four read wrappers are stock
`judicial-cli`:

```bash
# Wait for the sequencer to land it, then read it back.
judicial-cli wait --endpoint "$DAVIDSON" --hash <canonical_hash>   # → state=sequenced sequence=N
judicial-cli get  --endpoint "$DAVIDSON" --seq N | jq '.signatures | length'   # → 2 (signer + attester)

# The log's cosigned head, and a Merkle inclusion proof for any entry.
judicial-cli head      --endpoint "$DAVIDSON"
judicial-cli inclusion --endpoint "$DAVIDSON" --seq N
```

The sequence `N` an entry lands at is what later entries cite with
`--evidence "$COURT_DID:N"`. That is how a case composes: step 6 points
back at step 1.

### What the JN verified (three layers, all local)

When an entry is admitted and later audited, the SDK checks three
independent things — none of them touch an external RPC:

1. **Crypto identity** — the signature recovers to the address inside
   the `did:pkh` (that exact wallet/SSO account signed). Pure-CPU
   `ecrecover` (`baseproof/did/verifier_batch.go`).
2. **Authority** — that DID holds the **on-log-delegated** judicial role
   at submit time (`verification/delegation_resolver_ledger.go`,
   `verification/authority_resolver.go`). A local projection of the log,
   no network.
3. **Policy** — the signer/attester mix satisfies the schema's rule
   (judge-primary + clerk-attestation for orders).

---

## The vocabulary: schemas a case can write

The `--schema` value is a registered URI (`schemas/registry.go`). These
are the canonical strings — pass them verbatim.

| Schema URI | Struct | Typical signer → attester |
|---|---|---|
| `tn-civil-case-v1` | `schemas/civil_case.go` | clerk → plaintiff counsel |
| `tn-criminal-case-v1` | `schemas/criminal_case.go` | clerk → prosecutor |
| `tn-family-case-v1` | `schemas/family_case.go` | clerk → petitioner counsel |
| `tn-juvenile-case-v1` | `schemas/juvenile_case.go` | clerk → counsel |
| `tn-party-binding-v1` | `schemas/party_binding.go` | clerk → that party's counsel |
| `tn-party-binding-sealed-v1` | `schemas/party_binding_sealed.go` | clerk → counsel (sealed minor, etc.) |
| `tn-counsel-appearance-v1` | `schemas/counsel_appearance.go` | the attorney → clerk |
| `tn-evidence-artifact-v1` | `schemas/evidence_artifact.go` | clerk → filing party (e.g. a CEO's wallet) |
| `tn-disclosure-order-v1` | `schemas/disclosure_order.go` | judge → clerk |
| `tn-sealing-order-v1` | `schemas/sealing_order.go` | judge → clerk |
| `tn-appellate-disposition-v1` | `schemas/appellate_disposition.go` | justice → clerk |
| `tn-appellate-opinion-publication-v1` | `schemas/appellate_opinion_publication.go` | justice → clerk |
| `tn-appellate-opinion-participation-v1` | `schemas/appellate_opinion_participation.go` | panel justice → clerk |
| `tn-key-attestation-v1` | `schemas/key_attestation.go` | actor → court authority |
| `judicial-delegation-v1` | `schemas/judicial_delegation_registry.go` | court authority → clerk |
| `judicial-revocation-v1` | `schemas/judicial_delegation_registry.go` | court authority → clerk |
| `judicial-succession-v1` | `schemas/judicial_delegation_registry.go` | outgoing → incoming judge |

The ledger never parses any of these — it sequences canonical bytes. A
payload typo surfaces at the verifier, the correct architectural place
(`cmd/judicial-cli/main.go` design notes).

---

## The roster: who's available (from Step 0's default `ACTORS`)

| Manifest name | Vars | Role in the cases | did:pkh chain |
|---|---|---|---|
| `clerk-brown` | `$CLERK_BROWN_{DID,KEY,CERT}` | Court Clerk — attests nearly everything | eip155:1 |
| `judge-adams` | `$JUDGE_ADAMS_*` | Trial Judge (Davidson) | eip155:1 |
| `justice-edwards` | `$JUSTICE_EDWARDS_*` | Appellate Justice (TN COA) | eip155:1 |
| `cooper` | `$COOPER_*` | Plaintiff's attorney | eip155:1 |
| `davis` | `$DAVIS_*` | Defendant's attorney | eip155:8453 |
| `acme-ceo` | `$ACME_CEO_*` | Corporate party signing from a wallet | eip155:42161 |
| `beta-cfo` | `$BETA_CFO_*` | Corporate party signing from a wallet | eip155:137 |

Every actor here is **one method to the JN — a `did:pkh` EOA**, verified
pure-CPU and chain-agnostic; the chain id is just `did:pkh` metadata.
Locally `judicial-cli` signs with the key file (`SigAlgoEIP191`); in
production the *same* DID signs in the wallet via `eth_signTypedData_v4`
(`SigAlgoEIP712`). Same verification path either way. Add or rename
actors by overriding `ACTORS=` on `make identity` (see §00).

The court/log itself (`$COURT_DID = did:web:state:tn:davidson`) is **not**
in the roster — it is `did:web`, compiled in, and signs tree heads, not
entries.

---

## The shape of a case

Putting it together, every `cases/*` file is:

1. **Pre-flight** — the block at the top of this page (Step 0 + stack).
2. **A sequence of `submit-entry.sh` calls** — one per entry, each a
   `--signer/--attest/--schema/--payload` quad, verified with
   `judicial-cli wait/get`.
3. **Cross-references** — later entries cite earlier sequences with
   `--evidence "$COURT_DID:<seq>"`; a cross-*exchange* reference just
   changes `--destination`/`--endpoint` to the other court.

That's the entire contract. Open **[Case 1 — ACME v. Beta](01-acme-v-beta.md)**.
