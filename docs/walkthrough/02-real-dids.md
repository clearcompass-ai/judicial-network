# §02 · Mint real DIDs (`did:key` and `did:pkh`)

The walkthrough has actors with two flavors of identity. In §02 you
mint a real secp256k1 keypair for each one — same primitive in every
case — and decide whether to encode the public key as a `did:key`
(the W3C-spec multibase form, used by court personnel) or as a
`did:pkh:eip155:1:0x<addr>` (the CAIP-10 wallet form, used by
parties whose primary identity is an Ethereum wallet).

These are not pretend DIDs. They're the same keypair shape the
ledger uses for its own entry-signing key
(`ledger/cmd/ledger/main.go:189-200`). A signature produced by
one of these keys verifies cleanly through the SDK's
`did.NewKeyResolver()` (for did:key) or PKHVerifier (for did:pkh).

## Two DID methods, one signing primitive

| | `did:key` | `did:pkh:eip155:1:0x...` |
|---|---|---|
| Underlying key | secp256k1 | secp256k1 |
| DID encoding | multibase (compressed pubkey) | CAIP-10 (Ethereum address) |
| Signing primitive | `SignEntry` (64 bytes r\|\|s) | `SignEthereumRecoverable` (65 bytes r\|\|s\|\|v) |
| Signing digest | sha256(SigningPayload) | EIP191Digest(sha256(SigningPayload)) |
| Wire `AlgoID` | `SigAlgoECDSA` (0x0001) | `SigAlgoEIP191` (0x0003) |
| Verifier | KeyVerifier | PKHVerifier |
| Real-world | Court bar-issued keys, HSM-backed admin | MetaMask, Coinbase Wallet, Privy embedded, Safe wallets |

The `judicial-cli keygen` flag `--method pkh-eip155` switches the
DID encoding and signing path; everything else is shared.

## Three signature layers (v1.8 + attesta v1.5.1)

The walkthrough exercises THREE distinct signature mechanisms.
Conflating them is the most common mental-model bug, so they're
spelled out here once:

### Layer 1 — Entry signatures

**Where:** `entry.Signatures[]` on every canonical envelope. Visible
via `judicial-cli get --seq N | jq '.signatures'`.

**Who (v1.8 strict):** Only **T1 Signers** (Adjudicators, Clerks,
Court Reporters). Per v1.8 Part 1 Authority Summary: T2 Filers have
"Holds Keys = ❌" and T3 Parties have "Has DID = ❌". Strict reading:
the only DIDs that appear in `entry.Signatures[]` are T1 DIDs.

**Who (JN current implementation):** The CLI's `cosigner_keys` array
accepts ANY keypair file regardless of DID method or actor tier;
all of them produce real signatures that land in
`entry.Signatures[]`. This means current walkthroughs sometimes
place T2 attorney DIDs and T3 party-wallet DIDs in the entry
signers list alongside T1 Clerk/Judge DIDs.

**JN extension flag.** The walkthrough's current shape — attorneys
signing their own `counsel_appearance`, party wallets cosigning
`evidence_artifact` — is a **JN extension** to v1.8, not v1.8 strict.
JN reads v1.8's "Filers cannot sign entries directly" as: *the Signer
must always be present in `Signatures[]`*. The Filer's signature may
also be in `Signatures[]` as documentation that the attorney
attested the filing — but it never substitutes for the Signer's
signature. Production deployments that need v1.8-strict behavior
move T2 / T3 identities to **Layer 2** (payload metadata) instead.

> 🚩 **Tracked gap.** Migrating attorneys + parties out of
> `entry.Signatures[]` and into payload-embedded attestations is a
> separate workstream. It requires CLI changes (a new
> `payload_attestations` spec field) and a schema-by-schema review
> of `attorney_did` / `filed_by` / similar payload references.
> Until that ships, the current walkthrough specs work as
> documented and the JN extension is acknowledged here.

### Layer 2 — Payload-embedded attestations

**Where:** Inside the schema-typed `payload` field of the envelope.
Visible via `judicial-cli get --seq N | jq '.payload'`.

**Who:** T2 Filers (`attorney_did`, `filed_by` references), T3
Parties (`binding_id` references on `party_binding` events; optional
wallet DID + signature inside an `evidence_artifact` for
acknowledgments).

**What v1.8 expects:** Per v1.8 §Part 1 "Filers (Active Metadata
Subjects)": "they are network entities with their own DIDs (recorded
in `attorney_did` and similar payload fields)". The payload IS the
v1.8-mandated location for Filer identity. v1.8 §Part 1 "Parties
(Passive Metadata Subjects)" extends the same pattern to T3 — their
identity lives in `party_binding` payloads via the case-local
`binding_id`.

**Wallet attestations as payload data.** A T3 party's wallet
signature on an `evidence_artifact` (the ACME-CEO affidavit + the
two parental acknowledgments in the walkthrough) can be embedded
into the payload as a JN extension: a `party_attestations` array
of `{did, sig_algo, signature_hex, signed_digest}` tuples. This
shape is NOT in the current schemas; it's the target migration
shape for true v1.8 alignment. Today the wallet signatures appear
in Layer 1 instead.

### Layer 3 — Cowitness attestations (K-of-N quorum)

**Where:** `/v1/tree/head` response on every ledger. Visible via
`curl -fsS $DAVIDSON/v1/tree/head | jq '.cosignatures'`.

**Who:** N **independent cowitness operators**, each running its
own `standalone-witness` daemon with its own keypair. NOT case
actors.

**SDK mechanism (attesta v1.5.2, citations).**

- `crypto/cosign/witness_key_set.go::WitnessKeySet` carries the set
  topology: `keys []types.WitnessPublicKey`, `quorum int`,
  `networkID`, optional BLS aggregate verifier. Constructor
  `NewWitnessKeySet` enforces `1 ≤ K ≤ N` (line 215), unique
  PubKey IDs (line 222), non-zero NetworkID (line 211).
- Exposed methods: `Keys()`, `Size()` returning N, `Quorum()`
  returning K (lines 190 / 209 / 220).
- `types/tree_head.go::WitnessSignature` is one cowitness
  attestation: `PubKeyID [32]byte`, `SchemeTag byte` (ECDSA=64-byte
  R||S; BLS=48-byte compressed G1), `SigBytes []byte`.
- `types.CosignedTreeHead` aggregates: embeds `TreeHead{RootHash,
  SMTRoot, TreeSize}` and carries `Signatures []WitnessSignature`.

**How the aggregate is built (ledger side).**
`clearcompass-ai/ledger/cmd/ledger/boot/wire/gossip.go:363-388`
(`wireWitnessCosigner`) constructs a `witnessclient.HeadSync` from
three env vars:

  - `LEDGER_WITNESS_ENDPOINTS` — list of cowitness URLs the ledger
    polls
  - `LEDGER_WITNESS_QUORUM_K` — the K threshold
  - `LEDGER_GENESIS_WITNESS_SET` — DIDs that are allowed to cosign

If `LEDGER_WITNESS_ENDPOINTS` is empty (line 364), the mechanism is
**silently disabled** and `cosignatures: []`. This is the default
in the integration topology.

**What it provides:** External transparency. Every entry on the
log is committed to a tree head; every tree head requires K-of-N
independent cowitness attestations to be considered witnessed; a
forked or tampered log would produce a different `RootHash` /
`SMTRoot` / `TreeSize` triple, and any honest cowitness comparing
the head it previously signed against the head this ledger now
publishes would catch the divergence and refuse to re-cosign.

**Critical distinction.** Cowitness attestations (Layer 3) are NOT
v1.8 Part 1's "Filer cosignature":

| Layer | Sig over | Scope | Mandated by |
|---|---|---|---|
| L1 entry signatures | One envelope's canonical bytes | One entry | v1.8 §"Cryptographic Authority" |
| L2 payload attestations | Payload content (off-envelope) | One entry's data | v1.8 §Part 1 Filers/Parties |
| L3 cowitness attestations | The whole Merkle root + SMT root + tree size | Entire log | attesta v1.5.2 `cosign.WitnessKeySet` (independent of v1.8) |

The walkthrough's evidence pattern reaches all three:

- Layer 1: `judicial-cli get --seq N | jq '.signatures'`
- Layer 2: `judicial-cli get --seq N | jq '.payload | {attorney_did, filed_by}'`
- Layer 3: `curl $DAVIDSON/v1/tree/head | jq '.cosignatures | length, [.[] | {pubkey_id, scheme_tag}]'`

**Recommended demo: N=2 cowitnesses, K=2.** Both attestations
required for the tree head to be witnessed. Demonstrates the
K-of-N mechanism without the cost of running 3 daemons; runs
through the same constructor + verification path that production
N=5 / K=3 deployments use.

## 1. Pick a keys directory

```bash
mkdir -p ~/attesta/keys
cd ~/attesta/keys
```

Permissions land at `0600` (owner read/write only) — the CLI sets
that on write.

## 2. The actor cast (v1.8 three-tier model + web3-aware)

Per **Event Dictionary v1.8 Part 1**, actors fall into three
tiers based on cryptographic relationship to the log:

| Tier | v1.8 label | What v1.8 says | Web3 wallet? |
|---|---|---|---|
| **T1** | Signer | "The only entities that hold network cryptographic keys." Adjudicators, Clerks, Court Reporters. Exchange-scoped. | **No.** Institutional keys; HSM-backed in production. `did:key` only. |
| **T2** | Filer | "Legal professionals who drive litigation. They do not hold network keys, but they are network entities with their own DIDs… Every event submitted by a Filer requires Signer cosignature." Prosecutors, Defense Counsel, Civil Attorneys, Fiduciaries, Guardians ad litem. | **Optional.** Bar-issued court key (`did:key`) is canonical; some attorneys ALSO hold a personal-capacity wallet for non-court attestations (amicus authorship published off-court, conflict-disclosure attestation from a wallet they already use, etc.). The court-capacity DID stays `did:key`. |
| **T3** | Party | "The actual participants in the dispute. **Parties are not network entities and do not have DIDs.** They are recorded as case-local data inside `party_binding` events; the `binding_id` … is the only public reference." Plaintiffs, Defendants, Respondents, the State, Pro Se Litigants. | **Optional adoption overlay.** v1.8 strict reading: no DID. JN extension: a party that already holds a wallet (corporate CEO, individual with MetaMask / Coinbase Wallet / Privy embedded wallet) may attach wallet-signed attestations to entries that name them. The `binding_id` remains the v1.8-mandated public reference; the wallet DID is an *authentication overlay*, not a substitute. |

**Critical: T3 wallet adoption is a JN extension, not v1.8 strict.**
The trial Step 4 (ACME CEO affidavit) and the Anderson filing Step 2
(parental acknowledgments) both demonstrate this pattern. In every
case the Clerk's signature is the operative T1 authority; the
party's wallet cosignature is documentation that the party
themselves authenticated the entry. v1.8's "Parties have no DIDs"
invariant is preserved at the case-local-identifier level: parties
appear in `party_binding` events by `binding_id`, not by wallet
DID. The wallet DID surfaces only on optional
`evidence_artifact` acknowledgments, never on the party-binding
event itself.

The web3 question per tier:

Multi-chain support: `did:pkh:eip155:<chainId>:0x<addr>` per CAIP-10.
`judicial-cli keygen --method pkh-eip155 --chain-id N` accepts any
EVM chain ID. Common values:

| Chain | `chain-id` | Use |
|---|---|---|
| Ethereum mainnet | `1` | Most corporate wallets |
| Polygon | `137` | Cheap signatures; preferred for high-volume parties |
| Optimism | `10` | L2 scaling |
| Arbitrum | `42161` | L2 scaling |
| Base | `8453` | Coinbase-hosted L2; common for retail-onboarded wallets |

The CHAIN of a `did:pkh` is identity metadata — the verification
primitive (`SignEthereumRecoverable` + `SigAlgoEIP191`) is the same
across all EVM chains. A Polygon-resident wallet's signature
verifies on the same ledger that hosts an Ethereum-mainnet wallet's
signature; the chain id is documentation of WHERE the wallet
typically operates, not a constraint on WHERE the signature is
valid.

## Cast for the walkthrough cases

| Alias | DID method | v1.8 role | Wallet network | Used in case(s) |
|---|---|---|---|---|
| `clerk-brown` | `did:key` | Signer-Clerk | — | Both |
| `cooper` | `did:key` | Filer-Attorney | — | Case 1 (civil) |
| `davis` | `did:key` | Filer-Attorney | — | Case 1 (civil) |
| `judge-adams` | `did:key` | Signer-Adjudicator | — | Case 1 |
| `justice-edwards` | `did:key` | Signer-Adjudicator | — | Case 1 (appeal) |
| `acme-ceo` | `did:pkh:eip155:1` | Party (plaintiff principal) | **Ethereum mainnet** | Case 1 (witness affidavit) |
| `beta-cfo` | `did:pkh:eip155:137` | Party (defendant principal) | **Polygon** | Case 1 (counter-affidavit) |
| `anderson-mother` | `did:pkh:eip155:8453` | Party (family case principal) | **Base** | Case 2 (family filing acknowledgment) |
| `anderson-father` | `did:pkh:eip155:10` | Party (family case principal) | **Optimism** | Case 2 (family filing acknowledgment) |

Case 2 also mints three more court personnel (`judge-lewis`,
`magistrate-owens`, `atty-murphy`) — minted in Case 2's filing
walkthrough.

**Five web3 networks represented**: Ethereum mainnet, Polygon,
Base, Optimism, Arbitrum (the last via the optional witness
extension below). The point is to demonstrate that the protocol
admits signatures from ANY EVM-compatible wallet network without
preference; chain-id is documentation only.

## 3. Mint the five court-personnel DIDs (`did:key`)

```bash
judicial-cli keygen --out clerk-brown.key.json
judicial-cli keygen --out cooper.key.json
judicial-cli keygen --out davis.key.json
judicial-cli keygen --out judge-adams.key.json
judicial-cli keygen --out justice-edwards.key.json
```

Each prints the assigned DID:

```
$ judicial-cli keygen --out clerk-brown.key.json
did=did:key:zQ3shgNJJbyVUSbFVpqXCGQ8LjWshxtMPufJHrekzougqsyur
method=key
file=/home/you/attesta/keys/clerk-brown.key.json
```

The `did:key:zQ3sh...` form encodes the **compressed secp256k1
public key** in multibase. Per the [W3C did:key
spec](https://w3c-ccg.github.io/did-method-key/), anyone holding
the DID string can re-derive the public key without consulting a
registry. No resolver dependency; ideal for institutional keys.

## 4. Mint four web3 DIDs across four EVM chains

Each party-principal mints from a different EVM chain to demonstrate
multi-network support. The protocol admits all four identically;
chain-id is identity metadata, not a constraint.

```bash
# ACME's CEO — Ethereum mainnet (chain-id 1, the default; flag shown for clarity)
judicial-cli keygen --out acme-ceo.key.json --method pkh-eip155 --chain-id 1

# Beta's CFO — Polygon (chain-id 137)
judicial-cli keygen --out beta-cfo.key.json --method pkh-eip155 --chain-id 137

# Anderson mother — Base (chain-id 8453; Coinbase-hosted L2)
judicial-cli keygen --out anderson-mother.key.json --method pkh-eip155 --chain-id 8453

# Anderson father — Optimism (chain-id 10)
judicial-cli keygen --out anderson-father.key.json --method pkh-eip155 --chain-id 10
```

Each prints a CAIP-10 form:

```
$ judicial-cli keygen --out acme-ceo.key.json --method pkh-eip155 --chain-id 1
did=did:pkh:eip155:1:0x7ad817edea4e9eb9c223983ec9604376ce2d668f
method=pkh-eip155
file=/home/you/attesta/keys/acme-ceo.key.json

$ judicial-cli keygen --out beta-cfo.key.json --method pkh-eip155 --chain-id 137
did=did:pkh:eip155:137:0x5c8d92ab4fe6b9c1e3d5a7b8c9f0e1d2c3b4a596
method=pkh-eip155
file=/home/you/attesta/keys/beta-cfo.key.json
```

The `eip155:<N>` part is the CAIP-2 chain identifier. The address
(`0x7ad817...`) is `Keccak256(uncompressed_pubkey[1:])[12:]` — the
same derivation every Ethereum wallet uses, regardless of which
chain the wallet typically operates on.

## 5. Inspect a `did:pkh` key file

```bash
$ cat acme-ceo.key.json
{
  "did": "did:pkh:eip155:1:0x7ad817edea4e9eb9c223983ec9604376ce2d668f",
  "did_method": "pkh-eip155",
  "chain_id": 1,
  "ethereum_address_hex": "0x7ad817edea4e9eb9c223983ec9604376ce2d668f",
  "private_key_hex": "8a1b...32 bytes...4f9c",
  "public_key_compressed_hex": "02d9a8...33 bytes...0b41"
}
```

Compare to a `did:key` file (no `did_method`, `chain_id`,
`ethereum_address_hex` fields — just the bare DID + key bytes).
The CLI's submitter reads `did_method` to pick the right signing
primitive.

## 6. Capture each DID in a shell variable

```bash
# Court personnel (did:key)
CLERK=$(jq -r '.did'   clerk-brown.key.json)
COOPER=$(jq -r '.did'  cooper.key.json)
DAVIS=$(jq -r '.did'   davis.key.json)
ADAMS=$(jq -r '.did'   judge-adams.key.json)
EDWARDS=$(jq -r '.did' justice-edwards.key.json)

# Party principals (did:pkh, multi-chain)
ACME_CEO=$(jq -r '.did'        acme-ceo.key.json)
BETA_CFO=$(jq -r '.did'        beta-cfo.key.json)
ANDERSON_MOTHER=$(jq -r '.did' anderson-mother.key.json)
ANDERSON_FATHER=$(jq -r '.did' anderson-father.key.json)

echo "$ACME_CEO"         # did:pkh:eip155:1:0x...      (Ethereum mainnet)
echo "$BETA_CFO"         # did:pkh:eip155:137:0x...    (Polygon)
echo "$ANDERSON_MOTHER"  # did:pkh:eip155:8453:0x...   (Base)
echo "$ANDERSON_FATHER"  # did:pkh:eip155:10:0x...     (Optimism)
echo "$CLERK"            # did:key:zQ3sh...
```

## 6b. Optional: enroll an Arbitrum witness

For the §99 extension demonstrating a 5th chain:

```bash
judicial-cli keygen --out external-witness.key.json \
    --method pkh-eip155 --chain-id 42161   # Arbitrum
WITNESS_ARB=$(jq -r '.did' external-witness.key.json)
echo "$WITNESS_ARB"   # did:pkh:eip155:42161:0x...
```

Nothing in the walkthrough requires this — it's there as evidence
that adding a 6th, 7th, Nth EVM chain is one CLI flag away.

## 7. Verify both methods round-trip cleanly

```bash
cd ~/attesta/jn
go test ./cmd/judicial-cli/ -run "TestKeygen_Roundtrip|TestKeygen_PKHEIP155_Roundtrip|TestSignByMethod_PKH_RoundTripsThroughPKHVerifier" -v
```

Expected: three PASSes. The third is load-bearing — it pins that a
signature produced by `judicial-cli` for a `did:pkh` key verifies
through `sdksigs.VerifySecp256k1EIP191`, which is the same primitive
the ledger's PKHVerifier dispatches to under `SigAlgoEIP191`.

If those three pass, every web3 step in the walkthrough will work.

## 8. What's NOT happening yet

- No HTTP request issued to either ledger.
- No entry on either log.
- No DID has any *role* assigned. DIDs are public-key identifiers;
  the judicial-network's role catalog and authority resolver bind a
  DID to a role inside an institutional context. In production that
  binding happens via a `JudicialDelegationPayload` entry on the
  log; in the walkthrough we'll see that step explicitly in Case 1.

## 9. Recap

| You have | Where |
|---|---|
| 5 `did:key` keypairs (court personnel) | `~/attesta/keys/{clerk-brown,cooper,davis,judge-adams,justice-edwards}.key.json` |
| 4 `did:pkh` keypairs across 4 EVM chains (party principals) | `~/attesta/keys/{acme-ceo,beta-cfo,anderson-mother,anderson-father}.key.json` |
| 9 DID strings in shell vars | `$CLERK $COOPER $DAVIS $ADAMS $EDWARDS $ACME_CEO $BETA_CFO $ANDERSON_MOTHER $ANDERSON_FATHER` |
| 0 entries on either log | `curl -fsS $DAVIDSON/v1/tree/head` |

**Web3 chain coverage in the cast**: Ethereum mainnet (1), Polygon
(137), Optimism (10), Base (8453) — four EVM networks
represented across four party principals. Plus optional Arbitrum
(42161) via §6b. **All five admitted to the same ledger with the
same verification path** — the protocol's CAIP-10-native handling
makes multi-network support a non-event.

## Next

The remaining setup section boots the JN application-layer tools
(court-tools + provider-tools) so that everything you submit in
the cases shows up in the workflow API and the public-records API
within seconds:

- **[§03 — Boot the JN tools](03-tools.md)** (last setup step)

After that, both case files are independently runnable in any
order:

- **Case 1: ACME v. Beta** —
  [cases/01-acme-v-beta.md](cases/01-acme-v-beta.md). The trial
  includes a wallet-signed CEO affidavit step
  ([trial.md](cases/01-acme-v-beta-trial.md) Step 4) demonstrating
  did:pkh end-to-end.
- **Case 2: In re Anderson** —
  [cases/02-in-re-anderson.md](cases/02-in-re-anderson.md).

If you only want the protocol-level walkthrough and not the JN
tools, you can skip §03 — `judicial-cli` talks directly to the
ledger and doesn't need court-tools or provider-tools to
function. Skipping §03 just means cases don't visibly populate
the workflow API; they still land on the ledger's log.
