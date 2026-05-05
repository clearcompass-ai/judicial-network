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

## 1. Pick a keys directory

```bash
mkdir -p ~/attesta/keys
cd ~/attesta/keys
```

Permissions land at `0600` (owner read/write only) — the CLI sets
that on write.

## 2. The seven actors

| Alias | DID method | Role | Used in case(s) |
|---|---|---|---|
| `clerk-brown` | `did:key` | Court Clerk, Davidson | Both |
| `cooper` | `did:key` | Plaintiff's attorney, ACME | Case 1 (civil) |
| `davis` | `did:key` | Defendant's attorney, Beta | Case 1 (civil) |
| `judge-adams` | `did:key` | Trial Judge, Davidson | Case 1 |
| `justice-edwards` | `did:key` | Appellate Justice, TN COA | Case 1 (appeal) |
| `acme-ceo` | `did:pkh` (web3) | Plaintiff CEO, signs from corporate wallet | Case 1 (witness affidavit) |
| `beta-cfo` | `did:pkh` (web3) | Defendant CFO, signs from corporate wallet | Case 1 (counter-affidavit) |

Case 2 reuses `clerk-brown` and adds three more (`judge-lewis`,
`magistrate-owens`, `atty-murphy`) — minted in Case 2 itself.

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

## 4. Mint two web3 DIDs (`did:pkh:eip155`)

```bash
judicial-cli keygen --out acme-ceo.key.json --method pkh-eip155
judicial-cli keygen --out beta-cfo.key.json --method pkh-eip155
```

Each prints a CAIP-10 form:

```
$ judicial-cli keygen --out acme-ceo.key.json --method pkh-eip155
did=did:pkh:eip155:1:0x7ad817edea4e9eb9c223983ec9604376ce2d668f
method=pkh-eip155
file=/home/you/attesta/keys/acme-ceo.key.json
```

The `eip155:1` part is the CAIP-2 chain identifier — `1` is
Ethereum mainnet. Pass `--chain-id 137` for Polygon, `--chain-id
42161` for Arbitrum, etc. The address (`0x7ad817...`) is
`Keccak256(uncompressed_pubkey[1:])[12:]` — the same derivation
every Ethereum wallet uses.

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
CLERK=$(jq -r '.did'   clerk-brown.key.json)
COOPER=$(jq -r '.did'  cooper.key.json)
DAVIS=$(jq -r '.did'   davis.key.json)
ADAMS=$(jq -r '.did'   judge-adams.key.json)
EDWARDS=$(jq -r '.did' justice-edwards.key.json)
ACME_CEO=$(jq -r '.did' acme-ceo.key.json)
BETA_CFO=$(jq -r '.did' beta-cfo.key.json)

echo "$ACME_CEO"   # did:pkh:eip155:1:0x...
echo "$CLERK"      # did:key:zQ3sh...
```

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
| 5 `did:key` keypairs | `~/attesta/keys/{clerk,cooper,davis,judge-adams,justice-edwards}.key.json` |
| 2 `did:pkh` keypairs (web3 wallets) | `~/attesta/keys/{acme-ceo,beta-cfo}.key.json` |
| 7 DID strings in shell vars | `$CLERK $COOPER $DAVIS $ADAMS $EDWARDS $ACME_CEO $BETA_CFO` |
| 0 entries on either log | `curl -fsS $DAVIDSON/v1/tree/head` |

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
