# §02 · Mint five real did:keys

The walkthrough has five actors. In §02 you mint a real secp256k1
keypair for each one, encode each as a `did:key` (the spec-compliant
multibase form), and stash the keys somewhere `judicial-cli` can
find them.

These are not pretend DIDs. They're the same keypair shape the
operator uses for its own entry-signing key
(`operator/cmd/operator/main.go:189-200`). A signature produced by
one of these keys will verify cleanly through the SDK's
`signatures.VerifyEntry` and roundtrip through
`did.NewKeyResolver().Resolve(...)`.

## 1. Pick a keys directory

```bash
mkdir -p ~/ortholog/keys
cd ~/ortholog/keys
```

Why a dedicated directory: each `judicial-cli` step references a key
by file path, so keeping them organized matters. Permissions land at
`0600` (owner read/write only) — the CLI sets that on write.

## 2. The five actors

| Alias | Role | Used in case(s) |
|---|---|---|
| `clerk-brown` | Court Clerk, Davidson County | Both cases |
| `cooper`      | Plaintiff's attorney, ACME | Case 1 (civil) |
| `davis`       | Defendant's attorney, Beta Corp | Case 1 (civil) |
| `judge-adams` | Trial Judge, Davidson | Case 1 (civil) |
| `justice-edwards` | Appellate Justice, TN COA | Case 1 (appeal) |

Case 2 reuses `clerk-brown` and adds three more (`judge-lewis`,
`magistrate-owens`, `atty-murphy`) — you'll mint those in §02 of Case
2 itself, so they appear when their narrative does.

## 3. Mint them

One command per actor:

```bash
judicial-cli keygen --out clerk-brown.key.json
judicial-cli keygen --out cooper.key.json
judicial-cli keygen --out davis.key.json
judicial-cli keygen --out judge-adams.key.json
judicial-cli keygen --out justice-edwards.key.json
```

Each prints the assigned DID. Sample run:

```
$ judicial-cli keygen --out clerk-brown.key.json
did=did:key:zQ3shgNJJbyVUSbFVpqXCGQ8LjWshxtMPufJHrekzougqsyur
file=/home/you/ortholog/keys/clerk-brown.key.json
```

The DID encodes the **compressed secp256k1 public key** in
multibase. Per the [W3C did:key
spec](https://w3c-ccg.github.io/did-method-key/), anyone holding the
DID string can re-derive the public key without consulting a
registry. That's the point: did:key has no resolver dependency.

## 4. Inspect a key file

```bash
$ cat clerk-brown.key.json
{
  "did": "did:key:zQ3shgNJJbyVUSbFVpqXCGQ8LjWshxtMPufJHrekzougqsyur",
  "private_key_hex": "8a1b...32 bytes...4f9c",
  "public_key_compressed_hex": "02d9a8...33 bytes...0b41"
}
```

Three fields:
- `did` — the public identifier the entries will reference.
- `private_key_hex` — the 32-byte secp256k1 private scalar.
- `public_key_compressed_hex` — the 33-byte compressed pubkey
  (the same bytes encoded in the DID, hex form for convenience).

Treat `private_key_hex` like any other secret. In production this
file would not exist; signing happens inside Privy or an HSM via
the `IdentityProvider` interface.

## 5. Capture each DID in a shell variable

The walkthrough commands reference DIDs many times; we set
shell variables once so the commands stay short and copy-pastable:

```bash
CLERK=$(jq -r '.did' clerk-brown.key.json)
COOPER=$(jq -r '.did' cooper.key.json)
DAVIS=$(jq -r '.did' davis.key.json)
ADAMS=$(jq -r '.did' judge-adams.key.json)
EDWARDS=$(jq -r '.did' justice-edwards.key.json)

echo "$CLERK"
echo "$COOPER"
# ...
```

Need `jq`? `apt install jq` / `brew install jq` / your package
manager. If you don't have `jq`, `python -c "import json,sys;
print(json.load(open('clerk-brown.key.json'))['did'])"` works
identically.

## 6. Verify a key roundtrips through the SDK

This is optional but reassuring on first run. From the JN repo:

```bash
cd ~/ortholog/jn
go test ./cmd/judicial-cli/ -run TestKeygen_Roundtrip -v
```

Expected output ends with `--- PASS: TestKeygen_Roundtrip`. The test
mints a fresh DID, parses it back through `did.ParseDIDKey`,
recovers the compressed pubkey, and compares byte-for-byte to the
file. If this passes, every key you minted will sign cleanly.

## 7. What's NOT happening yet

- No HTTP request has been issued to either operator.
- No entry is on the log.
- No DID has any *role* assigned (e.g., `clerk` for
  `clerk-brown.key.json`). DIDs are just public-key identifiers; the
  judicial-network's role catalog and authority resolver bind a DID
  to a role inside an institutional context. In the production path
  that binding happens via a `JudicialDelegationPayload` entry on
  the log; in the walkthrough we'll show that step explicitly in
  Case 1 (CJ assigns Adams to the trial).

## 8. Recap

| You have | Where |
|---|---|
| 5 secp256k1 keypairs as JSON files | `~/ortholog/keys/*.key.json` |
| 5 `did:key` identifiers in shell vars | `$CLERK`, `$COOPER`, `$DAVIS`, `$ADAMS`, `$EDWARDS` |
| 0 entries on either log | confirm with `curl -fsS $DAVIDSON/v1/tree/head` |

Now we make something happen.

Choose your case:

- **Case 1: ACME Industries v. Beta Corp** —
  [cases/01-acme-v-beta.md](cases/01-acme-v-beta.md)
  · Civil contract dispute, trial on Davidson, appeal to COA.
  Cross-exchange composition.
- **Case 2: In re Anderson** —
  [cases/02-in-re-anderson.md](cases/02-in-re-anderson.md)
  · Family case with a sealed minor binding, judicial succession to
  Juvenile, and a delegation revocation.
