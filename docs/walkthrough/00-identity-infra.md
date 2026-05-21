# §00 · Identity Infra (Step 0 — every walkthrough starts here)

One command provisions every actor's identity; every case (`cases/*`) then
just *uses* those identities. Run it once, source the manifest, drive any case.

```bash
make identity            # or: ./scripts/identity.sh
. .run/identities/manifest.env
```

## The model (one method, three roles)
To the JN, every actor is the **same method — a `did:pkh` EOA** — verified
**pure-CPU** (EIP-191 / EIP-712 `ecrecover`, `did/verifier_batch.go`), **zero
RPC**, wallet- and chain-agnostic. Roles differ only in *who issues the key*:

| Role | Identity | Issued by (prod) | Local (this infra) |
|---|---|---|---|
| Court / log / destination | `did:web:state:tn:*` | the court domain (signs tree heads) | compiled-in; not minted |
| Officers (judge, clerk, justice) | `did:pkh` EOA | **court SSO → embedded wallet** (Privy/Web3Auth/…), role-bound on-log | `judicial-cli keygen` |
| External parties (attorneys, CEO/CFO) | `did:pkh` EOA | **any wallet** (MetaMask/Coinbase/WalletConnect) | `judicial-cli keygen` |

"Support 3-5 providers" is **free**: the JN verifies the signature, not the
wallet brand. Adding/removing a provider is a client-app change (EIP-1193 +
wagmi), never a JN change. EIP-1271 smart-contract wallets are a separate
appendix (rare corporate/treasury acts; the only path that touches an RPC).

## What you get (the manifest)
`.run/identities/manifest.env` — sourceable by any case:
- `COURT_DID`, `TLS_CA`, `TLS_SERVER_CERT/KEY`
- per actor: `<ACTOR>_DID`, `<ACTOR>_KEY` (signing key file), `<ACTOR>_CERT/_CERT_KEY` (mTLS client cert whose `did:` URI SAN = the actor — for JN API access; zero-trust, no no-auth path).

Default roster covers Case 1 and is reusable; override with
`ACTORS="name:method:chain …" make identity`.

## Signing — local vs production (same DID, same verification)
- **Local walkthrough:** `judicial-cli submit` signs with the key file → `SigAlgoEIP191`.
- **Production:** the *same* `did:pkh` signs in the wallet via `eth_signTypedData_v4` (EIP-712, readable order) → `SigAlgoEIP712`. UX differs; the verification path is identical (pure-CPU `ecrecover` against the `did:pkh` address).

## The core pattern: judge signs the order, clerk attests
A judicial order is a **multi-signer** entry:
- **Judge = primary** (`Signatures[0]`, `Header.SignerDID = $JUDGE_ADAMS_DID`).
- **Clerk = co-signer/attestation** (`Signatures[1] = $CLERK_BROWN_DID`).
- The jurisdiction's **cosignature/attestation policy** *requires* the clerk attestation (`verification/cosignature_check.go`, `attestation_check.go`, `policy/cosignature_mix.go`) — an order missing it is **rejected**. The "ensure" is policy, not workflow discipline.

## What the JN verifies (three layers)
1. **Crypto identity** — the signature recovers to the address in the `did:pkh` (that exact wallet/SSO account signed). Pure-CPU.
2. **Authority** — that `did:pkh` holds the **on-log-delegated** judicial role (`verification/delegation_resolver_ledger.go`, `authority_resolver.go`). Local projection, no network.
3. **Policy** — the judge-primary + clerk-attestation rule is satisfied.

## Then run any case
Every `cases/*` walkthrough assumes Step 0 has run and the manifest is
sourced. It uses `$<ACTOR>_DID` / `$<ACTOR>_KEY` to sign entries and
`$<ACTOR>_CERT` to call the JN API. Nothing in a case re-mints identities —
they all share this infra.

Next: bring up the stack (**[§01](01-environment.md)**), then a case (**[Case 1](cases/01-acme-v-beta.md)**).
