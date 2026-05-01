# 02 · Fixture and Actors

The walkthrough's three cases all use the same in-memory test fixture
and a shared cast of characters. This file establishes both. Read once,
then jump to any case.

## The `contractFixture`

Defined at `tests/contracts/delegation_helpers_test.go:121-137`. The
fixture wires every dependency a real operator would have, but every
backend is in-memory:

```go
type contractFixture struct {
    logDID           string                       // "did:web:state:tn:davidson"
    exchangeDID      string                       // same
    institutionalDID string                       // same

    identity     *identity.StubProvider           // signing backend (in-memory)
    operator     *operatorBackend                 // submitter + fetcher
    leafs        *leafBackend                     // synthetic SMT leaves
    catalog      schemas.RoleCatalog              // davidson.MustRoleCatalog()
    roleResolver *verification.MapRoleResolver
    resolver     *verification.AuthorityResolver
    buildCtx     *delegation.BuildContext

    keys map[string]*secp256k1.PrivateKey         // generated keys per DID
}
```

Constructed via `newFixture(t)` at line 139. Each test gets a fresh
fixture; nothing leaks across tests.

### What each backend does

- **`operatorBackend`** (`delegation_helpers_test.go:50-87`) implements
  both `delegation.OperatorSubmitter` (`SubmitCanonical`) and the
  SDK's `types.EntryFetcher` (`Fetch`). Stores canonical bytes in
  `bySeq map[uint64][]byte`, hands out monotonically-increasing
  sequence numbers.
- **`leafBackend`** (`delegation_helpers_test.go:91-114`) implements
  `types.LeafReader`. Used by succession and revocation tests to
  return synthetic SMT tip pointers without a real Merkle tree.
- **`identity.StubProvider`** (`api/exchange/identity/privy_stub.go`)
  implements the same `IdentityProvider` interface as Privy: maps
  DIDs to secp256k1 private keys, signs digests, returns public keys.

### Provisioning a key for an actor

```go
// delegation_helpers_test.go:182
func (f *contractFixture) provisionKey(t *testing.T, did string) string {
    priv, err := secp256k1.GeneratePrivateKey()
    if err != nil { t.Fatalf(...) }
    f.keys[did] = priv
    f.identity.BindKey(did, priv)
    return did
}
```

Usage:

```go
f := newFixture(t)
clerkDID := f.provisionKey(t, "did:key:zQ3sh-clerk-brown")
```

After this, `f.identity.SignDigest(ctx, SignRequest{SignerDID: clerkDID, ...})`
returns a real secp256k1 signature using the generated key. The DID
string is arbitrary; the binding is what makes signing work.

### Submitting a delegation entry

```go
// delegation_helpers_test.go:196
func (f *contractFixture) issue(t *testing.T, req delegation.IssueRequest) schemas.LogPositionRef {
    res, err := delegation.Issue(context.Background(), f.buildCtx, req)
    if err != nil { t.Fatalf(...) }
    f.roleResolver.Bind(req.GranteeDID, req.GranteeRole, f.institutionalDID)
    return res.Position
}
```

For each delegation the helper also binds the new grantee in the role
resolver — that wires `(did, role, exchange)` so cosignature checks can
look up the role for any signer DID.

### Reading an entry back

```go
// delegation_helpers_test.go:214
func (f *contractFixture) envelopeAt(t *testing.T, pos schemas.LogPositionRef) *envelope.Entry {
    meta, err := f.operator.Fetch(types.LogPosition{LogDID: pos.LogDID, Sequence: pos.Sequence})
    // ... deserialize meta.CanonicalBytes via envelope.Deserialize
    return e
}
```

## How a case-payload entry gets onto the log

The fixture's `f.issue()` and the public `delegation.SignAndSubmitCosigned`
cover delegation entries and cosigned arbitrary entries respectively.
For the walkthrough cases, every event has at least 2 signers
(realistic court flows always do — clerk + attorney, ADA + PD + judge,
etc.), so `SignAndSubmitCosigned` covers everything:

```go
// delegation/cosigned.go:98 — exported, multi-signer aware
pos, err := delegation.SignAndSubmitCosigned(
    ctx,
    f.buildCtx,
    entry,                           // *envelope.Entry (unsigned)
    display,                         // *identity.TypedDataDisplay
    "Filing motion_continuance",     // human-readable reason
    []string{cosigner1, cosigner2},  // additional signers
)
```

The entry's `Header.SignerDID` is the **primary signer** (Signatures[0]).
The cosigners list adds Signatures[1..N].

## The cast across all three cases

Every actor uses a `did:key:zQ3sh-*` DID for readability. The fixture's
`provisionKey(t, did)` generates a real secp256k1 key behind each DID,
so all signatures are cryptographically valid.

| DID alias | Role | Used in case(s) | Notes |
|---|---|---|---|
| `did:key:zQ3sh-judge-adams` | judge (Davidson trial) | 1, 2 | Civil + Criminal docket |
| `did:key:zQ3sh-judge-lewis` | judge (Davidson family) | 3 | Family division |
| `did:key:zQ3sh-magistrate-owens` | magistrate (Davidson juvenile) | 3 | Receives juvenile referral |
| `did:key:zQ3sh-cj-roberts` | chief_judge (Davidson) | 1 | Issues judicial assignments |
| `did:key:zQ3sh-clerk-brown` | court_clerk (Davidson) | 1, 2, 3 | Files all initial entries |
| `did:key:zQ3sh-justice-edwards` | justice (TN COA) | 1 | Authors appellate opinion |
| `did:key:zQ3sh-justice-foster-coa` | justice (TN COA) | 1 | Joins opinion (panel of 3) |
| `did:key:zQ3sh-justice-grant-coa` | justice (TN COA) | 1 | Concurs in opinion |
| `did:key:zQ3sh-cooper-attorney` | attorney (plaintiff) | 1 | Smith counsel |
| `did:key:zQ3sh-davis-attorney` | attorney (defense) | 1 | Johnson counsel |
| `did:key:zQ3sh-foster-ada` | attorney (state) | 2 | ADA in *State v. Wilson* |
| `did:key:zQ3sh-garcia-pd` | attorney (defense) | 2 | Public Defender |
| `did:key:zQ3sh-murphy-attorney` | attorney (mother) | 3 | Anderson custody |
| `did:key:zQ3sh-nelson-attorney` | attorney (father) | 3 | Anderson custody |
| `did:key:zQ3sh-detective-martinez` | law_enforcement | 2 | Files evidence |

Parties (Smith, Johnson, Wilson, Howard the witness, Mother/Father
Anderson, the minor) are bound via `PartyBindingPayload` /
`PartyBindingSealedPayload` — they are bound but generally do not sign
court entries directly.

## Institutional DIDs

The walkthrough's three cases span three exchanges:

| Exchange | DID | Bundle composer |
|---|---|---|
| Davidson County (trial, family, juvenile) | `did:web:state:tn:davidson` | `deployments/tn/counties/davidson/bundle.go` |
| TN Court of Appeals | `did:web:state:tn:coa` | `deployments/tn/coa/bundle.go` |
| TN Supreme Court | `did:web:state:tn:sup` | `deployments/tn/sup_ct/bundle.go` |

The fixture sets `institutionalDID = "did:web:state:tn:davidson"` by
default. Cases that span multiple exchanges (e.g., an appeal in case 1)
construct a second fixture for the COA exchange, demonstrating
cross-exchange entry flow.

## What a typical scenario step looks like

In every case file you'll see this shape repeatedly:

```go
// 1) Build payload from the right schema
p := &schemas.CivilCasePayload{
    DocketNumber: "2024-CV-001",
    CaseType:     "contract",
    FiledDate:    "2024-01-15",
    Status:       "active",
}
payloadBytes, err := schemas.SerializeCivilCasePayload(p)

// 2) Wrap in unsigned entry
auth := envelope.AuthoritySameSigner
header := envelope.ControlHeader{
    Destination: "did:web:state:tn:davidson",
    SignerDID:   clerkDID,
    AuthorityPath: &auth,
}
entry, err := envelope.NewUnsignedEntry(header, payloadBytes)

// 3) Sign + submit (cosigned with attorney)
display := &identity.TypedDataDisplay{ /* ... */ }
pos, err := delegation.SignAndSubmitCosigned(
    ctx, f.buildCtx, entry, display,
    "Filing 2024-CV-001 Smith v. Johnson",
    []string{cooperAttorneyDID},
)

// 4) Verify it's on the log
got := f.envelopeAt(t, pos)
require.Equal(t, clerkDID, got.Header.SignerDID)
require.Equal(t, 2, len(got.Signatures))
```

That's the whole pattern. Now jump to a case.

## Where to next

- **[cases/01-smith-v-johnson.md](cases/01-smith-v-johnson.md)** — Civil
- **[cases/02-state-v-wilson.md](cases/02-state-v-wilson.md)** — Criminal
- **[cases/03-anderson-custody.md](cases/03-anderson-custody.md)** — Family
