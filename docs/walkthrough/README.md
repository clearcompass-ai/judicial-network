# Judicial Network — Developer Walkthrough

This walkthrough takes a developer from a clean clone of `judicial-network`
to running three end-to-end Tennessee judicial cases against the in-memory
test fixture. **No external services required** (no Postgres, no GCS, no
Privy account). Every step uses real APIs cited from the codebase.

## What you'll build

Three realistic Tennessee judicial cases that, together, exercise **every
event payload type** the system supports:

| # | Case | Court | Actors | Events touched |
|---|---|---|---|---|
| 1 | *Smith v. Johnson* | Davidson Trial → COA | 7 | `CivilCasePayload`, `PartyBindingPayload` ×2, `CounselAppearancePayload` ×2, `JudicialDelegationPayload`, `EvidenceArtifactPayload`, `AppellateDispositionPayload`, `AppellateOpinionPublicationPayload`, `AppellateOpinionParticipationPayload` |
| 2 | *State v. Wilson* | Davidson Trial | 6 | `CriminalCasePayload`, `PartyBindingSealedPayload`, `CounselAppearancePayload` ×2, `DisclosureOrderPayload`, `EvidenceArtifactPayload`, `KeyAttestationPayload`, `SealingOrderPayload` |
| 3 | *In re Anderson Custody* | Davidson Family → Juvenile | 7 | `FamilyCasePayload`, `PartyBindingSealedPayload`, `CounselAppearancePayload` ×2, `JuvenileCasePayload`, `JudicialSuccessionPayload`, `JudicialRevocationPayload` |

The full coverage matrix is in [99-event-coverage.md](99-event-coverage.md).

## Folder layout

```
docs/walkthrough/
├── README.md                          ← you are here
├── 01-setup.md                        ← clone + go test (5 min)
├── 02-fixture-and-actors.md           ← the contractFixture pattern
├── cases/
│   ├── 01-smith-v-johnson.md          ← Civil contract → appeal
│   ├── 02-state-v-wilson.md           ← Criminal felony, sealed victim
│   └── 03-anderson-custody.md         ← Family → Juvenile referral
└── 99-event-coverage.md               ← coverage matrix
```

## Read in order

1. **[01-setup.md](01-setup.md)** — Get the existing test suite green.
   Confirms your environment can build and run the fixture.
2. **[02-fixture-and-actors.md](02-fixture-and-actors.md)** — Learn the
   `contractFixture` pattern. Every case in this walkthrough composes
   the same fixture; understanding this once is enough for all three.
3. **[cases/](cases/)** — Pick any case in any order. Each is
   self-contained narrative + code + expected log output, working
   through the events progressively.
4. **[99-event-coverage.md](99-event-coverage.md)** — Confirm coverage
   when you're done.

## Why these three cases

The codebase has **17 distinct event payload types** across schemas/.
A single linear scenario can't naturally exercise all of them — civil
trial cases don't carry juvenile sealing semantics, criminal cases don't
have appellate participation entries, family cases don't typically use
DisclosureOrders the way criminal discovery does. Three cases let each
case stay realistic while collectively touching every payload.

## Code conventions used in this walkthrough

- Every code snippet is **copy-paste runnable** in a `*_test.go` file
  inside `tests/scenarios/` (or wherever you build your scenarios).
- File:line citations point at the actual API definitions — when
  payloads or builders evolve, drift will fail compilation in your
  scenario rather than in the documentation.
- Snippets prefer **real schema names** (`CivilCasePayload`,
  `JudicialSuccessionPayload`) over invented helpers. If a helper
  doesn't exist in the repo, the walkthrough composes the
  primitives that do.
- DIDs are deliberately **human-readable** in this walkthrough
  (`did:key:zQ3sh-cooper-attorney`) — not realistic encoded keys.
  The fixture binds these strings to generated secp256k1 keys via
  `provisionKey`, so the readable strings work end-to-end while the
  cryptography stays real.

## What's NOT covered

- **Privy embedded wallets**: this walkthrough uses
  `identity.StubProvider` (in-memory secp256k1). Real Privy integration
  needs an API key and is out of scope for laptop dev. The `StubProvider`
  is the same interface the production `PrivyProvider` satisfies, so
  scenario code drops in unchanged.
- **EIP-1271 smart-contract wallets** (v0.8.0): covered separately by
  `tests/contracts/smart_contract_wallet_test.go`. Walkthrough scenarios
  use EOA keys for clarity.
- **Operator deployment** (Postgres + GCS + Tessera). The walkthrough
  uses the in-memory `operatorBackend` test double which provides the
  same `OperatorSubmitter` + `EntryFetcher` interfaces.

## Status (as of writing)

- SDK: `v0.8.0` (includes EIP-1271 support)
- Branch: `claude/notice-of-appearance-event-rsEGt`
- All `tests/contracts/` tests green (82 tests)
- Walkthrough scenarios are markdown-only at this checkpoint;
  runnable `tests/scenarios/*_test.go` is a logical next step you
  can request.

Ready? Open [01-setup.md](01-setup.md).
