# Case 1 · *ACME Industries v. Beta Corp* — overview

A civil contract dispute that gets appealed. **The appeal physically
crosses operators**: the COA's appellate-disposition entry carries
an `EvidencePointers` reference back to the trial-court entry,
demonstrating the protocol's cross-exchange composition end-to-end.

The case runs in two acts. Each is its own walkthrough file:

1. **[Trial in Davidson Chancery](01-acme-v-beta-trial.md)** — filing,
   party bindings, counsel appearances, judgment for ACME (5 entries
   on the Davidson log).
2. **[Appeal to TN COA](01-acme-v-beta-appeal.md)** — cross-exchange
   disposition + opinion (2 entries on the COA log, the disposition
   pointing back to the trial-court filing).

## The story (in one paragraph)

ACME Industries delivered $1.2M of specialty steel to Beta Corp under
a fixed-price supply contract. Beta paid $400K on delivery and
refused the balance, alleging non-conforming goods. ACME sued in
Davidson County Chancery Court. After a four-day bench trial, Judge
Adams entered judgment for ACME for the full unpaid balance plus
statutory interest. Beta appealed to the Tennessee Court of Appeals,
which six months later **affirmed**.

## Why this case earns its place

It's the simplest flow that exercises the **cross-exchange seam** —
the protocol-level mechanism (`EvidencePointers`) by which one
exchange's entry can cite another's without any prior trust
relationship between the two operators. Every federated deployment
will hit this pattern; the civil-appeal flow is the cleanest
realization.

## Cast (5 actors)

| Alias | Role | Court | Used in act |
|---|---|---|---|
| `clerk-brown` | Court Clerk | Davidson | Both |
| `cooper` | Plaintiff's attorney (ACME) | Davidson | Trial |
| `davis` | Defendant's attorney (Beta) | Davidson | Trial |
| `judge-adams` | Trial Judge | Davidson | Trial (assigned by CJ; we collapse this step in narration) |
| `justice-edwards` | Appellate Justice | TN COA | Appeal |

DIDs and key files were minted in [§02](../02-real-dids.md). All
five shell variables (`$CLERK`, `$COOPER`, `$DAVIS`, `$ADAMS`,
`$EDWARDS`) should be exported.

## End state

After both acts, the logs hold:

| Log | # | Schema | Primary signer | Cosigner | Cross-ref |
|---|---|---|---|---|---|
| Davidson | 1 | `civil_case` | clerk | cooper | — |
| Davidson | 2 | `party_binding` (plaintiff) | clerk | cooper | — |
| Davidson | 3 | `party_binding` (defendant) | clerk | davis | — |
| Davidson | 4 | `counsel_appearance` (cooper) | cooper | clerk | — |
| Davidson | 5 | `counsel_appearance` (davis) | davis | clerk | — |
| COA | 1 | `appellate_disposition` | edwards | clerk | **→ Davidson:1** |
| COA | 2 | `appellate_opinion_publication` | edwards | clerk | → COA:1 |

That's the centerpiece: **COA sequence 1 carries an
`EvidencePointers` pointer at Davidson sequence 1**. Two operators
with no shared state, mediated by a single public cross-pointer.

## What's NOT in this case

- **`AppellateOpinionParticipationPayload`** — for multi-judge
  panels, each non-author judge files a participation entry. Our
  1-judge panel narrative skips it; the spec shape is a near-copy
  of `appellate_opinion_publication`.
- **Sealing / disclosure orders.** Civil contract cases are
  public by default in Tennessee. Order entries are exercised in
  Case 2's family-court flow.
- **`EvidenceArtifactPayload`.** Trial exhibits would also be on
  the log in production; we skip them here for narrative brevity.

Adding any of these to your local run is one new `judicial-cli
submit` spec file each.

## Start with the trial

Open **[01-acme-v-beta-trial.md](01-acme-v-beta-trial.md)**.
