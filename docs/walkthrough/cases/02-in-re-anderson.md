# Case 2 · *In re Anderson* — overview

A divorce + custody case where authority structure changes mid-case.
Single exchange (everything on `$DAVIDSON`), but the operations are
the most delicate the system supports: sealed binding for the minor
child, scoped judicial succession across divisions of the same
court, and a delegation revocation when mediation fails.

The case runs in two acts:

1. **[Family filing in Davidson](02-anderson-filing.md)** — open the
   case, bind the (sealed) minor, record counsel appearance, record
   the judge's delegation. Four entries.
2. **[Juvenile referral, succession, revocation](02-anderson-succession.md)**
   — open the companion juvenile case, transfer scoped authority to
   the juvenile-division magistrate, and revoke the family-court
   mediator delegation when mediation fails. Three entries.

## The story

Maya and David Anderson are divorcing in Davidson Family Court.
Custody of their 9-year-old child is contested. Three months in,
allegations surface that require juvenile-court oversight. The
family-court judge moves the juvenile portion of the case to a
juvenile-division magistrate via a `JudicialSuccessionPayload` —
the same Davidson ledger's log records that authority over the
juvenile portion has shifted, with a *narrowed* scope so the
divorce/property aspects stay with the family judge. Mediation
fails six weeks later; the mediator delegation is revoked.

## Why this case earns its place

Most courthouse documentation focuses on initial filings. This
walkthrough's value compounds when it shows what happens when
**authority itself changes mid-case**. Family law also showcases
sealed bindings: the child's identity must be on the log (so future
disposition can refer to "the child" unambiguously) but **not in
plaintext** on a public log. That's a different shape from the
public party bindings in Case 1.

## Cast (4 actors)

| Alias | Role | Court division | Used in act |
|---|---|---|---|
| `clerk-brown` | Court Clerk (reused from Case 1) | Davidson | Both |
| `judge-lewis` | Judge | Davidson Family Division | Both |
| `magistrate-owens` | Magistrate | Davidson Juvenile Division | Act II |
| `atty-murphy` | Attorney for the mother | Davidson | Act I |

In a real custody case both parents would have separate counsel and
a guardian ad litem might be appointed for the child. We narrate
with 4 actors for clarity; adding more is one extra spec each.

## Mint the three new keys

(Assumes you have `clerk-brown.key.json` from §02.)

```bash
cd ~/attesta/keys
judicial-cli keygen --out judge-lewis.key.json
judicial-cli keygen --out magistrate-owens.key.json
judicial-cli keygen --out atty-murphy.key.json

LEWIS=$(jq -r '.did' judge-lewis.key.json)
OWENS=$(jq -r '.did' magistrate-owens.key.json)
MURPHY=$(jq -r '.did' atty-murphy.key.json)
```

## End state

After both acts the Davidson log holds 7 new entries (8 if you ran
Case 1 first; the case starts fresh in either situation, just shift
the sequence numbers):

| # in case | Schema | Primary | Cosigner | Notable |
|---|---|---|---|---|
| 1 | `family_case` | clerk | murphy | — |
| 2 | `party_binding_sealed` | clerk | **lewis** | sealing authority cosigner |
| 3 | `counsel_appearance` | murphy | clerk | — |
| 4 | `judicial_delegation` | lewis | clerk | — |
| 5 | `juvenile_case` | clerk | lewis | companion docket |
| 6 | `judicial_succession` | lewis | **owens** | scoped, narrowed |
| 7 | `judicial_revocation` | lewis | clerk | mediator slot closed |

## What you'll learn

By the end of Case 2 you'll have observed:

1. A child's identity on the log **sealed** — not visible to the
   ledger, not visible to public log readers, but cited by
   subsequent custody orders by binding ID.
2. A **scoped judicial succession** moving authority for one docket
   while leaving authority for a sibling docket intact — both the
   outgoing and incoming judges signing the transfer.
3. A **revocation** closing a delegation slot with audit-visible
   reason and timestamp.

These operations are the ones courts most often get wrong on paper.
On the log, they're typed and verifiable.

## Start with Act I

Open **[02-anderson-filing.md](02-anderson-filing.md)**.
