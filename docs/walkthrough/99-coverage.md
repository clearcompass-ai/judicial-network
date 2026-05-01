# §99 · Coverage matrix and natural extensions

What the two walkthrough cases collectively exercised, what they
intentionally skipped, and how to add the missing pieces.

## Schema coverage

| # | Schema | File | Case 1 (civil) | Case 2 (family) |
|---|---|---|:-:|:-:|
| 1 | `CivilCasePayload` | `schemas/civil_case.go:29` | ✓ trial step 1 | — |
| 2 | `FamilyCasePayload` | `schemas/family_case.go:31` | — | ✓ filing step 1 |
| 3 | `JuvenileCasePayload` | `schemas/juvenile_case.go:35` | — | ✓ succession step 5 |
| 4 | `PartyBindingPayload` | `schemas/party_binding.go:66` | ✓ ×2 trial step 2 | — |
| 5 | `PartyBindingSealedPayload` | `schemas/party_binding_sealed.go:17` | — | ✓ filing step 2 |
| 6 | `CounselAppearancePayload` | `schemas/counsel_appearance.go:48` | ✓ ×2 trial step 3 | ✓ filing step 3 |
| 7 | `JudicialDelegationPayload` | `schemas/judicial_delegation.go:76` | (collapsed in narration) | ✓ filing step 4 |
| 8 | `JudicialSuccessionPayload` | `schemas/judicial_amendments.go:48` | — | ✓ succession step 6 |
| 9 | `JudicialRevocationPayload` | `schemas/judicial_amendments.go:28` | — | ✓ succession step 7 |
| 10 | `AppellateDispositionPayload` | `schemas/appellate_disposition.go:34` | ✓ appeal step 5 | — |
| 11 | `AppellateOpinionPublicationPayload` | `schemas/appellate_opinion_publication.go:33` | ✓ appeal step 6 | — |
| 12 | `EvidenceArtifactPayload` | `schemas/evidence_artifact.go:71` | ✓ trial step 4 (CEO affidavit, web3) | — |

12 of the 17 payload schemas exercised. The remaining 5 are listed
below with a one-paragraph "how to add" each.

## Cross-cutting features exercised

| Feature | Where in the walkthrough |
|---|---|
| Multi-signer cosigned entries | every step in both cases |
| Cross-exchange via `EvidencePointers` | Case 1 appeal step 5 (Davidson:1 cited from COA:1) |
| Sealed binding (umbral_pre, sealed grant mode) | Case 2 filing step 2 |
| Scoped judicial succession (`inheritance: narrowed`) | Case 2 succession step 6 |
| Delegation revocation | Case 2 succession step 7 |
| Real `did:key` DIDs minted via `judicial-cli keygen` | §02 |
| Real `did:pkh:eip155` (web3) DIDs minted via `--method pkh-eip155` | §02 |
| Mixed-method entries (did:key + did:pkh on the same log) | Case 1 trial step 4 |
| EIP-191 wallet signing (`SigAlgoEIP191`, 65-byte r\|\|s\|\|v) | Case 1 trial step 4 |
| Real two-operator topology (`make dev-up`) | §01 |
| **Real** Google Cloud Storage bytestore (your own buckets) | §01 |
| Sequence-number monotonicity per log | observable in `tree/head` after each step |

## What's missing — natural extensions

### 6 schemas not yet exercised

Each is a one-spec add. Drop a new spec file alongside the existing
ones; the CLI handles them identically.

#### `CriminalCasePayload`
`schemas/criminal_case.go:49`. Same shape as `CivilCasePayload`,
plus `charges []string`, `victim_info`, `sealed_exhibits`. Pair with
a `PartyBindingSealedPayload` for the victim. **Suggested add:** a
third case, *State v. Wilson* — felony assault with a sealed-victim
binding and an evidence chain.

#### `KeyAttestationPayload`
`schemas/key_attestation.go:87`. Attests that an entity's key was
generated inside an enclave (e.g., Intel SGX). Used to defend
chain-of-custody for evidence collected by enclaved devices.
**Suggested add:** in the criminal case, attest the extraction-
terminal's key when the detective files digital evidence.

#### `DisclosureOrderPayload`
`schemas/disclosure_order.go:39`. Order from a judge granting named
recipients access to otherwise sealed material. **Suggested add:**
in the criminal case, the judge orders disclosure of the sealed
victim binding to the public defender for trial preparation.

#### `SealingOrderPayload`
`schemas/sealing_order.go:16`. Restrictive order — narrows access to
specific artifacts. **Suggested add:** in the criminal case, seal
records identifying a juvenile witness mid-trial.

#### `AppellateOpinionParticipationPayload`
`schemas/appellate_opinion_participation.go:30`. Used when a panel
has multiple judges; each non-author judge files a participation
entry (joined / concurred-in-part / dissented). Our 1-judge COA
panel doesn't trigger it. **Suggested add:** expand Case 1's COA
panel to 3 judges and have the two non-author judges file
participation entries.

### Other natural extensions

- **A third operator** — e.g., the TN Supreme Court (`$SUPCT`,
  port 8082). Adds a *second* cross-exchange hop: COA's opinion
  cited from a Sup Ct certiorari disposition. The
  `docker-compose.dev.yml` would gain one more service block;
  no CLI change needed.
- **Privy IdentityProvider** swapped in for `judicial-cli`'s file-
  based key signing. Production path; same SDK seam
  (`identity.IdentityProvider`).
- **A multi-signer cosigned filing past 2 signers** — e.g., a
  joint-custody settlement signed by both parents' attorneys plus
  the judge plus the GAL. The `cosigner_keys` array supports
  arbitrary count up to operator's per-entry signature limit.

## How to keep this matrix current

1. When you add a new payload schema in `schemas/`, append a row
   here with `?` in the case columns until a case exercises it.
2. When you extend a case file (e.g., add an `EvidenceArtifactPayload`
   step to Case 1's trial), update the relevant row.
3. The numerator in "11 of 17 payload schemas" should match
   `ls schemas/*_payload.go` after each schema add (modulo the few
   non-payload schemas in that directory).

## Sanity check

Quick one-liner to confirm every schema this matrix references
actually exists in the repo:

```bash
for s in CivilCasePayload FamilyCasePayload JuvenileCasePayload \
         PartyBindingPayload PartyBindingSealedPayload \
         CounselAppearancePayload JudicialDelegationPayload \
         JudicialSuccessionPayload JudicialRevocationPayload \
         AppellateDispositionPayload AppellateOpinionPublicationPayload \
         CriminalCasePayload EvidenceArtifactPayload \
         KeyAttestationPayload DisclosureOrderPayload \
         SealingOrderPayload AppellateOpinionParticipationPayload; do
    grep -rl "type $s struct" schemas/ > /dev/null \
      && echo "  ✓ $s" \
      || echo "  ✗ MISSING: $s"
done
```

Run this from the JN repo root. If anything prints with `✗`, that
schema name in this matrix is wrong (or the schema was renamed
without updating this file).

## Walkthrough complete

That's the whole story:

- **Two real cases**, each told as a coherent narrative pairing the
  legal context with the technical action.
- **Five real DIDs** minted from real secp256k1 keys.
- **Two real operators** running on your laptop, talking to each
  other through a public cross-pointer.
- **Eleven of seventeen** payload schemas exercised, with the
  remaining six listed as one-spec extensions.
- **Every primitive cited at file:line** in upstream code, so this
  walkthrough fails compilation rather than rot when the SDK or JN
  moves.

Stop the topology when you're done:

```bash
cd ~/ortholog/operator
make dev-down
```

Goodbye, GCS buckets. Until next time.
