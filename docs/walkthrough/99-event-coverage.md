# 99 · Event Coverage Matrix

This page proves the three walkthrough cases collectively touch **every
payload schema** the system defines. Use it as an audit checklist when
adding new cases or new schemas.

## Schema → Case mapping

| # | Schema | File | Case 1 *Smith v. Johnson* | Case 2 *State v. Wilson* | Case 3 *Anderson Custody* |
|---|---|---|:-:|:-:|:-:|
| 1 | `CivilCasePayload` | `schemas/civil_case.go:29` | ✓ Step 1 | — | — |
| 2 | `CriminalCasePayload` | `schemas/criminal_case.go:49` | — | ✓ Step 1 | — |
| 3 | `FamilyCasePayload` | `schemas/family_case.go:31` | — | — | ✓ Step 1 |
| 4 | `JuvenileCasePayload` | `schemas/juvenile_case.go:35` | — | — | ✓ Step 5 |
| 5 | `PartyBindingPayload` | `schemas/party_binding.go:66` | ✓ Step 2 (×2) | — | — |
| 6 | `PartyBindingSealedPayload` | `schemas/party_binding_sealed.go:17` | — | ✓ Step 2 (victim) | ✓ Step 2 (minor) |
| 7 | `CounselAppearancePayload` | `schemas/counsel_appearance.go:48` | ✓ Step 3 (×2) | ✓ Step 3 (×2) | ✓ Step 3 (×2) |
| 8 | `JudicialDelegationPayload` | `schemas/judicial_delegation.go:76` | ✓ Step 4 (judge) | — | ✓ Step 4 (mediator) |
| 9 | `JudicialSuccessionPayload` | `schemas/judicial_amendments.go:48` | — | — | ✓ Step 6 |
| 10 | `JudicialRevocationPayload` | `schemas/judicial_amendments.go:28` | — | — | ✓ Step 7 |
| 11 | `EvidenceArtifactPayload` | `schemas/evidence_artifact.go:71` | ✓ Step 5 | ✓ Step 5 (sealed) | — |
| 12 | `KeyAttestationPayload` | `schemas/key_attestation.go:87` | — | ✓ Step 6 | — |
| 13 | `DisclosureOrderPayload` | `schemas/disclosure_order.go:39` | — | ✓ Step 4 | — |
| 14 | `SealingOrderPayload` | `schemas/sealing_order.go:16` | — | ✓ Step 7 | — |
| 15 | `AppellateDispositionPayload` | `schemas/appellate_disposition.go:34` | ✓ Step 7 | — | — |
| 16 | `AppellateOpinionPublicationPayload` | `schemas/appellate_opinion_publication.go:33` | ✓ Step 8 | — | — |
| 17 | `AppellateOpinionParticipationPayload` | `schemas/appellate_opinion_participation.go:30` | ✓ Step 9 | — | — |

**Total**: 17 / 17 payloads exercised across the three cases.

## Cross-cutting features exercised

| Feature | Where |
|---|---|
| Multi-signer entries (cosigned) | Every step in every case |
| Cross-exchange flow (Davidson → COA) | Case 1 Steps 6-9 |
| Sealed party bindings | Cases 2 + 3 |
| Authority delegation (issue) | Cases 1 + 3 |
| Authority succession (narrowed) | Case 3 Step 6 |
| Authority revocation | Case 3 Step 7 |
| Evidence chain-of-custody | Case 2 Steps 5-6 |
| Key attestation (enclave) | Case 2 Step 6 |
| Disclosure-then-seal interaction | Case 2 Steps 4 + 7 |
| Sequence-number monotonicity per log | Verification step in each case |

## SDK seam features exercised

| Feature | Where |
|---|---|
| `envelope.NewUnsignedEntry` | `submitWithCosigner` helper |
| `envelope.SigningPayload` (via `delegation.SignAndSubmitCosigned`) | Every step |
| `envelope.Serialize` (via `delegation.signAndSubmit*`) | Every step |
| `envelope.Deserialize` (via `f.envelopeAt`) | Verification |
| Multi-signature attachment | Every step |
| `did:web` destination binding | Case 1 (cross-exchange) |
| `secp256k1` signing via `identity.StubProvider` | Every step |
| `identity.TypedDataDisplay` | Every step |

## Composer (Bundle) coverage

| Bundle | Where used |
|---|---|
| `deployments/tn/counties/davidson/bundle.go` (trial) | Cases 1, 2, 3 (default fixture) |
| `deployments/tn/coa/bundle.go` | Case 1 Step 6+ |
| `deployments/tn/sup_ct/bundle.go` | — (not used; reserved for future Sup Ct review case) |
| `deployments/tn/trial/` (shared TN trial framework) | Indirectly via Davidson bundle |
| `internal/testfixtures/davidsonlegacy/` (6-role catalog) | — (not used; legacy test depth) |

## Coverage gaps to add (next-pass cases)

These are not exercised by the current three cases. A fourth case
covering Sup Ct review (e.g., *State v. Wilson* certiorari) would close
them:

| Schema / feature | Suggested case |
|---|---|
| `deployments/tn/sup_ct/` Bundle | Sup Ct review of an already-appealed case |
| Authority chain depth > 2 | Multi-step delegation: CJ → Judge → Magistrate |
| `EvidenceArtifactPayload` re-encryption grant | Disclosure-driven re-encryption flow |
| `CounselAppearance` withdrawal (`status=withdrawn`) | Mid-case attorney substitution |

## How to keep this matrix current

1. When you add a new payload type to `schemas/`, append a row here
   with `?` in the case columns until at least one case exercises it.
2. When you add a new case (e.g., `cases/04-*.md`), update the
   columns of every row your case touches.
3. The "Total" at the end of the schema table should match
   `ls schemas/*_payload.go | wc -l` (or whatever the canonical count
   becomes when the schema package is reorganized).

## Sanity check command

A rough one-liner to confirm every schema name in the matrix actually
exists in the repo:

```bash
for s in CivilCasePayload CriminalCasePayload FamilyCasePayload \
         JuvenileCasePayload PartyBindingPayload PartyBindingSealedPayload \
         CounselAppearancePayload JudicialDelegationPayload \
         JudicialSuccessionPayload JudicialRevocationPayload \
         EvidenceArtifactPayload KeyAttestationPayload \
         DisclosureOrderPayload SealingOrderPayload \
         AppellateDispositionPayload AppellateOpinionPublicationPayload \
         AppellateOpinionParticipationPayload; do
    grep -rn "type $s struct" schemas/ > /dev/null || echo "MISSING: $s"
done
```

If that prints nothing, every payload referenced in the walkthrough
exists in the codebase exactly as named.

## Going further

Once the three cases run as Go test files (a logical next step from
markdown), add a CI check that asserts:

```go
// pseudo
if numPayloadsExercised != totalPayloadsInSchemas {
    t.Errorf("walkthrough scenarios cover %d/%d schemas; add cases or remove unused payloads",
        numPayloadsExercised, totalPayloadsInSchemas)
}
```

That makes the matrix self-enforcing — a new schema without a
walkthrough case fails CI.
