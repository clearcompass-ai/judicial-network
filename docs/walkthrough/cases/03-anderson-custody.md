# Case 3 · *In re Anderson Custody* — Family → Juvenile referral

## Background

Maya and David Anderson are divorcing. Custody of their 9-year-old
child (sealed) is contested. Mid-case, allegations surface that
require a juvenile-court inquiry; Family Judge Lewis succeeds part of
the case to Juvenile Magistrate Owens. Later the original mediation
delegation is revoked when mediation fails.

This case showcases the **judicial succession + revocation** path
(rare in production but critical to log integrity) and the **sealed
minor** binding pattern.

## Cast (7 actors)

| DID | Role | Side |
|---|---|---|
| `did:key:zQ3sh-clerk-brown` | court_clerk | Davidson |
| `did:key:zQ3sh-cj-roberts` | chief_judge | Davidson |
| `did:key:zQ3sh-judge-lewis` | judge | Davidson Family Division |
| `did:key:zQ3sh-magistrate-owens` | magistrate | Davidson Juvenile Division |
| `did:key:zQ3sh-murphy-attorney` | attorney | Mother |
| `did:key:zQ3sh-nelson-attorney` | attorney | Father |
| `did:key:zQ3sh-mediator-quinn` | mediator | Court-appointed (later revoked) |

The minor is bound via `PartyBindingSealedPayload` — never appears as
a signer, identity encrypted to the family-division vendor.

## Timeline

```
2024-05-10  Clerk files FamilyCasePayload (divorce + custody)            → trial:1
2024-05-10  Clerk files PartyBindingSealedPayload (minor)                → trial:2
2024-05-12  Murphy files CounselAppearancePayload (for mother)           → trial:3
2024-05-12  Nelson files CounselAppearancePayload (for father)           → trial:4
2024-05-15  CJ Roberts issues JudicialDelegationPayload (→ Quinn med.)   → trial:5
2024-06-20  Allegations surface → file JuvenileCasePayload               → trial:6
2024-06-22  Lewis succeeds custody portion to Owens                      → trial:7
                (JudicialSuccessionPayload, inheritance="narrowed")
2024-07-15  Mediation fails → CJ Roberts revokes Quinn's delegation     → trial:8
                (JudicialRevocationPayload)
```

## Step 0 — Setup

```go
func TestCase_AndersonCustody(t *testing.T) {
    f := newFixture(t)
    ctx := context.Background()

    clerkDID    := f.provisionKey(t, "did:key:zQ3sh-clerk-brown")
    cjDID       := f.provisionKey(t, "did:key:zQ3sh-cj-roberts")
    lewisDID    := f.provisionKey(t, "did:key:zQ3sh-judge-lewis")
    owensDID    := f.provisionKey(t, "did:key:zQ3sh-magistrate-owens")
    murphyDID   := f.provisionKey(t, "did:key:zQ3sh-murphy-attorney")
    nelsonDID   := f.provisionKey(t, "did:key:zQ3sh-nelson-attorney")
    quinnDID    := f.provisionKey(t, "did:key:zQ3sh-mediator-quinn")

    f.roleResolver.Bind(cjDID,     "chief_judge", f.institutionalDID)
    f.roleResolver.Bind(lewisDID,  "judge",       f.institutionalDID)
    f.roleResolver.Bind(murphyDID, "attorney",    f.institutionalDID)
    f.roleResolver.Bind(nelsonDID, "attorney",    f.institutionalDID)
```

## Step 1 — Family case filing (`FamilyCasePayload`)

Schema: `schemas/family_case.go:31` / `:79`.

```go
    fam := &schemas.FamilyCasePayload{
        DocketNumber: "2024-FAM-003",
        CaseType:     "divorce",
        CaseSubType:  "contested_custody",
        FiledDate:    "2024-05-10",
        Status:       "active",
    }
    fBytes, _ := schemas.SerializeFamilyCasePayload(fam)
    casePos := submitWithCosigner(t, f, clerkDID, murphyDID, fBytes,
        "File 2024-FAM-003 In re Anderson")
```

## Step 2 — Sealed minor binding (`PartyBindingSealedPayload`)

Schema: `schemas/party_binding_sealed.go:17` / `:55`.

The minor child's identity is encrypted to the family-court vendor
(typically the county clerk's office under TN code §36-1-125).

```go
    minorBind := &schemas.PartyBindingSealedPayload{
        VendorDID:                "did:web:state:tn:davidson:family-vendor",
        CaseRef:                  fam.DocketNumber,
        Role:                     "minor_subject",
        Status:                   "active",
        ArtifactEncryption:       "umbral_pre",
        GrantAuthorizationMode:   "sealed",
        GrantEntryRequired:       true,
        GrantRequiresAuditEntry:  true,
        EncryptedMappingCID:      "bafy...minor",
        BindingID:                "minor-anderson-001",
    }
    mBytes, _ := schemas.SerializePartyBindingSealedPayload(minorBind)
    submitWithCosigner(t, f, clerkDID, murphyDID, mBytes,
        "Bind sealed minor in 2024-FAM-003")
```

## Step 3 — Counsel appearances (`CounselAppearancePayload` ×2)

```go
    murphyApp := &schemas.CounselAppearancePayload{
        AppearanceID: "ap-murphy-001",
        AttorneyDID:  murphyDID,
        Represents:   []string{"mother-anderson-binding"},
        CaseRef:      fam.DocketNumber,
        CaseSeq:      casePos.Sequence,
        FiledDate:    "2024-05-12",
        Status:       "active",
    }
    mABytes, _ := schemas.SerializeCounselAppearancePayload(murphyApp)
    submitWithCosigner(t, f, murphyDID, clerkDID, mABytes,
        "Murphy appears for mother")

    nelsonApp := &schemas.CounselAppearancePayload{
        AppearanceID: "ap-nelson-001",
        AttorneyDID:  nelsonDID,
        Represents:   []string{"father-anderson-binding"},
        CaseRef:      fam.DocketNumber,
        CaseSeq:      casePos.Sequence,
        FiledDate:    "2024-05-12",
        Status:       "active",
    }
    nABytes, _ := schemas.SerializeCounselAppearancePayload(nelsonApp)
    submitWithCosigner(t, f, nelsonDID, clerkDID, nABytes,
        "Nelson appears for father")
```

## Step 4 — Mediator delegation

CJ Roberts assigns court-appointed mediator Quinn for a 60-day window.
Uses the existing `delegation.Issue` path:

```go
    mediatorPos := f.issue(t, delegation.IssueRequest{
        GranterDID:   cjDID,
        GranteeDID:   quinnDID,
        GranteeRole:  "mediator",
        Scope:        []string{fam.DocketNumber, "mediation_only"},
        DurationDays: 60,
        Rationale:    "Court-appointed mediation per TN R.S.Ct. 31",
    })
    // mediatorPos = {LogDID: davidson, Sequence: 5}
```

## Step 5 — Juvenile case filing (`JuvenileCasePayload`)

Schema: `schemas/juvenile_case.go:35` / `:90`.

Allegations require a juvenile-court inquiry. The case opens as a
companion docket (with `auto_seal_at_disposition = true`):

```go
    juv := &schemas.JuvenileCasePayload{
        DocketNumber:           "2024-JUV-004",
        CaseType:               "dependency_inquiry",
        FiledDate:              "2024-06-20",
        Status:                 "active",
        AutoSealAuthority:      "TN-37-1-153",
        AutoSealAtDisposition:  true,
    }
    jBytes, _ := schemas.SerializeJuvenileCasePayload(juv)
    submitWithCosigner(t, f, clerkDID, lewisDID, jBytes,
        "Open companion juvenile inquiry on 2024-FAM-003")
```

## Step 6 — Judicial succession (`JudicialSuccessionPayload`)

Schema: `schemas/judicial_amendments.go:48`.

Lewis succeeds the custody portion of the case to Magistrate Owens.
This is a **narrowed** succession — Lewis keeps the divorce-decree
authority; Owens takes only the custody scope. Use
`delegation.Succeed` (`delegation/succession.go:99`).

```go
    succReq := delegation.SuccessionRequest{
        SignerDID:        lewisDID,
        TargetDelegation: schemas.LogPositionRef{
            LogDID:   f.logDID,
            Sequence: mediatorPos.Sequence,  // succeeding from mediator slot
        },
        SuccessorDID:  owensDID,
        Reason:        "Allegations require juvenile-court oversight; transfer custody portion only.",
        Inheritance:   "narrowed",
        NarrowedScope: []string{"2024-JUV-004"},  // Owens authorized only on juvenile docket
    }
    succRes, err := delegation.Succeed(ctx, f.buildCtx, succReq)
    must(t, err)
    f.roleResolver.Bind(owensDID, "magistrate", f.institutionalDID)
```

## Step 7 — Mediator revocation (`JudicialRevocationPayload`)

Schema: `schemas/judicial_amendments.go:28`.

Mediation fails after 25 days. CJ Roberts revokes Quinn's delegation
to free the slot. Use `delegation.Revoke`
(`delegation/revoke.go:86`):

```go
    revReq := delegation.RevokeRequest{
        GranterDID:       cjDID,
        TargetDelegation: mediatorPos, // the LogPositionRef from Step 4
        Reason:           "Mediation impasse declared 2024-07-15; case proceeds to litigated custody.",
    }
    revRes, err := delegation.Revoke(ctx, f.buildCtx, revReq)
    must(t, err)
    // revRes.Position = {LogDID: davidson, Sequence: 8}
}
```

## Verification

```go
    // davidson tip = 8: case=1, minor=2, murphyApp=3, nelsonApp=4,
    // mediator=5, juvCase=6, succession=7, revocation=8.
```

## Why both succession AND revocation in one case?

- **Succession** (`JudicialSuccessionPayload`) — Lewis was a sitting
  judge with active authority over the custody scope; she **transferred**
  that authority to Owens. The case continues; only the responsible
  judicial officer changed.
- **Revocation** (`JudicialRevocationPayload`) — Quinn's mediator
  delegation is **terminated** without a successor. The slot closes;
  the case proceeds without a mediator.

Both write to the log immutably. Subsequent authority queries against
either delegation return the appropriate state via the
`AuthorityResolver` walking the chain (see
`verification/delegation_chain.go`).

## Helper used in this file

Same `submitWithCosigner` and `must` from cases 1 and 2.

## Events covered

`FamilyCasePayload` ✓ · `JuvenileCasePayload` ✓ ·
`PartyBindingSealedPayload` ✓ · `CounselAppearancePayload` ✓×2 ·
`JudicialDelegationPayload` ✓ (mediator) · `JudicialSuccessionPayload` ✓ ·
`JudicialRevocationPayload` ✓
