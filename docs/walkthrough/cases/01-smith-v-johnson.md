# Case 1 · *Smith v. Johnson* — Civil contract dispute → COA appeal

## Background

ACME Industries (plaintiff Smith) sues Beta Corp (defendant Johnson)
in Davidson County Chancery Court for breach of a $1.2M supply contract.
Trial concludes with judgment for Smith. Johnson appeals to the
Tennessee Court of Appeals.

## Cast (7 actors)

| DID | Role | Side |
|---|---|---|
| `did:key:zQ3sh-clerk-brown` | court_clerk | Davidson |
| `did:key:zQ3sh-cj-roberts` | chief_judge | Davidson |
| `did:key:zQ3sh-judge-adams` | judge | Davidson (assigned) |
| `did:key:zQ3sh-cooper-attorney` | attorney | Plaintiff (Smith) |
| `did:key:zQ3sh-davis-attorney` | attorney | Defendant (Johnson) |
| `did:key:zQ3sh-justice-edwards` | justice | TN Court of Appeals (panel chair) |
| `did:key:zQ3sh-justice-foster-coa` | justice | TN COA (panel) |

## Timeline

```
2024-01-15  Clerk files CivilCasePayload                                  → trial:1
2024-01-15  Clerk binds Plaintiff (PartyBindingPayload)                  → trial:2
2024-01-15  Clerk binds Defendant (PartyBindingPayload)                  → trial:3
2024-01-16  Cooper files CounselAppearancePayload (for Smith)            → trial:4
2024-01-17  Davis files CounselAppearancePayload (for Johnson)           → trial:5
2024-02-01  CJ Roberts issues JudicialDelegationPayload (→ Adams)        → trial:6
2024-04-10  Cooper files EvidenceArtifactPayload (signed contract scan)  → trial:7
2024-08-22  Johnson appeals → COA exchange opens
2024-12-01  COA panel issues AppellateDispositionPayload                 → coa:1
2024-12-01  Edwards files AppellateOpinionPublicationPayload (majority)  → coa:2
2024-12-01  Foster files AppellateOpinionParticipationPayload (joined)   → coa:3
```

## Step 0 — Setup

```go
func TestCase_SmithVJohnson(t *testing.T) {
    f := newFixture(t)  // davidson trial fixture
    ctx := context.Background()

    clerkDID  := f.provisionKey(t, "did:key:zQ3sh-clerk-brown")
    cjDID     := f.provisionKey(t, "did:key:zQ3sh-cj-roberts")
    judgeDID  := f.provisionKey(t, "did:key:zQ3sh-judge-adams")
    cooperDID := f.provisionKey(t, "did:key:zQ3sh-cooper-attorney")
    davisDID  := f.provisionKey(t, "did:key:zQ3sh-davis-attorney")

    f.roleResolver.Bind(cooperDID, "attorney", f.institutionalDID)
    f.roleResolver.Bind(davisDID,  "attorney", f.institutionalDID)
    f.roleResolver.Bind(cjDID,     "chief_judge", f.institutionalDID)
```

(Imports: `context`, `testing`; SDK `core/envelope` + `exchange/identity`;
JN `delegation` + `schemas`. Helpers `must`, `submitWithCosigner`,
`submitCosigned` listed at end of file.)

## Step 1 — File the case (`CivilCasePayload`)

Schema: `schemas/civil_case.go:29` (struct), `:79` (`SerializeCivilCasePayload`).

```go
    civil := &schemas.CivilCasePayload{
        DocketNumber: "2024-CV-001",
        CaseType:     "contract",
        FiledDate:    "2024-01-15",
        Status:       "active",
        Plaintiff:    "ACME Industries",
        Defendant:    "Beta Corp",
        ClaimAmount:  "1200000.00",
    }
    pBytes, err := schemas.SerializeCivilCasePayload(civil)
    must(t, err)

    casePos := submitWithCosigner(t, f, clerkDID, cooperDID, pBytes,
        "File 2024-CV-001 Smith v. Johnson")
    // casePos = {LogDID: davidson, Sequence: 1}
```

`submitWithCosigner` is a thin wrapper over
`delegation.SignAndSubmitCosigned`; see helper at the end of this file.

## Step 2 — Bind the parties (`PartyBindingPayload` ×2)

Schema: `schemas/party_binding.go:66` / `:151`.

```go
    plaintiffBind := &schemas.PartyBindingPayload{
        BindingID:  "smith-bind-001",
        PartyClass: "plaintiff",
        PartyName:  "ACME Industries",
        CaseRef:    civil.DocketNumber,
        CaseSeq:    casePos.Sequence,
    }
    pbBytes, _ := schemas.SerializePartyBindingPayload(plaintiffBind)
    submitWithCosigner(t, f, clerkDID, cooperDID, pbBytes, "Bind plaintiff Smith")

    defendantBind := &schemas.PartyBindingPayload{
        BindingID:  "johnson-bind-001",
        PartyClass: "defendant",
        PartyName:  "Beta Corp",
        CaseRef:    civil.DocketNumber,
        CaseSeq:    casePos.Sequence,
    }
    dbBytes, _ := schemas.SerializePartyBindingPayload(defendantBind)
    submitWithCosigner(t, f, clerkDID, davisDID, dbBytes, "Bind defendant Johnson")
```

## Step 3 — Counsel appearances (`CounselAppearancePayload` ×2)

Schema: `schemas/counsel_appearance.go:48` / `:151`.

```go
    cooperApp := &schemas.CounselAppearancePayload{
        AppearanceID: "ap-cooper-001",
        AttorneyDID:  cooperDID,
        Represents:   []string{plaintiffBind.BindingID},
        CaseRef:      civil.DocketNumber,
        CaseSeq:      casePos.Sequence,
        FiledDate:    "2024-01-16",
        Status:       "active",
    }
    cBytes, _ := schemas.SerializeCounselAppearancePayload(cooperApp)
    submitWithCosigner(t, f, cooperDID, clerkDID, cBytes,
        "Cooper appears for plaintiff Smith")

    davisApp := &schemas.CounselAppearancePayload{
        AppearanceID: "ap-davis-001",
        AttorneyDID:  davisDID,
        Represents:   []string{defendantBind.BindingID},
        CaseRef:      civil.DocketNumber,
        CaseSeq:      casePos.Sequence,
        FiledDate:    "2024-01-17",
        Status:       "active",
    }
    dBytes, _ := schemas.SerializeCounselAppearancePayload(davisApp)
    submitWithCosigner(t, f, davisDID, clerkDID, dBytes,
        "Davis appears for defendant Johnson")
```

## Step 4 — Judge assignment (`JudicialDelegationPayload`)

Use the existing delegation helper — this exercises the
`delegation.Issue` path:

```go
    assignPos := f.issue(t, delegation.IssueRequest{
        GranterDID:   cjDID,
        GranteeDID:   judgeDID,
        GranteeRole:  "judge",
        Scope:        []string{civil.DocketNumber}, // case-scoped delegation
        DurationDays: 365,
        Rationale:    "Assigned for trial in 2024-CV-001",
    })
    // assignPos = {LogDID: davidson, Sequence: 6}
```

Now `judgeDID` resolves as `judge` for case `2024-CV-001` via the
authority resolver — `f.resolve(judgeDID, ...)` returns a non-nil
`Authority` for any judge action on this case.

## Step 5 — File evidence (`EvidenceArtifactPayload`)

Schema: `schemas/evidence_artifact.go:71` / `:135`.

```go
    contractScan := &schemas.EvidenceArtifactPayload{
        ArtifactEncryption:        "umbral_pre",
        GrantAuthorizationMode:    "open",   // civil discovery — no sealing
        GrantEntryRequired:        true,
        GrantRequiresAuditEntry:   true,
        EvidenceType:              "exhibit",
        Classification:            "ordinary",
        ChainOfCustodyRequired:    true,
        EvidenceID:                "ex-001",
        Description:               "Original signed supply contract, May 2023",
        ContentDigest:             "sha256:9b1c...",
        CaseRef:                   civil.DocketNumber,
        FiledBy:                   cooperDID,
    }
    eBytes, _ := schemas.SerializeEvidencePayload(contractScan)
    submitWithCosigner(t, f, cooperDID, clerkDID, eBytes,
        "File Exhibit A — original contract")
```

## Step 6 — Switch to COA exchange

Build a second fixture bound to `did:web:state:tn:coa` using
`coa.MustBundle()` (composer at `deployments/tn/coa/bundle.go`).
`newFixtureFor` is a one-line variant of `newFixture` parametrising
the three exchange constants at `delegation_helpers_test.go:142-144`.

```go
    coaFix := newFixtureFor(t, "did:web:state:tn:coa", coa.MustBundle())
    edwardsDID := coaFix.provisionKey(t, "did:key:zQ3sh-justice-edwards")
    fosterDID  := coaFix.provisionKey(t, "did:key:zQ3sh-justice-foster-coa")
    coaFix.roleResolver.Bind(edwardsDID, "justice", coaFix.institutionalDID)
    coaFix.roleResolver.Bind(fosterDID,  "justice", coaFix.institutionalDID)
```

## Step 7 — Disposition (`AppellateDispositionPayload`)

Schema: `schemas/appellate_disposition.go:34` / `:115`.

```go
    disp := &schemas.AppellateDispositionPayload{
        Outcome:   "affirmed",
        Panel:     []string{edwardsDID, fosterDID, "did:key:zQ3sh-justice-grant-coa"},
        VoteTally: "3-0",
        CaseRef:   civil.DocketNumber,
        FiledDate: "2024-12-01",
    }
    dispBytes, _ := schemas.SerializeDispositionPayload(disp)
    dispPos := submitCosigned(t, coaFix, edwardsDID, dispBytes,
        []string{fosterDID}, "COA disposition for 2024-CV-001")
```

## Step 8 — Opinion publication (`AppellateOpinionPublicationPayload`)

Schema: `schemas/appellate_opinion_publication.go:33` / `:119`.

```go
    op := &schemas.AppellateOpinionPublicationPayload{
        OpinionID:    "op-coa-2024-001",
        OpinionType:  "majority",
        AuthorDID:    edwardsDID,
        Parts:        []string{"facts", "discussion", "conclusion"},
        ContentHash:  "sha256:5a3e...",
        CaseRef:      civil.DocketNumber,
        FiledDate:    "2024-12-01",
    }
    opBytes, _ := schemas.SerializeOpinionPublicationPayload(op)
    submitCosigned(t, coaFix, edwardsDID, opBytes, []string{fosterDID},
        "Publish majority opinion in 2024-CV-001")
```

## Step 9 — Opinion participation (`AppellateOpinionParticipationPayload`)

Schema: `schemas/appellate_opinion_participation.go:30` / `:110`.

```go
    join := &schemas.AppellateOpinionParticipationPayload{
        OpinionID: op.OpinionID,
        JudgeDID:  fosterDID,
        Role:      "joined",
        CaseRef:   civil.DocketNumber,
        FiledDate: "2024-12-01",
    }
    jBytes, _ := schemas.SerializeOpinionParticipationPayload(join)
    submitCosigned(t, coaFix, fosterDID, jBytes, []string{edwardsDID},
        "Foster joins majority")
}
```

## Helper used in this file

```go
// submitWithCosigner: primary signs + one cosigner.
func submitWithCosigner(
    t *testing.T, f *contractFixture,
    primary, cosigner string, payload []byte, reason string,
) schemas.LogPositionRef {
    auth := envelope.AuthoritySameSigner
    entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
        Destination: f.exchangeDID, SignerDID: primary, AuthorityPath: &auth,
    }, payload)
    must(t, err)
    pos, err := delegation.SignAndSubmitCosigned(
        context.Background(), f.buildCtx, entry,
        &identity.TypedDataDisplay{Reason: reason}, reason,
        []string{cosigner})
    must(t, err)
    return pos
}
// submitCosigned: primary + N cosigners (used in COA panel votes).
```

## Verification

```go
    // davidson tip = 7 (case=1, plaintiff=2, defendant=3,
    // cooperApp=4, davisApp=5, assign=6, evidence=7).
    // COA tip = 3 (disposition=1, opinion=2, participation=3).
```

## Events covered

`CivilCasePayload` ✓ · `PartyBindingPayload` ✓×2 ·
`CounselAppearancePayload` ✓×2 · `JudicialDelegationPayload` ✓ ·
`EvidenceArtifactPayload` ✓ · `AppellateDispositionPayload` ✓ ·
`AppellateOpinionPublicationPayload` ✓ ·
`AppellateOpinionParticipationPayload` ✓
