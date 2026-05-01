# Case 2 · *State v. Wilson* — Felony assault, sealed victim, evidence chain

## Background

The State of Tennessee charges Marcus Wilson with aggravated assault.
The victim's identity is sealed at filing (TN code §40-38-103). The
prosecution's case relies on an evidence chain that includes a
phone-extracted video — protected by a court-ordered key attestation
to defend chain-of-custody at trial.

## Cast (6 actors)

| DID | Role | Side |
|---|---|---|
| `did:key:zQ3sh-clerk-brown` | court_clerk | Davidson |
| `did:key:zQ3sh-judge-adams` | judge | Davidson (assigned) |
| `did:key:zQ3sh-foster-ada` | attorney | State (ADA) |
| `did:key:zQ3sh-garcia-pd` | attorney | Defendant (Public Defender) |
| `did:key:zQ3sh-detective-martinez` | law_enforcement | TN State (filed evidence) |
| `did:key:zQ3sh-howard-witness` | witness | (party-bound, not a signer) |

The victim is bound via `PartyBindingSealedPayload` — they have a DID
inside the sealed mapping but never sign anything on the public log.

## Timeline

```
2024-03-04  Clerk files CriminalCasePayload                              → trial:1
2024-03-04  Clerk files PartyBindingSealedPayload (victim, sealed)       → trial:2
2024-03-05  Foster (ADA) files CounselAppearancePayload (for State)      → trial:3
2024-03-05  Garcia (PD) files CounselAppearancePayload (for Wilson)      → trial:4
2024-03-12  Judge Adams issues DisclosureOrderPayload (limited PD-only)  → trial:5
2024-03-15  Detective Martinez files EvidenceArtifactPayload (video)     → trial:6
2024-03-15  Detective Martinez files KeyAttestationPayload               → trial:7
2024-04-01  Judge Adams issues SealingOrderPayload (juvenile witness)    → trial:8
```

## Step 0 — Setup

```go
func TestCase_StateVWilson(t *testing.T) {
    f := newFixture(t)
    ctx := context.Background()

    clerkDID    := f.provisionKey(t, "did:key:zQ3sh-clerk-brown")
    judgeDID    := f.provisionKey(t, "did:key:zQ3sh-judge-adams")
    fosterDID   := f.provisionKey(t, "did:key:zQ3sh-foster-ada")
    garciaDID   := f.provisionKey(t, "did:key:zQ3sh-garcia-pd")
    martinezDID := f.provisionKey(t, "did:key:zQ3sh-detective-martinez")

    f.roleResolver.Bind(judgeDID,    "judge",           f.institutionalDID)
    f.roleResolver.Bind(fosterDID,   "attorney",        f.institutionalDID)
    f.roleResolver.Bind(garciaDID,   "attorney",        f.institutionalDID)
    f.roleResolver.Bind(martinezDID, "law_enforcement", f.institutionalDID)
```

## Step 1 — Charging document (`CriminalCasePayload`)

Schema: `schemas/criminal_case.go:49` / `:107`.

```go
    crim := &schemas.CriminalCasePayload{
        DocketNumber: "2024-CR-002",
        CaseType:     "felony",
        FiledDate:    "2024-03-04",
        Status:       "pending",
        Charges: []string{
            "39-13-102: aggravated assault (Class C felony)",
        },
        VictimInfo:     "sealed-binding-001",  // ref to sealed party
        SealedExhibits: true,
    }
    pBytes, _ := schemas.SerializeCriminalCasePayload(crim)
    casePos := submitWithCosigner(t, f, clerkDID, fosterDID, pBytes,
        "File 2024-CR-002 State v. Wilson")
```

## Step 2 — Sealed victim binding (`PartyBindingSealedPayload`)

Schema: `schemas/party_binding_sealed.go:17` / `:55`.

The victim's identity is encrypted; the on-log entry exposes only
the binding ID and the encryption metadata. The vendor (here a TN
victim-services bureau) holds the encrypted mapping.

```go
    vicBind := &schemas.PartyBindingSealedPayload{
        VendorDID:                "did:web:state:tn:victim-services",
        CaseRef:                  crim.DocketNumber,
        Role:                     "victim",
        Status:                   "active",
        ArtifactEncryption:       "umbral_pre",
        GrantAuthorizationMode:   "sealed",
        GrantEntryRequired:       true,
        GrantRequiresAuditEntry:  true,
        EncryptedMappingCID:      "bafy...victim",
        BindingID:                "sealed-binding-001",
    }
    vBytes, _ := schemas.SerializePartyBindingSealedPayload(vicBind)
    submitWithCosigner(t, f, clerkDID, fosterDID, vBytes,
        "Bind sealed victim for 2024-CR-002")
```

## Step 3 — Counsel appearances (`CounselAppearancePayload` ×2)

```go
    fosterApp := &schemas.CounselAppearancePayload{
        AppearanceID: "ap-foster-001",
        AttorneyDID:  fosterDID,
        Represents:   []string{"state-of-tn"},
        CaseRef:      crim.DocketNumber,
        CaseSeq:      casePos.Sequence,
        FiledDate:    "2024-03-05",
        Status:       "active",
    }
    fBytes, _ := schemas.SerializeCounselAppearancePayload(fosterApp)
    submitWithCosigner(t, f, fosterDID, clerkDID, fBytes,
        "Foster (ADA) appears for State")

    garciaApp := &schemas.CounselAppearancePayload{
        AppearanceID: "ap-garcia-001",
        AttorneyDID:  garciaDID,
        Represents:   []string{"defendant-wilson"},
        CaseRef:      crim.DocketNumber,
        CaseSeq:      casePos.Sequence,
        FiledDate:    "2024-03-05",
        Status:       "active",
    }
    gBytes, _ := schemas.SerializeCounselAppearancePayload(garciaApp)
    submitWithCosigner(t, f, garciaDID, clerkDID, gBytes,
        "Garcia (PD) appears for defendant Wilson")
```

## Step 4 — Disclosure order (`DisclosureOrderPayload`)

Schema: `schemas/disclosure_order.go:39` / `:78`.

Judge Adams orders the prosecution to disclose the sealed evidence
to defense counsel only. `authorized_recipients` is the named DID
list; `scope = "case_wide"` means anything in this docket.

```go
    disc := &schemas.DisclosureOrderPayload{
        OrderType:           "disclosure",
        Scope:               "case_wide",
        AuthorizedRecipients: []string{garciaDID},
        AuthorityCitation:   "Tenn. R. Crim. P. 16",
        EffectiveDate:       "2024-03-12",
        Conditions:          "PD-only; no copies; review on supervised terminal.",
    }
    dBytes, _ := schemas.SerializeDisclosureOrderPayload(disc)
    submitWithCosigner(t, f, judgeDID, clerkDID, dBytes,
        "Discovery order — disclose sealed evidence to PD")
```

## Step 5 — Evidence artifact (`EvidenceArtifactPayload`)

Schema: `schemas/evidence_artifact.go:71` / `:135`.

Detective Martinez files the phone-extracted video. The artifact is
content-addressed (CID) and umbral-PRE encrypted; the disclosure order
above gates re-encryption for the PD.

```go
    video := &schemas.EvidenceArtifactPayload{
        ArtifactEncryption:       "umbral_pre",
        GrantAuthorizationMode:   "sealed",
        GrantEntryRequired:       true,
        GrantRequiresAuditEntry:  true,
        EvidenceType:             "exhibit",
        Classification:           "sealed",
        ChainOfCustodyRequired:   true,
        EvidenceID:               "ex-video-001",
        Description:              "iPhone 12 video, recovered 2024-03-04",
        ContentDigest:            "sha256:7a2c...",
        ArtifactCID:              "bafy...video",
        CaseRef:                  crim.DocketNumber,
        FiledBy:                  martinezDID,
        DisclosureOrderRef:       "trial:5",  // refers to the disclosure entry
        AuthorizedRecipients:     []string{garciaDID},
    }
    vBytes2, _ := schemas.SerializeEvidencePayload(video)
    submitWithCosigner(t, f, martinezDID, fosterDID, vBytes2,
        "File Exhibit 1 — extracted video")
```

## Step 6 — Key attestation (`KeyAttestationPayload`)

Schema: `schemas/key_attestation.go:87` / `:172`.

Detective Martinez attests that the Cellebrite extraction terminal's
key was generated inside an SGX enclave; this defends chain-of-custody
against tampering claims.

```go
    keyAtt := &schemas.KeyAttestationPayload{
        AttestedEntity:         martinezDID,
        AttestedEntityPosition: schemas.SchemaPosition{LogDID: f.logDID},
        GenerationMode:         "client_side_enclave",
        EnclavePlatform:        "intel_sgx_v2",
        AttestationTime:        time.Date(2024, 3, 15, 14, 30, 0, 0, time.UTC).UnixMicro(),
        WitnessArtifactHash:    "sha256:c4e1...",
        AttestationEvidence:    "MIIE...sgx-quote-base64...",
    }
    kBytes, _ := schemas.SerializeKeyAttestation(keyAtt)
    submitWithCosigner(t, f, martinezDID, fosterDID, kBytes,
        "Attest extraction-terminal key (SGX)")
```

## Step 7 — Sealing order (`SealingOrderPayload`)

Schema: `schemas/sealing_order.go:16` / `:37`.

A juvenile witness (Howard) is identified late; Judge Adams seals
their identifying records.

```go
    seal := &schemas.SealingOrderPayload{
        OrderType:         "sealing",
        Authority:         judgeDID,
        CaseRef:           crim.DocketNumber,
        Reason:            "Witness is a minor; TN code §37-1-153.",
        AffectedArtifacts: []string{"witness-howard-binding"},
    }
    sBytes, _ := schemas.SerializeSealingOrderPayload(seal)
    submitWithCosigner(t, f, judgeDID, clerkDID, sBytes,
        "Seal records identifying juvenile witness")
}
```

## Verification

```go
    // davidson tip = 8 (case=1, victim=2, fosterApp=3, garciaApp=4,
    // disclosure=5, video=6, keyAtt=7, sealing=8).
```

## Why two orders (disclosure + sealing)?

- **`DisclosureOrderPayload`** is permissive: it grants a named recipient
  (the PD) access to artifacts they would otherwise not be cleared for.
  Used to enforce Brady-rule disclosure under sealing.
- **`SealingOrderPayload`** is restrictive: it removes a class of
  artifact from the default-public access set. Used to add new sealing
  obligations after filing.
  These compose — a disclosure order can grant access to a sealed
  artifact without unsealing it for everyone else.

## Helper used in this file

Same `submitWithCosigner` from
[01-smith-v-johnson.md](01-smith-v-johnson.md). Both cases reuse it
verbatim; in a real `tests/scenarios/` package it would live in a
shared `helpers_test.go`.

## Events covered

`CriminalCasePayload` ✓ · `PartyBindingSealedPayload` ✓ ·
`CounselAppearancePayload` ✓×2 · `DisclosureOrderPayload` ✓ ·
`EvidenceArtifactPayload` ✓ · `KeyAttestationPayload` ✓ ·
`SealingOrderPayload` ✓
