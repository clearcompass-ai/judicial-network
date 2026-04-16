# Judicial Network — Complete File Inventory (149 files)

## Final Issues (4 open, 2 closed)

### OPEN

**Issue 1: `GenerateDIDKey` produces non-opaque DIDs — wrong for sealed parties**

Evidence: `did/creation.go` line ~52 produces `"did:key:f" + hex.EncodeToString(pubBytes)`.
The public key is embedded in the DID string. Anyone can decode it.

Impact: `parties/privacy.go` must NOT use `GenerateDIDKey` for sealed party
vendor-specific DIDs. Sealed parties in juvenile/family cases need opaque
identifiers where the mapping is exchange-controlled.

Fix: Use `did.NewWebDID(exchangeDomain, "holder/"+randomUUID)` in `privacy.go`.
The exchange resolves the DID via its HTTP endpoint, enforcing access control.
`GenerateDIDKey` remains correct for test fixtures and operator bootstrap.

Evidence source: SDK `did/creation.go` Document 31.

---

**Issue 3: File names diverge from v4 document — needs reconciliation**

Impact: Three packages have different file names in the plan vs v4 document.
This inventory adopts the plan's structure (by workflow step, not jurisdiction
type) and reconciles the mapping:

```
V4 DOCUMENT                    → THIS INVENTORY           RATIONALE
───────────────────────────────────────────────────────────────────────
parties/identifier_scope.go    → parties/privacy.go        Schema-driven DID selection is
                                                           vendor DID generation
parties/sealed_identity.go     → parties/binding_sealed.go Sealed binding + identity in one
parties/attorney_reference.go  → parties/roster.go         Cross-log links include attorneys

enforcement/protective_order.go → enforcement/compliance.go Protective orders absorbed into
                                                           sealing.go (same BuildEnforcement
                                                           Path C). Compliance is new.

appeals/intra_jurisdiction.go  → appeals/initiation.go     Workflow-step structure is better
appeals/cross_jurisdiction.go  → appeals/record.go         than jurisdiction-type structure
appeals/remand.go              → appeals/decision.go       for implementation clarity
appeals/cert.go                → appeals/mandate.go
```

Fix: Update v4 document to match this inventory. File counts unchanged (4+5+4).

---

**Issue 4: `artifact.BatchExpunge` does not exist**

Evidence: `cases/artifact/expunge.go` has `ExpungeArtifact` (single artifact).
`enforcement/expungement.go` needs batch expungement for case-level erasure.

Impact: `enforcement/expungement.go` cannot call a function that doesn't exist.

Fix: Add `BatchExpunge` to `cases/artifact/expunge.go` following the same
pattern as `BatchReencrypt` in `reencrypt.go` (loop + semaphore concurrency +
per-CID retry + progress callback). ~60 lines.

---

**Issue 6: DID Document has no key purpose differentiation**

Evidence: `did/resolver.go` `VerificationMethod` struct has no `purpose` field.
`WitnessKeys()` returns all keys from all verification methods. W3C DID Core
defines `authentication`, `assertionMethod`, `keyAgreement` as separate
verification relationships — the SDK doesn't model these yet.

Impact: `cases/artifact/did_keys.go` cannot resolve encryption-specific keys
(`keyAgreement`) separately from signing keys (`assertionMethod`). Courts
initially use the same key for both, so this doesn't block shipping.

Fix: `did_keys.go` uses `doc.WitnessKeys()[0]` for now. Flag SDK enhancement
to add `Authentication`, `AssertionMethod`, `KeyAgreement` fields to
`DIDDocument`. Not blocking.

---

### CLOSED

**Issue 2: `BuildApprovalCosignature` — EXISTS**

Evidence: `lifecycle/scope_governance.go` exports it. Convenience wrapper
around `builder.BuildCosignature`. Plan reference is correct.

**Issue 5: `QueryByTargetRoot` — EXISTS**

Evidence: `log/operator_api.go` `OperatorQueryAPI` interface exports it.
`appeals/record.go` calls it directly.

---

## Complete File Inventory

### Root (3 files)

```
judicial-network/
├── README.md
├── LICENSE
└── go.mod                         # depends on github.com/clearcompass-ai/ortholog-sdk
```

---

### Layer 1: Domain Definition (13 files)

```
companion/
└── judicial_companion.md          # Domain companion document
                                   # No SDK dependency — pure conventions
```

```
schemas/
├── criminal_case.go               # tn-criminal-case-v1
│                                  #   SDK: schema.SchemaParameterExtractor reads well-known fields
├── civil_case.go                  # tn-civil-case-v1
├── family_case.go                 # tn-family-case-v1
├── juvenile_case.go               # tn-juvenile-case-v1
├── evidence_artifact.go           # tn-evidence-artifact-v1
│                                  #   artifact_encryption: umbral_pre
│                                  #   grant_authorization_mode: sealed
│                                  #   re_encryption_threshold: { m: 3, n: 5 }
├── shard_genesis.go               # shard-genesis-v1
├── court_officer.go               # tn-court-officer-v1 (delegation payload)
├── party_binding.go               # tn-party-binding-v1 (public, real_did)
├── party_binding_sealed.go        # tn-party-binding-sealed-v1 (PRE, vendor_did)
├── sealing_order.go               # tn-sealing-order-v1
├── appellate_decision.go          # tn-appellate-decision-v1
└── registry.go                    # Schema URI → serializer mapping
                                   #   SDK: implements schema.SchemaParameterExtractor
```

---

### Layer 2: Network Topology (4 files)

```
topology/
├── network.go                     # Jurisdiction hierarchy (pure data model)
│                                  #   No SDK calls
├── spoke_config.go                # Three-log convention: officers, cases, parties
│                                  #   No SDK calls — consumed by onboarding/provision.go
├── anchor_publisher.go            # Periodic anchoring to parent log
│                                  #   SDK: builder.BuildAnchorEntry
│                                  #   SDK: witness.TreeHeadClient
└── discovery.go                   # Court DID → anchor chain resolution
                                   #   SDK: witness.TreeHeadClient
                                   #   SDK: did.DIDResolver (via DIDEndpointAdapter)
```

---

### Layer 3: Court Authority Management (8 files)

```
delegation/
├── court_profile.go               # Institutional DID + scope creation
│                                  #   SDK: builder.BuildScopeCreation
├── division.go                    # Division scope under court
│                                  #   SDK: builder.BuildScopeCreation (with parent pointer)
├── judge.go                       # Depth 1: division → judge
│                                  #   SDK: builder.BuildDelegation
├── clerk.go                       # Depth 2: judge → clerk
│                                  #   SDK: builder.BuildDelegation
├── deputy.go                      # Depth 3: clerk → deputy (max depth)
│                                  #   SDK: builder.BuildDelegation
├── succession.go                  # Judicial rotation
│                                  #   SDK: builder.BuildSuccession
├── roster_sync.go                 # officers.yaml ↔ delegation tree reconciliation
│                                  #   SDK: log.OperatorQueryAPI.QueryBySignerDID
│                                  #   SDK: verifier.WalkDelegationTree
│                                  #   SDK: builder.BuildDelegation (new officers)
│                                  #   SDK: builder.BuildRevocation (departed officers)
└── mirror.go                      # Cross-log delegation mirrors
                                   #   SDK: builder.BuildMirrorEntry
```

---

### Layer 4: Case Lifecycle (12 files)

```
cases/
├── initiation.go                  # New case → root entity on cases log
│                                  #   SDK: builder.BuildRootEntity
├── filing.go                      # Attorney filings (motions, exhibits, responses)
│                                  #   SDK: builder.BuildAmendment (Path A, same signer)
│                                  #   SDK: builder.AssemblePathB + BuildPathBEntry (delegated)
│                                  #   Calls: cases/artifact/publish.go
├── judicial_action.go             # Judge-signed orders via delegation chain
│                                  #   SDK: builder.AssemblePathB + BuildPathBEntry
│                                  #   Calls: cases/artifact/publish.go
├── amendment.go                   # Status changes, reassignment, CID updates
│                                  #   SDK: builder.BuildAmendment
├── transfer.go                    # Cross-division and cross-county transfer
│                                  #   SDK: verifier.BuildCrossLogProof
│                                  #   SDK: builder.BuildAmendment
│                                  #   SDK: builder.BuildMirrorEntry
└── docket_query.go                # Read-side: docket → case root position
                                   #   SDK: log.OperatorQueryAPI.QueryBySignerDID
                                   #   SDK: smt.LeafReader (Origin_Tip + Authority_Tip)
```

```
cases/artifact/
├── publish.go                     # Encrypt + push + key store
│                                  #   SDK: artifact.EncryptArtifact (AES-GCM)
│                                  #   SDK: artifact.PRE_Encrypt (Umbral PRE)
│                                  #   SDK: lifecycle.GenerateDelegationKey (PRE delegation)
│                                  #   SDK: lifecycle.ArtifactKeyStore (AES-GCM keys)
│                                  #   SDK: storage.ContentStore.Push
│                                  #   SDK: storage.Compute (CID)
│                                  #   Defines: DelegationKeyStore interface (PRE wrapped keys)
├── retrieve.go                    # Sealing check + grant composition
│                                  #   SDK: lifecycle.GrantArtifactAccess
│                                  #   SDK: lifecycle.UnwrapDelegationKey (PRE path)
│                                  #   SDK: lifecycle.VerifyAndDecryptArtifact (free tier proxy)
│                                  #   SDK: verifier.EvaluateOrigin (sealing check)
│                                  #   Uses: DelegationKeyStore.Get (PRE path)
├── expunge.go                     # Key destruction + backend cleanup
│                                  #   SDK: lifecycle.ArtifactKeyStore.Delete (AES-GCM)
│                                  #   SDK: storage.ContentStore.Delete
│                                  #   Uses: DelegationKeyStore.Delete (PRE)
│                                  #   Provides: BatchExpunge (loop + concurrency) [Issue 4]
├── reencrypt.go                   # AES-GCM key rotation batch
│                                  #   SDK: lifecycle.ReEncryptWithGrant
│                                  #   SDK: lifecycle.ArtifactKeyStore
│                                  #   PRE artifacts NOT re-encrypted (PRE transforms access)
├── bulk_import.go                 # Historical record digitization
│                                  #   Calls: publish.go in a batch loop
│                                  #   Rate limiting per storage backend
└── did_keys.go                    # Shared DID key resolution helper
                                   #   SDK: did.DIDResolver
                                   #   SDK: DIDDocument.WitnessKeys()[0] (Issue 6: no purpose field)
                                   #   Consumed by: publish.go, retrieve.go, evidence_access.go
```

---

### Layer 5: Party Management (4 files)

```
parties/
├── binding.go                     # Party-case binding on parties log
│                                  #   SDK: builder.BuildRootEntity (new binding)
│                                  #   SDK: builder.BuildAmendment (role changes)
├── binding_sealed.go              # Sealed bindings for juvenile/family cases
│                                  #   Calls: cases/artifact/publish.go (PRE path)
│                                  #   SDK: lifecycle.GrantArtifactAccess (sealed mode)
├── roster.go                      # Case party roster + cross-log links
│                                  #   SDK: builder.BuildCommentary (cross-log refs)
│                                  #   SDK: log.OperatorQueryAPI.QueryByTargetRoot
│                                  #   Absorbs attorney_reference.go functionality
└── privacy.go                     # Vendor-specific DID generation + mapping
                                   #   SDK: did.NewWebDID (NOT GenerateDIDKey — Issue 1)
                                   #   SDK: exchange/identity/mapping_escrow (off-log mapping)
                                   #   Absorbs identifier_scope.go functionality
```

---

### Layer 6: Enforcement (5 files)

```
enforcement/
├── sealing.go                     # Path C sealing order
│                                  #   SDK: builder.BuildEnforcement
│                                  #   SDK: verifier.EvaluateConditions (activation delay)
│                                  #   Also handles protective orders (same Path C mechanism)
├── unsealing.go                   # Path C + cosignature requirement
│                                  #   SDK: builder.BuildEnforcement
│                                  #   SDK: lifecycle.BuildApprovalCosignature
│                                  #   SDK: verifier.CheckActivationReady
├── evidence_access.go             # Umbral PRE grant workflow (sealed evidence)
│                                  #   SDK: lifecycle.GrantArtifactAccess (sealed mode)
│                                  #   SDK: lifecycle.CheckGrantAuthorization
│                                  #   SDK: lifecycle.UnwrapDelegationKey
│                                  #   SDK: artifact.PRE_VerifyCFrag (sanity check)
│                                  #   SDK: builder.BuildCommentary (grant entry)
│                                  #   Uses: DelegationKeyStore.Get
│                                  #   Uses: did_keys.ResolveEncryptionKey
├── expungement.go                 # Cryptographic erasure per TCA 40-32-101
│                                  #   SDK: builder.BuildEnforcement (expungement order)
│                                  #   Calls: cases/artifact/expunge.go BatchExpunge [Issue 4]
│                                  #   Both ArtifactKeyStore.Delete and DelegationKeyStore.Delete
└── compliance.go                  # Enforcement timeline verification
                                   #   SDK: verifier.EvaluateConditions
                                   #   SDK: verifier.CheckActivationReady
                                   #   SDK: log.OperatorQueryAPI.ScanFromPosition
                                   #   SDK: builder.ClassifyEntry
```

---

### Layer 7: Appeals (4 files)

```
appeals/
├── initiation.go                  # Notice of appeal → root entity on appellate log
│                                  #   SDK: builder.BuildRootEntity
│                                  #   SDK: verifier.BuildCrossLogProof (prove lower court case)
├── record.go                      # Record on appeal — certified copy of lower court entries
│                                  #   SDK: log.OperatorQueryAPI.QueryByTargetRoot
│                                  #   Calls: cases/artifact/retrieve.go (lower court)
│                                  #   Calls: cases/artifact/publish.go (appellate log)
│                                  #   SDK: builder.BuildCommentary (manifest of transferred CIDs)
├── decision.go                    # Appellate decision entry
│                                  #   SDK: builder.AssemblePathB + BuildPathBEntry
│                                  #   Calls: cases/artifact/publish.go (opinion document)
└── mandate.go                     # Mandate — makes appellate decision effective
                                   #   SDK: builder.BuildEnforcement (reverse/remand on lower court)
                                   #   SDK: builder.BuildCommentary (affirm on lower court)
                                   #   SDK: verifier.BuildCrossLogProof (cross-log reference)
```

---

### Layer 8: Verification (6 files)

```
verification/
├── case_status.go                 # Origin_Tip → current case state
│                                  #   SDK: verifier.EvaluateOrigin
│                                  #   SDK: smt.LeafReader
├── delegation_chain.go            # Delegation provenance verification
│                                  #   SDK: verifier.WalkDelegationTree
│                                  #   SDK: builder.ValidateChainLiveness
├── sealing_check.go               # Authority_Tip → enforcement status
│                                  #   SDK: verifier.EvaluateAuthority
├── background_check.go            # Party DID → public case associations
│                                  #   SDK: log.OperatorQueryAPI.QueryBySignerDID
│                                  #   SDK: smt.BatchMultiproofs (efficiency)
├── appellate_history.go           # Appeal chain reconstruction across logs
│                                  #   SDK: verifier.BuildCrossLogProof
│                                  #   SDK: verifier.VerifyCrossLogProof
└── evidence_chain.go              # Chain of custody reconstruction
                                   #   SDK: log.OperatorQueryAPI.ScanFromPosition
                                   #   SDK: builder.ClassifyEntry
                                   #   SDK: artifact.PRE_VerifyCFrag (per cfrag, no private key)
```

---

### Layer 9: Monitoring (9 files)

```
monitoring/
├── anchor_freshness.go            # Anchor intervals on schedule?
│                                  #   SDK: log.OperatorQueryAPI.ScanFromPosition
│                                  #   SDK: witness.TreeHeadClient
├── delegation_health.go           # Expired judges still signing?
│                                  #   SDK: verifier.WalkDelegationTree
│                                  #   SDK: builder.ClassifyEntry
├── sealing_compliance.go          # Activation delays respected?
│                                  #   SDK: verifier.CheckActivationReady
│                                  #   SDK: verifier.EvaluateConditions
├── mirror_consistency.go          # Delegation mirrors match officers log?
│                                  #   SDK: smt.LeafReader (compare tips)
├── blob_availability.go           # Structural blobs retrievable?
│                                  #   SDK: storage.ContentStore.Exists
├── dual_attestation.go            # 2 identity attestations per officer?
│                                  #   SDK: log.OperatorQueryAPI.QueryBySignerDID
├── dashboard.go                   # Aggregated AOC network view
│                                  #   Reads from all other monitoring services
├── evidence_grant_compliance.go   # Grant entries exist? CFrags valid?
│                                  #   SDK: artifact.PRE_VerifyCFrag
│                                  #   SDK: verifier.CheckActivationReady
│                                  #   SDK: builder.BuildCommentary (compliance attestation)
└── shard_health.go                # Size thresholds, archive access, genesis chain
                                   #   SDK: verifier.VerifyShardChain
```

---

### Layer 10: Onboarding (5 files)

```
onboarding/
├── provision.go                   # Three logs for a new court
│                                  #   SDK: lifecycle.ProvisionThreeLogs
├── anchor_registration.go         # First anchor to parent log
│                                  #   SDK: builder.BuildAnchorEntry
├── schema_adoption.go             # Pull schemas from state/federal log
│                                  #   SDK: builder.BuildRootEntity (local schema copy)
│                                  #   SDK: verifier.WalkSchemaChain (predecessor chain)
├── officer_bootstrap.go           # Bulk delegation from initial roster
│                                  #   SDK: builder.BuildDelegation (batch)
└── migration.go                   # Legacy CMS import
                                   #   Calls: cases/artifact/bulk_import.go
```

---

### Layer 11: CMS Integration (6 files)

```
cms_bridge/
├── interface.go                   # Generic CMS event interface
│                                  #   No SDK calls — pure type definitions
├── event_mapper.go                # CMS event → SDK entry construction
│                                  #   SDK: all 18 entry builders (routes by event type)
└── adapters/
    ├── tyler_odyssey.go           # Tyler Technologies Odyssey
    ├── journal_tech.go            # Journal Technologies
    ├── thomson_reuters_ctrack.go  # Thomson Reuters C-Track
    └── generic_csv.go             # Fallback CSV import
```

---

### Layer 12: Public API (12 files)

```
public_api/
├── server.go                      # HTTP/gRPC server setup
│
├── handlers/
│   ├── case_lookup.go             # GET /v1/cases/{docket_number}
│   ├── party_search.go            # GET /v1/parties/{did}
│   ├── verify_order.go            # GET /v1/verify/{log_position}
│   ├── bulk_verify.go             # POST /v1/verify/batch
│   ├── case_documents.go          # GET /v1/cases/{docket}/documents
│   ├── document_download.go       # GET /v1/documents/{cid}
│   │                              #   Calls: cases/artifact/retrieve.go
│   │                              #   Passes result to storage/delivery_adapter.go
│   ├── evidence_chain.go          # GET /v1/evidence/{cid}/chain
│   │                              #   Calls: verification/evidence_chain.go
│   └── party_batch.go             # POST /v1/parties/batch
│                                  #   SDK: smt.BatchMultiproofs
│
└── middleware/
    ├── proof_attachment.go        # Cryptographic proof on every response
    ├── sealed_filter.go           # Authority_Tip check before response
    └── metering.go                # Free vs metered endpoint enforcement
```

---

### Layer 12.5: Delivery (1 file)

```
storage/
└── delivery_adapter.go            # Route GrantArtifactAccessResult → HTTP response
                                   #   Routes on result.Credential.Method:
                                   #     "signed_url" → 302
                                   #     "ipfs" → JSON envelope
                                   #     "direct" → proxy stream (free tier)
                                   #   SDK: lifecycle.VerifyAndDecryptArtifact (proxy mode)
```

---

### Layer 13: Consortium (9 files)

```
consortium/
├── formation.go                   # Create state judicial consortium
│                                  #   SDK: builder.BuildScopeCreation
├── membership.go                  # Court joins/leaves
│                                  #   SDK: lifecycle.ProposeAmendment
│                                  #   SDK: lifecycle.CollectApprovals
│                                  #   SDK: lifecycle.ExecuteAmendment / ExecuteRemoval
├── federated_did.go               # Consortium-scoped federated DIDs
│                                  #   SDK: did.NewWebDID
├── access_tiers.go                # Consumer type tier schemas
│                                  #   SDK: builder.BuildRootEntity (tier schema entries)
├── mapping_escrow.go              # Consortium mapping escrow
│                                  #   SDK: exchange/identity/mapping_escrow
│
└── load_accounting/
    ├── schema.go                  # Load accounting schema entry
    │                              #   SDK: builder.BuildRootEntity
    ├── fire_drills.go             # Synthetic recovery exercises
    │                              #   SDK: escrow.VerifyShare
    ├── aggregator.go              # Deterministic settlement computation
    │                              #   SDK: log.OperatorQueryAPI.ScanFromPosition
    │                              #   SDK: builder.ClassifyEntry
    └── settlement.go              # Off-log settlement coordination
                                   #   SDK: builder.BuildCommentary (period boundaries)
```

---

### Layer 14: Migration (3 files)

```
migration/
├── graceful.go                    # Cooperative exchange shutdown
│                                  #   Calls: cases/artifact/reencrypt.go BatchReencrypt
├── ungraceful.go                  # Exchange failure recovery
│                                  #   SDK: lifecycle.InitiateRecovery
│                                  #   SDK: lifecycle.CollectShares
│                                  #   SDK: lifecycle.ExecuteRecovery
│                                  #   SDK: lifecycle.EvaluateArbitration (custody disputes)
└── bulk_historical.go             # Mass legacy record import
                                   #   Calls: cases/artifact/bulk_import.go
```

---

### Deployments (27 files)

```
deployments/TEMPLATE/                        # 12 files
├── config/
│   ├── court.yaml                           # Institutional DID, Authority_Set
│   ├── officers.yaml                        # Judge/clerk roster with scope_limits
│   ├── logs.yaml                            # Three-log DID configuration
│   ├── anchor.yaml                          # Parent log, interval
│   ├── exchange.yaml                        # Exchange DID, key gen mode
│   ├── schemas.yaml                         # Active schema versions
│   ├── cms.yaml                             # CMS adapter and endpoint
│   ├── storage.yaml                         # Artifact storage backend
│   ├── access_tiers.yaml                    # API tier definitions
│   └── shard.yaml                           # Shard interval, archive tier
├── bootstrap.sh                             # Steps 1-10 deployment
└── verify.sh                                # Post-deployment verification
```

```
deployments/davidson_county/                 # 15 files
├── README.md
├── config/
│   ├── court.yaml                           # did:web:courts.nashville.gov
│   ├── officers.yaml                        # Current Davidson roster
│   ├── logs.yaml                            # Three Davidson log DIDs
│   ├── anchor.yaml                          # TN state anchor
│   ├── exchange.yaml                        # Exchange relationship
│   ├── schemas.yaml                         # Active schemas
│   ├── cms.yaml                             # Tyler Odyssey adapter
│   ├── storage.yaml                         # GCS backend
│   ├── access_tiers.yaml                    # API tiers
│   └── shard.yaml                           # Shard config
├── services/
│   ├── daily_docket.go                      # Cron: CMS → BuildCommentary
│   └── court_ops.go                         # Event-driven: hours, closures
├── bootstrap.sh                             # Steps 1-10
└── verify.sh                                # Steps 1-18 (incl. artifact lifecycle)
```

---

### Tests (18 files)

```
tests/
├── delegation_chain_test.go                 # Court → judge → clerk → deputy
├── succession_test.go                       # Judge retires → succession
├── case_lifecycle_test.go                   # Filing → motions → order → judgment
├── sealing_test.go                          # Seal → hidden → unseal → visible
├── expungement_test.go                      # Key destroyed → CID irrecoverable
├── cross_county_test.go                     # Davidson verified from Shelby
├── appellate_chain_test.go                  # Municipal → county → state → SCOTUS
├── background_check_test.go                 # Party DID → public records
├── onboarding_test.go                       # New court provisions + anchors
├── mirror_propagation_test.go               # Delegation revoked → mirror revoked
├── roster_sync_test.go                      # Judge retires → new judge files
├── consortium_formation_test.go             # 3 counties form, 1 joins
├── fire_drill_test.go                       # Load accounting end-to-end
├── migration_graceful_test.go               # Exchange shutdown → migration
├── migration_ungraceful_test.go             # Exchange disappears → recovery
├── evidence_access_test.go                  # Umbral PRE end-to-end
├── evidence_chain_test.go                   # Chain of custody reconstruction
└── shard_lifecycle_test.go                  # Freeze → new shard → verify chain
```

---

## Count Verification

```
Root                              3
companion/                        1
schemas/                         12
topology/                         4
delegation/                       8
cases/                            6
cases/artifact/                   6
parties/                          4
enforcement/                      5
appeals/                          4
verification/                     6
monitoring/                       9
onboarding/                       5
cms_bridge/                       2
cms_bridge/adapters/              4
public_api/                       1
public_api/handlers/              8
public_api/middleware/            3
storage/                          1
consortium/                       5
consortium/load_accounting/       4
migration/                        3
deployments/TEMPLATE/            12
deployments/davidson_county/     15
tests/                           18
                                ───
TOTAL                           149
```

```
Go source (.go)          102
Test files (_test.go)     18
Config files (.yaml)      20
Shell scripts (.sh)        4
Markdown (.md)             2
Root files                 3
                         ───
                         149
```

---

## SDK Functions Consumed (deduplicated)

```
ENTRY BUILDERS (18):
  BuildRootEntity, BuildAmendment, BuildDelegation, BuildSuccession,
  BuildRevocation, BuildScopeCreation, BuildScopeAmendment, BuildScopeRemoval,
  BuildEnforcement, BuildCommentary, BuildCosignature, BuildRecoveryRequest,
  BuildAnchorEntry, BuildKeyRotation, BuildKeyPrecommit, BuildSchemaEntry,
  BuildPathBEntry, BuildMirrorEntry

CLASSIFICATION:
  ClassifyEntry, ClassifyBatch

DELEGATION:
  AssemblePathB, ValidateChainLiveness

LIFECYCLE:
  GrantArtifactAccess, VerifyAndDecryptArtifact, ReEncryptWithGrant,
  CheckGrantAuthorization, GenerateDelegationKey, UnwrapDelegationKey,
  ProvisionThreeLogs, InitiateRecovery, CollectShares, ExecuteRecovery,
  EvaluateArbitration, ProposeAmendment, CollectApprovals,
  ExecuteAmendment, ExecuteRemoval, ActivateRemoval,
  BuildApprovalCosignature, ProcessWithRetry,
  GenerateAdmissionStamp, VerifyAdmissionStamp

VERIFICATION:
  EvaluateOrigin, EvaluateAuthority, EvaluateConditions,
  CheckActivationReady, EvaluateKeyRotation, EvaluateContest,
  VerifyDerivationCommitment, WalkSchemaChain, EvaluateMigration,
  BuildCrossLogProof, VerifyCrossLogProof, WalkDelegationTree,
  VerifyShardChain

CRYPTO:
  EncryptArtifact, DecryptArtifact, ReEncryptArtifact,
  PRE_Encrypt, PRE_GenerateKFrags, PRE_ReEncrypt, PRE_VerifyCFrag,
  PRE_DecryptFrags, SplitGF256, ReconstructGF256,
  EncryptForNode, VerifyShare

CONTENT:
  storage.Compute, CID.Verify

QUERIES:
  QueryBySignerDID, QueryByTargetRoot, QueryByCosignatureOf,
  QueryBySchemaRef, ScanFromPosition

DID:
  NewWebDID, DIDResolver.Resolve, WitnessKeys,
  OperatorEndpointURL, ArtifactStoreURL

INTERFACES (injected at deployment):
  ContentStore, RetrievalProvider, EntryFetcher, LeafReader,
  SchemaParameterExtractor, ArtifactKeyStore,
  DelegationKeyStore (judicial-network-defined)
```A disclosure order is a court directive authorizing specific recipients to access specific PRE-encrypted evidence. It's the bridge between judicial authority and the SDK's CheckGrantAuthorization sealed mode. The court publishes a disclosure order entry (Path C enforcement), and evidence_access.go reads it to assemble the recipient list passed to GrantArtifactAccess.
sealing_order.go      → hides the case (blocks all access)
evidence_artifact.go  → defines the evidence (PRE encryption params)
disclosure_order.go   → authorizes specific recipients for specific evidence
What needs updating in v4:
Add to Layer 1 schemas section, between evidence_artifact.go and shard_genesis.go:
│   ├── disclosure_order.go                # tn-disclosure-order-v1
│   │                                      #   Path C enforcement entry schema
│   │                                      #   authorized_recipients: [did:example:prosecutor, ...]
│   │                                      #   artifact_refs: [artifact_cid_1, artifact_cid_2]
│   │                                      #   scope: case-level or artifact-level
│   │                                      #   activation_delay: per court policy
│   │                                      #   cosignature_threshold: 0 (judge acts alone) or 1
│   │                                      #   Consumed by enforcement/evidence_access.go to
│   │                                      #     populate AuthorizedRecipients in GrantArtifactAccess
Registry count goes from 12 → 13 registrations. Schema count goes from 12 → 13 files in schemas/.