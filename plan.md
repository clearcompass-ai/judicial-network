# Judicial Network — Final Wave Plan v5

Grounded in: ortholog-sdk v0.1.1 (128 files, verified via guide + source),
ortholog-operator Phase 2, ortholog-artifact-store Phase 3, judicial-network
current tree. CMS integration eliminated. Phases restructured.

---

## Current State

| Wave | Status | Files |
|------|--------|-------|
| Waves 1-3 (schemas, parties, enforcement, appeals, verification) | Complete | ~58 on disk |
| Wave 4 (monitoring, onboarding, bug fixes) | Complete | 14 delivered |
| **Phase 0 (compilation fix)** | **Delivered in this document** | **3 files** |

**What's eliminated:** CMS integration (6 files). External systems generate
standardized entries — the bridge is their job, not ours.

**What remains:** 3 phases, ~66 files.

---

## Phase 0 — Fix Compilation (DELIVERED)

Three files delivered. Apply to the judicial-network repo:

| File | Action | Purpose |
|------|--------|---------|
| `onboarding/provision.go` | Replace | Calls `lifecycle.ProvisionSingleLog` 3×. Drops all deleted SDK symbols. |
| `did/mappings.go` | Create | Absorbs `CourtMapping`, `JNetMapping`, `CCRMapping` from deleted SDK helpers. |
| `go.mod` | Replace | Pins SDK to v0.1.1. Keeps `replace` for development. |

### Verification steps

```bash
cd ~/workspace/judicial-network

# 1. Apply the three files
cp <delivered>/onboarding/provision.go onboarding/provision.go
cp <delivered>/did/mappings.go did/mappings.go
cp <delivered>/go.mod go.mod

# 2. Verify compilation
go build ./...

# 3. Verify no stale references
grep -rn "ProvisionThreeLogs\|ProvisionConfig\|ProvisionResult" --include='*.go' .
# Expected: zero hits

# 4. Vet
go vet ./...
```

### What changed in `onboarding/provision.go`

| Before | After |
|--------|-------|
| `lifecycle.ProvisionThreeLogs(sdkCfg)` | `lifecycle.ProvisionSingleLog(cfg)` called 3× via `provisionOne` |
| Return type `*lifecycle.ProvisionResult` | Return type `*CourtProvision` (domain-owned) |
| `lifecycle.DelegationSpec{LogDIDs: ...}` | `lifecycle.DelegationSpec{DelegateDID: ..., ScopeLimit: ...}` — per-log filtering in domain code |
| `lifecycle.SchemaSpec{LogDID: ...}` | `lifecycle.SchemaSpec{Payload: ...}` — no per-spec log target |
| `lifecycle.ProvisionConfig{CourtDID, OfficersLogDID, ...}` | `lifecycle.SingleLogConfig{SignerDID, LogDID, AuthoritySet, ...}` |

### What changed in `did/mappings.go`

New file. Three functions return `did.VendorMapping` values with verified
field names (`Method`, `DomainSuffix`, `TargetMethod`). Plus `AllMappings()`
convenience function. Registration:

```go
import judicialdid "github.com/clearcompass-ai/judicial-network/did"

resolver := did.NewVendorDIDResolver(baseResolver, judicialdid.AllMappings())
```

### ProposalType migration

Not needed. Grep confirmed zero call sites using `"add_access_tier"` or
any `ProposalType` value in the judicial-network repo. The typed enum
(`ProposalAddAuthority`, `ProposalRemoveAuthority`, `ProposalChangeParameters`,
`ProposalDomainExtension`) is available when future code needs it.

---

## Phase 1 — Consortium + Migration + Deployments (36 files)

Federation infrastructure, migration tooling, and deployment templates.
No tests in this phase — tests are Phase 3.

### 1.1 Consortium (8 files)

| File | SDK primitives (guide §) |
|------|--------------------------|
| `consortium/formation.go` | `BuildScopeCreation` (§11.3), `ProvisionSingleLog` (§20.1) |
| `consortium/membership.go` | `ProposeAmendment`, `CollectApprovals`, `ExecuteAmendment` (§20.2) |
| `consortium/federated_did.go` | `VendorDIDResolver` (§17.2), `BuildCrossLogProof` (§24.1) |
| `consortium/mapping_escrow.go` | `MappingEscrow` (§28), `SplitGF256`, `EncryptForNode` (§15) |
| `consortium/load_accounting/schema.go` | `BuildSchemaEntry` (§11.3) |
| `consortium/load_accounting/fire_drills.go` | `ContentStore.Exists` (§8.2), `BuildCommentary` (§11.3) |
| `consortium/load_accounting/aggregator.go` | `ScanFromPosition` (§27.3), `ClassifyEntry` (§11.1) |
| `consortium/load_accounting/settlement.go` | `BuildCommentary` (§11.3), `ExecuteRemoval` (§20.2) |

**Correction #4 context:** `membership.go` uses `ExecuteRemoval` +
`ActivateRemoval` (guide §20.2). The removal time-lock is 90 days
default, 7 days with objective triggers (`TriggerEquivocation`,
`TriggerMissedSLA`, `TriggerEscrowLiveness`, `TriggerUnauthorizedAction`).

### 1.2 Migration (3 files)

| File | SDK primitives (guide §) |
|------|--------------------------|
| `migration/graceful.go` | `BuildSuccession` (§11.3), `BuildAmendment` (§11.3), `ReEncryptWithGrant` (§20.4) |
| `migration/ungraceful.go` | `InitiateRecovery`, `CollectShares`, `ExecuteRecovery`, `EvaluateArbitration` (§20.3) |
| `migration/bulk_historical.go` | `BuildRootEntity` (§11.3), `ProcessWithRetry` (§10.2) |

**`ungraceful.go` carries correction #4:** uses `ActivateRemoval` (guide
§20.2) for the N-1 scope removal that ejects a failed exchange. The
`ActivateRemovalParams` carries `EvidencePointers` referencing objective
triggers.

### 1.3 Deployments — TEMPLATE (11 files)

Config templates. No Go code except bootstrap/verify scripts.

| File | Purpose |
|------|---------|
| `deployments/TEMPLATE/config/court.yaml` | Institutional DID + name |
| `deployments/TEMPLATE/config/logs.yaml` | Three log DIDs |
| `deployments/TEMPLATE/config/anchor.yaml` | Parent anchor log (optional) |
| `deployments/TEMPLATE/config/exchange.yaml` | Exchange DID + endpoint |
| `deployments/TEMPLATE/config/storage.yaml` | Backend (gcs/s3/ipfs) + credentials |
| `deployments/TEMPLATE/config/schemas.yaml` | Schema URIs to adopt |
| `deployments/TEMPLATE/config/witnesses.yaml` | Witness set + quorum K |
| `deployments/TEMPLATE/config/monitoring.yaml` | Alert destinations + thresholds |
| `deployments/TEMPLATE/config/escrow.yaml` | Escrow nodes + M-of-N |
| `deployments/TEMPLATE/bootstrap.sh` | Calls `ProvisionCourt` + submits entries |
| `deployments/TEMPLATE/verify.sh` | Calls `EvaluateOrigin` on scope entity |

**Eliminated:** `access_tiers.yaml` (no access tiers).

### 1.4 Deployments — Davidson County (14 files)

| File | Purpose |
|------|---------|
| `deployments/davidson_county/README.md` | Deployment-specific documentation |
| `deployments/davidson_county/config/court.yaml` | `did:web:courts.nashville.gov` |
| `deployments/davidson_county/config/logs.yaml` | Three Davidson log DIDs |
| `deployments/davidson_county/config/anchor.yaml` | TN state anchor log |
| `deployments/davidson_county/config/exchange.yaml` | Davidson exchange DID |
| `deployments/davidson_county/config/storage.yaml` | GCS backend + bucket |
| `deployments/davidson_county/config/schemas.yaml` | All judicial schemas |
| `deployments/davidson_county/config/witnesses.yaml` | 3-of-4 witness set |
| `deployments/davidson_county/config/monitoring.yaml` | PagerDuty + log alerts |
| `deployments/davidson_county/config/escrow.yaml` | 3-of-5 escrow nodes |
| `deployments/davidson_county/daily_docket.go` | Daily docket generation |
| `deployments/davidson_county/court_ops.go` | Court operations helpers |
| `deployments/davidson_county/bootstrap.sh` | Davidson-specific bootstrap |
| `deployments/davidson_county/verify.sh` | Davidson-specific verification |

**Eliminated:** `access_tiers.yaml`.

---

## Phase 2 — Public API (12 files)

The read-side HTTP API for public transparency. Everyone gets the same
access. No tiers. Rate limiting via Cloudflare externally.

| File | SDK primitives (guide §) |
|------|--------------------------|
| `public_api/server.go` | HTTP server + route registration |
| `public_api/handlers/case_lookup.go` | `EvaluateOrigin` (§23.1), `EvaluateAuthority` (§23.2) |
| `public_api/handlers/party_search.go` | `QueryBySignerDID` (§27.3) |
| `public_api/handlers/verify_order.go` | `EvaluateConditions`, `EvaluateContest` (§§23.3, 23.4) |
| `public_api/handlers/bulk_verify.go` | Batch `EvaluateOrigin` |
| `public_api/handlers/case_documents.go` | `QueryByTargetRoot` (§27.3) |
| `public_api/handlers/document_download.go` | `VerifyAndDecryptArtifact` (§20.4) |
| `public_api/handlers/evidence_chain.go` | `VerifyCrossLogProof` (§24.1) |
| `public_api/handlers/party_batch.go` | Batch `QueryBySignerDID` |
| `public_api/middleware/proof_attachment.go` | `GenerateMembershipProof` (§6.5) |
| `public_api/middleware/sealed_filter.go` | `EvaluateAuthority` — uniform 404 for sealed cases |
| `storage/delivery_adapter.go` | `RetrievalProvider.Resolve` (§8.3) — routes signed_url/ipfs/direct |

**Open question:** `document_download.go` crypto model. Two options:
(a) Server holds well-known reader keypair, re-encrypts, serves plaintext.
(b) AES-GCM with keys in public registry, serves ciphertext + key.

**What's NOT here:** `middleware/metering.go` (eliminated — no access tiers).

---

## Phase 3 — Tests (18 files)

Integration tests covering every major workflow across all waves.

| File | Covers |
|------|--------|
| `tests/provision_test.go` | `ProvisionCourt` → 3× `ProvisionSingleLog` round-trip |
| `tests/filing_test.go` | Case filing via Path A and Path B |
| `tests/sealing_test.go` | Seal → activate → unseal lifecycle |
| `tests/evidence_grant_test.go` | AES-GCM and Umbral PRE grant flows |
| `tests/appeal_test.go` | Appeal initiation → record transfer → mandate |
| `tests/delegation_chain_test.go` | Depth-1, depth-2, depth-3, revocation cascade |
| `tests/expungement_test.go` | Cryptographic erasure + key destruction |
| `tests/party_binding_test.go` | Party binding + sealed variant |
| `tests/schema_adoption_test.go` | `WalkSchemaChain` + `EvaluateMigration` |
| `tests/consortium_formation_test.go` | Multi-county scope creation + membership |
| `tests/consortium_settlement_test.go` | Load accounting + settlement |
| `tests/migration_graceful_test.go` | Exchange A → Exchange B graceful transfer |
| `tests/migration_ungraceful_test.go` | Recovery + arbitration + `ActivateRemoval` |
| `tests/cross_jurisdiction_test.go` | Cross-log compound proof verification |
| `tests/monitoring_test.go` | Anchor freshness, blob availability, sealing compliance |
| `tests/public_api_test.go` | HTTP handler round-trips |
| `tests/did_mapping_test.go` | `CourtMapping`, `JNetMapping`, `CCRMapping` transforms |
| `tests/bulk_import_test.go` | Historical case import + `ProcessWithRetry` |

---

## Summary

| Phase | Files | Scope |
|-------|-------|-------|
| Phase 0 | 3 | **Delivered.** Compilation fix. |
| Phase 1 | 36 | Consortium, migration, deployments |
| Phase 2 | 12 | Public API |
| Phase 3 | 18 | Integration tests |
| **Total remaining** | **66** | |

**Eliminated:** CMS integration (6 files). External systems' job.

---

## Correction Tracker

| # | Correction | Status |
|---|-----------|--------|
| 1 | `VerifyDelegationProvenance` | Applied (Waves 1-3) |
| 2 | `EvaluateOrigin` | Applied (Waves 1-3) |
| 3 | `EvaluateAuthority` in compliance.go | Applied (Wave 4) |
| 4 | `ActivateRemoval` | **Phase 1** — `migration/ungraceful.go` |
| 5 | `CheckFreshnessNow` | Applied (Wave 4) |
| 6 | `EvaluateMigration` | Applied (Wave 4) |
| 7 | `EvaluateContest` | Applied (Wave 4) |

---

## Bug Tracker

### Fixed (Wave 4)

| § | Bug | Fix |
|---|-----|-----|
| 5.1 | `CheckSealingActivation` never passes Now/Cosignatures | `time.Time` + cosignatures passed through |
| 5.2 | `TransferRecord` publishes CID string as plaintext | Real retrieve+republish |
| 5.4 | `compliance.go` missing | Created with `EvaluateAuthority` |
| 5.10 | Duck-typed time interface | Replaced with `time.Time` |

### Outstanding (non-blocking)

| § | Bug | Severity | Target |
|---|-----|----------|--------|
| 5.5 | Manual PRE capsule encoding | Fragility | Phase 2+ |
| 5.6 | Hardcoded scan limit 200 | Magic number | Phase 2 |
| 5.7 | Path A detection implicit | Robustness | Phase 2 |
| 5.8 | No batch atomicity in BulkImport | Design | Phase 1 |
| 5.9 | Docket query scan inefficiency | Scalability | Phase 2 |
| 5.11 | Schema registration count drift | Consistency | Next revision |

---

## Access Tier Elimination — Complete

Zero tier references in Go source (verified by grep). Five plan.md lines
to remove. File counts: 149 → 145. Not tiering: `DisclosureScopeType`
(judicial ruling), `GrantAuthorizationMode` (court-ordered sealing),
`BulkImport.RateLimit` (operational pacing).

---

## Infrastructure Gaps (Operator, parallel track)

| Gap | Effort | Priority |
|-----|--------|----------|
| Per-exchange admission rate cap (`api/middleware/per_exchange_rate.go`) | ~100 lines | High |
| Faster difficulty signal (rate-of-change on queue depth) | ~50 lines | Medium |
| Storage accounting (bytes per exchange) | ~100 lines | Low |
| Short-expiry retrieval credentials (config change) | 0 lines | Medium |

These proceed independently of Phases 1-3. They're operator concerns,
not judicial-network code.

---

## Bulk Ingestion & Freeloader Defense

**Write:** Mode A credits + Mode B PoW + dynamic difficulty + 1MB cap +
per-exchange rate cap (gap §above).

**Read:** Cloudflare externally. Public API intentionally free. Short-expiry
retrieval credentials make `/resolve` the authenticated choke point.

**Consortium leech:** `blob_availability.go` (Wave 4, on disk) detects
missing pins. Settlement via `load_accounting/` (Phase 1). Enforcement
via scope removal with 7-day objective triggers.

**Escrow:** Paid for liveness (cosignature SLA), not storage. Fire drills
measure responsiveness. SLA failures → objective trigger → 7-day removal.