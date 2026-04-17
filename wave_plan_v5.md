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

## Phase 2 — Four-Layer Service Architecture (21 files)

### Architecture

```
INFRASTRUCTURE (exists — separate repos):
  Operator (Phase 2):       POST /v1/entries, GET /v1/entries/{pos}, tiles
  Artifact Store (Phase 3): POST /v1/artifacts, GET .../resolve

DOMAIN — Verification API (api/, 7 files):
  Read-only. Domain-agnostic. No auth.
  Wraps SDK verifier functions that neither operator nor artifact store runs.

EXCHANGE (exchange/, 9 files):
  Write path. Key custody. mTLS + signed request auth.
  Build → sign → submit entries. Encrypt → push artifacts. Index builder.

BUSINESS — Court API (business/, 5 files):
  Domain-specific (Davidson County). mTLS + on-log delegation for writes.
  Public reads. Sealed filter. Docket search via exchange index.
```

### Auth Model

```
BOUNDARY               MECHANISM                    REVOCATION
─────────────────────────────────────────────────────────────────────
Exchange → Operator     mTLS (DID in cert SAN)       Cert renewal
Signer → Exchange       Signed request (Ed25519)     On-log BuildRevocation
                        OR mTLS                      
CMS → Business API      mTLS + on-log delegation     On-log BuildRevocation
Admin → Business API    mTLS + on-log delegation     On-log BuildRevocation
                        with scope "admin"           
Public reads            None                         N/A (transparency)
```

No tokens. No sessions table. No API keys. No RBAC tables.
The log IS the authorization database.

### 2.1 Domain — Verification API (7 files)

| File | Endpoint | SDK primitive |
|------|----------|---------------|
| `api/server.go` | Route table | — |
| `api/handlers/verify_origin.go` | `GET /v1/verify/origin/{logID}/{pos}` | `EvaluateOrigin` (§23.1) |
| `api/handlers/verify_authority.go` | `GET /v1/verify/authority/{logID}/{pos}` | `EvaluateAuthority` + `CheckActivationReady` + `EvaluateContest` (§§23.2-23.4) |
| `api/handlers/verify_batch.go` | `POST /v1/verify/batch` | Batch `EvaluateOrigin` |
| `api/handlers/verify_delegation.go` | `GET /v1/verify/delegation/{logID}/{did}` | `WalkDelegationTree` + `LiveDelegations` (§24.6) |
| `api/handlers/verify_cross_log.go` | `POST /v1/verify/cross-log` | `VerifyCrossLogProof` (§24.1) |
| `api/handlers/verify_fraud_proof.go` | `POST /v1/verify/fraud-proof` | `VerifyDerivationCommitment` (§24.3) |

### 2.2 Exchange Service (9 files)

| File | Purpose |
|------|---------|
| `exchange/server.go` | mTLS server, route table (~25 endpoints) |
| `exchange/auth/mtls.go` | DID extraction from client cert SAN |
| `exchange/auth/signed_request.go` | Ed25519 signed request verification + nonce store |
| `exchange/handlers/entries.go` | build/sign/submit/full/status |
| `exchange/handlers/artifacts.go` | publish (encrypt+push) + grant |
| `exchange/handlers/management.go` | delegations, keys, DIDs, scope governance |
| `exchange/keystore/keystore.go` | Key custody interface + in-memory impl |
| `exchange/index/scanner.go` | Sequential log reader (CT monitor pattern) |
| `exchange/index/store.go` | docket→pos, DID→pos, CID→pos mappings |

### 2.3 Business — Court API (5 files)

| File | Purpose |
|------|---------|
| `business/server.go` | mTLS server, sealed filter, delegation auth |
| `business/auth/delegation_check.go` | mTLS + on-log delegation verification |
| `business/handlers/cases.go` | case lookup, documents, download (Option B) |
| `business/handlers/operations.go` | filing, party search, officers, daily docket |
| `business/middleware/sealed_filter.go` | Uniform 404 for sealed/expunged (judicial policy) |

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
| `tests/verification_api_test.go` | All 6 verification endpoints |
| `tests/did_mapping_test.go` | `CourtMapping`, `JNetMapping`, `CCRMapping` transforms |
| `tests/bulk_import_test.go` | Historical case import + `ProcessWithRetry` |

---

## Summary

| Phase | Files | Scope |
|-------|-------|-------|
| Phase 0 | 3 | **Delivered.** Compilation fix. |
| Phase 1 | 36 | **Delivered.** Consortium, migration, deployments |
| Phase 2 | 21 | **Delivered.** Domain API, exchange, business |
| Phase 3 | 18 | Tests (not yet) |
| **Total remaining** | **18** | Tests only |

**Eliminated:** CMS integration (6 files). External systems' job.

---

## Correction Tracker

| # | Correction | Status |
|---|-----------|--------|
| 1 | `VerifyDelegationProvenance` | Applied (Waves 1-3) |
| 2 | `EvaluateOrigin` | Applied (Waves 1-3) |
| 3 | `EvaluateAuthority` in compliance.go | Applied (Wave 4) |
| 4 | `ActivateRemoval` | **Applied (Phase 1)** — `migration/ungraceful.go` |
| 5 | `CheckFreshnessNow` | Applied (Wave 4) |
| 6 | `EvaluateMigration` | Applied (Wave 4) |
| 7 | `EvaluateContest` | Applied (Wave 4) |

**All 7 corrections applied.**

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
