**All 196 tests pass. Zero failures.** But coverage is thin — only `tests/` has test files. Here's what's needed, organized by the trust architecture you described.

## Testing Philosophy

The judicial-network is infrastructure that tools build on. Tests must prove that **any tool** built on this API can trust the guarantees. Three tiers:

**Tier 1 — Unit tests (no services, mock SDK interfaces)**
Test each package's logic with mocked `smt.LeafReader`, `verifier.EntryFetcher`, `storage.ContentStore`. These run in CI in milliseconds.

**Tier 2 — Integration tests (real SDK, in-memory stores)**
Wire real SDK functions with in-memory leaf stores and entry fetchers. Test complete workflows end-to-end without HTTP.

**Tier 3 — System tests (real services on localhost)**
Full HTTP round-trips against operator, artifact store, exchange. Require `docker-compose` or similar. Run nightly, not on every commit.

## What Needs Tests — By Trust Guarantee

### 1. Entry integrity (the log records what happened)

```
Package: cases/, delegation/, enforcement/
Tests needed:
  - Filing produces correct BuildRootEntity + BuildAmendment entries
  - Judicial action (order, judgment) produces correct Path B entries
  - Sealing order produces correct BuildEnforcement entry
  - Revocation advances OriginTip (delegation broken)
  - Commentary entries (daily docket, recusal) have zero SMT impact
  - Schema_Ref correctly points to adopted schema position
  
Why it matters: Tools trust that entries are well-formed.
A CMS tool calls cases/filing.go — it needs to know the
entry will be accepted by the operator's builder.
```

### 2. Delegation chain correctness (who CAN act)

```
Package: delegation/
Tests needed:
  - Judge delegation at depth 1 (court → judge)
  - Clerk delegation at depth 2 (court → judge → clerk)  
  - Deputy at depth 3 (court → judge → clerk → deputy)
  - Depth 4 rejected (protocol max = 3)
  - Revocation breaks chain for future entries
  - Revocation does NOT invalidate past entries
  - Same DID with delegations on multiple divisions
  - Mirror consistency: delegation on officers → mirrored to cases
  - Roster sync: officers.yaml changes → correct Build/Revoke calls
  
Why it matters: Every tool action goes through delegation.
A filing tool must trust that its delegation chain will verify.
```

### 3. Sealing enforcement (access control works)

```
Package: enforcement/
Tests needed:
  - Sealing order blocks artifact retrieval
  - Unsealing order restores access
  - Expungement: key deletion + CAS deletion = irrecoverable
  - Juvenile auto-seal at disposition (activation_delay=0)
  - Sealing activation delay (72h for criminal)
  - Unsealing requires cosignature (threshold=1)
  - Sealed entries still visible on log (metadata public, content sealed)
  
Why it matters: Sealing is a constitutional requirement.
A public records tool must trust that sealed records are inaccessible.
```

### 4. Artifact lifecycle (documents survive correctly)

```
Package: cases/artifact/
Tests needed:
  - Publish: EncryptArtifact → Compute CID → push to store → return metadata
  - Retrieve: fetch ciphertext → decrypt → verify content digest
  - Re-encrypt: old key → new key, CID changes, content identical
  - Bulk import: N historical documents → N entries with correct CIDs
  - Delegation key isolation: pk_del ≠ pk_owner, wrapping roundtrips
  - Grant: GrantArtifactAccess with sealed vs open authorization modes
  
Why it matters: Evidence integrity. A DA's tool uploads an exhibit —
it needs cryptographic proof the document wasn't tampered with.
```

### 5. Cross-court verification (proofs compose)

```
Package: consortium/, verification/
Tests needed:
  - BuildCrossLogProof between two logs sharing an anchor
  - VerifyCrossLogProof with valid/invalid witness signatures
  - Transitive proof: court A → anchor → court B
  - FederatedResolver handles vendor DID translation
  - Background check across jurisdictions
  
Why it matters: When Shelby County verifies a Davidson County
filing, the proof must be mathematically sound.
```

### 6. Provisioning (new courts work from day one)

```
Package: onboarding/
Tests needed:
  - ProvisionCourt produces 3 LogProvisions
  - Each log has scope entity + delegations + schemas
  - Officer filtering: judge targets officers log only
  - Schema filtering: schemas target cases log only  
  - Schema adoption resolves URIs from registry
  - Anchor registration produces correct BuildAnchorEntry
  - Full bootstrap: provision → adopt → anchor → verify
  
Why it matters: A new county deploying the system must trust
that bootstrap produces a valid, verifiable court.
```

### 7. Migration (custody transfers are safe)

```
Package: migration/
Tests needed:
  - Graceful: succession entries + key rotations + re-encryption
  - Ungraceful: InitiateRecovery → CollectShares → ExecuteRecovery
  - Bulk historical: N cases imported with cross-log references
  - No data loss: every artifact re-encrypted under new keys
  
Why it matters: Vendor transfer is the highest-stakes operation.
A court switching from ClearCompass to NewVendor must trust
that no case data is lost or corrupted.
```

### 8. Verification API (the domain API itself)

```
Package: api/handlers/
Tests needed:
  - GET /v1/verify/origin/{logID}/{pos} → correct OriginEvaluation
  - GET /v1/verify/authority/{logID}/{pos} → correct AuthorityEvaluation
  - GET /v1/verify/delegation/{logID}/{pos} → full delegation tree
  - POST /v1/verify/cross-log → valid/invalid proof responses
  - POST /v1/verify/fraud-proof → correct FraudProofResult
  - GET /v1/verify/batch → multiple positions in one call
  - Unknown log → 404
  - Invalid position → 400
  - operatorFetcher adapter: ScanFromPosition(pos, 1) → EntryFetcher.Fetch
  
Why it matters: This IS the trust surface. Every tool calls these
endpoints. They must return correct, auditable results.
```

## Concrete Next Step

The highest-value tests to write first, in order:

1. **`delegation/` unit tests** — delegation chain is the authorization backbone. Every tool depends on it. Test build + verify + revoke at all 3 depths.

2. **`cases/artifact/` unit tests** — artifact lifecycle is the data integrity backbone. Test encrypt → store → retrieve → decrypt roundtrip.

3. **`api/handlers/` HTTP tests** — the existing `verification_api_test.go` has 196 tests but they test with mock handlers. Need tests wired to real SDK functions with in-memory stores.

4. **`enforcement/` unit tests** — sealing is a legal requirement. Test seal → block → unseal → allow → expunge → irrecoverable.

5. **`onboarding/` integration test** — one test that provisions a full court, bootstraps officers, adopts schemas, and verifies the result using the verification API. This is the "does the whole thing work" test.

Want me to start writing the Tier 1 delegation tests? Those exercise the most critical path and require zero infrastructure.

## BUILD PLAN
Wave 1 — Foundation (does the plumbing work?)
Tests that every other test depends on. If these fail, nothing above them can be trusted.
Packages: onboarding/, delegation/, cases/artifact/, schemas/

Provisioning produces valid 3-log court with scope entities, delegations, schemas
Delegation chain builds correctly at depths 1-3, rejects depth 4
Revocation breaks future signing, preserves past validity
Artifact roundtrip: encrypt → store → retrieve → decrypt → verify digest
Schema registry resolves URIs and produces correct SchemaParameterExtractor output

Why first: A tool that can't provision a court or verify a delegation chain can't do anything else.
Wave 2 — Enforcement (do the rules hold?)
Tests that the domain constraints are enforced — sealing, access control, cross-court trust.
Packages: enforcement/, cases/, verification/, consortium/

Sealing blocks retrieval, unsealing restores it, expungement is irrecoverable
Juvenile auto-seal at disposition (activation_delay=0)
Filing and judicial action produce correct Path A/B entries with Schema_Ref
Cross-court proof builds and verifies through shared anchor
Federated DID resolution translates vendor DIDs correctly

Why second: These depend on Wave 1's plumbing. A sealing test needs a provisioned court with delegated officers and stored artifacts.
Wave 3 — Resilience (does it survive failure?)
Tests for the worst-case scenarios — migration, recovery, API correctness under adversarial input.
Packages: migration/, api/handlers/, monitoring/, deployments/

Graceful migration: succession + key rotation + artifact re-encryption
Ungraceful recovery: escrow share collection → key reconstruction
Verification API: all 6 endpoints return correct results, error cases return proper HTTP codes
operatorFetcher adapter correctly wraps ScanFromPosition
Davidson County bootstrap → verify round-trip

Why last: Migration and API tests are the highest-fidelity tests. They exercise the full stack and prove the system survives vendor transfer — the ultimate trust guarantee.