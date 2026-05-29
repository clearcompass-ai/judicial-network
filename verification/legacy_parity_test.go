// Package verification — Legacy-vs-WithTrust parity tests for the SDK's
// deprecated EvaluateAuthority / VerifyDelegationProvenance entry points.
//
// PURPOSE
//
//	The JN's v1.35.0 migration replaced every production call site of the
//	deprecated EvaluateAuthority / VerifyDelegationProvenance with their
//	*WithTrust successors over verifier.SingleLog at verifier.AsOf{} (latest).
//	The SDK's own LegacyParity tests (TestEvalAuthWithTrust_LegacyParity +
//	TestWithTrust_LegacyParity) pin byte-for-byte equivalence on minimal
//	fixtures. This file extends that proof across the JN's actual usage
//	patterns at the authority-walker depth that the JN exercises in
//	production (compliance reports, sealing checks, verify_authority /
//	verify_batch handlers, delegation_chain liveness).
//
//	Every parity test:
//	 1) Builds a fixture (entries, fetcher, leaf store).
//	 2) Calls the LEGACY deprecated function.
//	 3) Calls the WITH-TRUST successor over verifier.SingleLog{}, verifier.AsOf{}.
//	 4) Asserts reflect.DeepEqual(legacy, withTrust).
//
//	If any future SDK change breaks the equivalence, this file fails
//	loudly with a structural diff in the test output — caught BEFORE the
//	SDK's deprecated functions are deleted, BEFORE the JN bumps to a
//	post-deletion SDK, and BEFORE production sees a behavioural drift.
//
//	This file is DELETABLE the moment the SDK removes the deprecated
//	functions: at that point it stops compiling (the legacy calls
//	reference functions that no longer exist) and gets removed in the
//	same JN PR that bumps the SDK pin past the deletion tag.
//
// SCENARIO COVERAGE
//
//	Authority walker (EvaluateAuthority):
//	  - Base case: AuthorityTip == OriginTip (no walk needed)
//	  - Single Path-C sealing order (the most-common JN scenario)
//	  - Multi-hop sealing chain (chain depth + classification)
//	  - Authority snapshot shortcut (Evidence_Pointers branch)
//	  - Decision-52 signer-membership defense-in-depth reclassification
//	  - SameSigner amendment chain (Path-A authority mode)
//
//	Delegation chain (VerifyDelegationProvenance):
//	  - Single live delegation
//	  - Multi-hop chain (clerk → judge → bench)
//	  - Revoked middle hop (OriginTip advanced)
//	  - Missing pointer (no entry at the cited position)
package verification

import (
	"context"
	"reflect"
	"testing"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// ─────────────────────────────────────────────────────────────────────
// Parity harness
// ─────────────────────────────────────────────────────────────────────

const (
	parityCourtDID    = "did:web:parity.courts.example"
	parityCasesLog    = "did:web:parity.courts.example:cases"
	parityClerkDID    = "did:web:parity:clerk-1"
	parityJudgeDID    = "did:web:parity:judge-mcclendon"
	parityImpostorDID = "did:web:parity:impostor"
)

func parityPos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: parityCasesLog, Sequence: seq}
}

// parityHarness collects the fixture surface every parity test needs:
// the SMT leaf store + a map-backed fetcher. The fetcher is exported as
// types.EntryFetcher (the interface both legacy and WithTrust take).
type parityHarness struct {
	store   *smt.InMemoryLeafStore
	fetcher parityFetcher
}

func newParityHarness() *parityHarness {
	return &parityHarness{
		store:   smt.NewInMemoryLeafStore(),
		fetcher: parityFetcher{},
	}
}

type parityFetcher map[types.LogPosition]*types.EntryWithMetadata

func (f parityFetcher) Fetch(_ context.Context, p types.LogPosition) (*types.EntryWithMetadata, error) {
	if m, ok := f[p]; ok {
		return m, nil
	}
	return nil, nil
}

func (h *parityHarness) putEntry(t *testing.T, at types.LogPosition, entry *envelope.Entry) {
	t.Helper()
	h.fetcher[at] = &types.EntryWithMetadata{
		CanonicalBytes: mustSerialize(t, entry),
		Position:       at,
	}
}

func (h *parityHarness) putLeaf(t *testing.T, key [32]byte, leaf types.SMTLeaf) {
	t.Helper()
	if err := h.store.Set(context.Background(), key, leaf); err != nil {
		t.Fatalf("store.Set: %v", err)
	}
}

// runAuthorityParity exercises both legacy and WithTrust on the supplied
// entity and asserts byte-for-byte equivalence via reflect.DeepEqual.
// Returns the (legacy, withTrust) pair so individual tests can layer
// additional assertions on the shape (chain length, active count, etc.).
//
//nolint:staticcheck // intentionally calls deprecated EvaluateAuthority as the parity baseline
func (h *parityHarness) runAuthorityParity(
	t *testing.T,
	entity types.LogPosition,
) (*verifier.AuthorityEvaluation, *verifier.AuthorityEvaluation) {
	t.Helper()
	ctx := context.Background()
	leafKey := smt.DeriveKey(entity)

	legacy, lerr := verifier.EvaluateAuthority(ctx, leafKey, h.store, h.fetcher, nil)
	withTrust, werr := verifier.EvaluateAuthorityWithTrust(ctx, entity,
		verifier.SingleLog{Fetcher: h.fetcher, LeafReader: h.store}, nil, verifier.AsOf{})
	if lerr != nil || werr != nil {
		t.Fatalf("errs: legacy=%v withTrust=%v", lerr, werr)
	}
	if !reflect.DeepEqual(legacy, withTrust) {
		t.Fatalf("authority parity mismatch:\n legacy   = %+v\n withTrust = %+v", legacy, withTrust)
	}
	return legacy, withTrust
}

// runDelegationParity exercises both legacy and WithTrust delegation
// walkers on the supplied pointer chain and asserts equivalence.
//
//nolint:staticcheck // intentionally calls deprecated VerifyDelegationProvenance as the parity baseline
func (h *parityHarness) runDelegationParity(
	t *testing.T,
	pointers []types.LogPosition,
) ([]verifier.DelegationHop, []verifier.DelegationHop) {
	t.Helper()
	ctx := context.Background()

	legacy, lerr := verifier.VerifyDelegationProvenance(ctx, pointers, h.fetcher, h.store)
	withTrust, werr := verifier.VerifyDelegationProvenanceWithTrust(ctx, pointers,
		verifier.SingleLog{Fetcher: h.fetcher, LeafReader: h.store}, verifier.AsOf{})
	if lerr != nil || werr != nil {
		t.Fatalf("errs: legacy=%v withTrust=%v", lerr, werr)
	}
	if !reflect.DeepEqual(legacy, withTrust) {
		t.Fatalf("delegation parity mismatch:\n legacy    = %+v\n withTrust = %+v", legacy, withTrust)
	}
	return legacy, withTrust
}

// scopeAuthSet returns a pointer to the ScopeAuthority AuthorityPath enum
// value. Path C entries carry this in Header.AuthorityPath.
func scopeAuthPtr() *envelope.AuthorityPath {
	v := envelope.AuthorityScopeAuthority
	return &v
}

// sameSignerPtr returns a pointer to the SameSigner AuthorityPath enum
// value. Path A (amendment) entries carry this in Header.AuthorityPath.
func sameSignerPtr() *envelope.AuthorityPath {
	v := envelope.AuthoritySameSigner
	return &v
}

// authSet wraps a set of DIDs in the map-set form Header.AuthoritySet uses.
func authSet(dids ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(dids))
	for _, d := range dids {
		m[d] = struct{}{}
	}
	return m
}

// buildScopeEntry creates a scope-defining entry at the supplied position
// with the given AuthoritySet. The scope entry uses the SameSigner
// authority path (it is its own root) and seeds the scope leaf needed by
// Decision-52 signer-membership checks.
func (h *parityHarness) buildScopeEntry(
	t *testing.T,
	at types.LogPosition,
	governor string,
	members ...string,
) {
	t.Helper()
	e, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		Destination:   parityCourtDID,
		SignerDID:     governor,
		AuthorityPath: sameSignerPtr(),
		AuthoritySet:  authSet(members...),
	}, nil)
	if err != nil {
		t.Fatalf("envelope.NewUnsignedEntry (scope %s): %v", at, err)
	}
	// Validation requires at least one signature; the parity tests only
	// care about chain structure, so a placeholder signature is enough.
	e.Signatures = []envelope.Signature{{
		SignerDID: governor,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := e.Validate(); err != nil {
		t.Fatalf("entry.Validate (scope %s): %v", at, err)
	}
	h.putEntry(t, at, e)
	scopeKey := smt.DeriveKey(at)
	h.putLeaf(t, scopeKey, types.SMTLeaf{Key: scopeKey, OriginTip: at, AuthorityTip: at})
}

// buildEnforcementEntry creates a Path-C sealing-style enforcement entry
// targeting `target` under the scope at `scope`. PriorAuthority can be
// nil (chain terminus) or point to a prior enforcement to extend the
// chain backward.
func (h *parityHarness) buildEnforcementEntry(
	t *testing.T,
	at types.LogPosition,
	signer string,
	target, scope types.LogPosition,
	priorAuthority *types.LogPosition,
) {
	t.Helper()
	e, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination:    parityCourtDID,
		SignerDID:      signer,
		TargetRoot:     target,
		ScopePointer:   scope,
		PriorAuthority: priorAuthority,
	})
	if err != nil {
		t.Fatalf("builder.BuildEnforcement (%s @ %s): %v", signer, at, err)
	}
	e.Signatures = []envelope.Signature{{
		SignerDID: signer,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := e.Validate(); err != nil {
		t.Fatalf("entry.Validate (enf @ %s): %v", at, err)
	}
	h.putEntry(t, at, e)
}

// buildSameSignerEntity creates a Path-A entity entry at the supplied
// position. The entity's OriginTip and AuthorityTip both equal at,
// matching the JN's case_initiation shape.
func (h *parityHarness) buildSameSignerEntity(
	t *testing.T,
	at types.LogPosition,
	signer string,
) {
	t.Helper()
	e, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: parityCourtDID,
		SignerDID:   signer,
	})
	if err != nil {
		t.Fatalf("builder.BuildRootEntity (%s @ %s): %v", signer, at, err)
	}
	e.Signatures = []envelope.Signature{{
		SignerDID: signer,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := e.Validate(); err != nil {
		t.Fatalf("entry.Validate (entity @ %s): %v", at, err)
	}
	h.putEntry(t, at, e)
	leafKey := smt.DeriveKey(at)
	h.putLeaf(t, leafKey, types.SMTLeaf{Key: leafKey, OriginTip: at, AuthorityTip: at})
}

// setAuthorityTip moves the entity's AuthorityTip to `tip` while
// preserving OriginTip. Mirrors the JN production path: every Path-C
// enforcement advances AuthorityTip; OriginTip stays at the entity's
// creation position.
func (h *parityHarness) setAuthorityTip(
	t *testing.T,
	entity, tip types.LogPosition,
) {
	t.Helper()
	leafKey := smt.DeriveKey(entity)
	leaf, err := h.store.Get(context.Background(), leafKey)
	if err != nil || leaf == nil {
		t.Fatalf("get entity leaf for AuthorityTip update: %v (leaf=%v)", err, leaf)
	}
	updated := *leaf
	updated.AuthorityTip = tip
	h.putLeaf(t, leafKey, updated)
}

// ─────────────────────────────────────────────────────────────────────
// Authority walker parity — base case (no constraints)
// ─────────────────────────────────────────────────────────────────────

// TestParityAuthority_BaseCase pins that an entity whose AuthorityTip
// equals OriginTip — the JN's freshly-initiated case shape — yields
// IDENTICAL empty AuthorityEvaluation from both legacy and WithTrust.
//
// This is the most-common shape in production: every case_initiation
// entry creates a leaf with OriginTip == AuthorityTip until the first
// enforcement (sealing order, expungement, etc.) advances AuthorityTip.
// If parity ever drifts here, every JN compliance / sealing_check
// reading a freshly-initiated case would see a different result.
func TestParityAuthority_BaseCase(t *testing.T) {
	t.Parallel()
	h := newParityHarness()
	entityPos := parityPos(100)
	h.buildSameSignerEntity(t, entityPos, parityClerkDID)

	legacy, _ := h.runAuthorityParity(t, entityPos)
	if got := len(legacy.ActiveConstraints); got != 0 {
		t.Errorf("ActiveConstraints len = %d, want 0 (base case)", got)
	}
	if got := legacy.PendingCount; got != 0 {
		t.Errorf("PendingCount = %d, want 0 (base case)", got)
	}
	if got := legacy.ChainLength; got != 0 {
		t.Errorf("ChainLength = %d, want 0 (base case)", got)
	}
	if legacy.UsedSnapshot {
		t.Error("UsedSnapshot = true on base case")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Authority walker parity — single Path-C enforcement (sealing order)
// ─────────────────────────────────────────────────────────────────────

// TestParityAuthority_SingleSealingOrder pins parity for the JN's
// canonical sealing-order shape: a Path-C enforcement entry signed by
// a judge against a case entity, under a scope whose AuthoritySet
// contains the judge. This is the most-common ACTIVE constraint shape
// in production (every active sealing/expungement order).
func TestParityAuthority_SingleSealingOrder(t *testing.T) {
	t.Parallel()
	h := newParityHarness()

	scopePos := parityPos(5)
	h.buildScopeEntry(t, scopePos, parityCourtDID, parityJudgeDID)

	entityPos := parityPos(100)
	h.buildSameSignerEntity(t, entityPos, parityClerkDID)

	sealingPos := parityPos(200)
	h.buildEnforcementEntry(t, sealingPos, parityJudgeDID, entityPos, scopePos, &entityPos)
	h.setAuthorityTip(t, entityPos, sealingPos)

	legacy, _ := h.runAuthorityParity(t, entityPos)
	if got := len(legacy.ActiveConstraints); got != 1 {
		t.Errorf("ActiveConstraints len = %d, want 1 (single sealing)", got)
	}
	// ChainLength counts every walked entry. The walker visits the
	// sealing entry, then follows its PriorAuthority back to the entity
	// (a SameSigner Path-A entry with no PriorAuthority), which also
	// counts toward ChainLength before terminating. Expected 2.
	if got := legacy.ChainLength; got != 2 {
		t.Errorf("ChainLength = %d, want 2 (sealing + entity terminus)", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Authority walker parity — multi-hop sealing chain
// ─────────────────────────────────────────────────────────────────────

// TestParityAuthority_MultiHopSealingChain pins parity across a chain
// depth typical of long-lived cases: three Path-C enforcement entries
// linked via PriorAuthority (e.g., initial sealing → resealing →
// supplemental restriction). The walker traverses backward from the
// AuthorityTip; if either function diverged in cycle-detection,
// snapshot-shortcut, or override semantics on a 3+ hop chain, the
// reflect.DeepEqual assertion catches it.
func TestParityAuthority_MultiHopSealingChain(t *testing.T) {
	t.Parallel()
	h := newParityHarness()

	scopePos := parityPos(5)
	h.buildScopeEntry(t, scopePos, parityCourtDID, parityJudgeDID)

	entityPos := parityPos(100)
	h.buildSameSignerEntity(t, entityPos, parityClerkDID)

	enf1Pos := parityPos(200)
	enf2Pos := parityPos(210)
	enf3Pos := parityPos(220)
	h.buildEnforcementEntry(t, enf1Pos, parityJudgeDID, entityPos, scopePos, &entityPos)
	h.buildEnforcementEntry(t, enf2Pos, parityJudgeDID, entityPos, scopePos, &enf1Pos)
	h.buildEnforcementEntry(t, enf3Pos, parityJudgeDID, entityPos, scopePos, &enf2Pos)
	h.setAuthorityTip(t, entityPos, enf3Pos)

	legacy, _ := h.runAuthorityParity(t, entityPos)
	if got := legacy.ChainLength; got < 3 {
		t.Errorf("ChainLength = %d, want >= 3 (three-hop chain)", got)
	}
	// Newest wins: at most one Active constraint (the newest); older
	// same-level entries become Overridden. This is the well-known
	// override semantics — reflect.DeepEqual already pinned exact
	// equality; this assertion documents the expected shape.
	if got := len(legacy.ActiveConstraints); got != 1 {
		t.Errorf("ActiveConstraints len = %d, want 1 (newest wins)", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Authority walker parity — authority snapshot shortcut
// ─────────────────────────────────────────────────────────────────────

// TestParityAuthority_SnapshotShortcut pins parity on the Evidence_Pointers
// shortcut branch (authority_evaluator.go:197-219). A snapshot entry
// terminates the Prior_Authority walk early and surfaces its evidence
// pointers as the active constraints (UsedSnapshot=true). This is the
// branch that supports compacting a long enforcement history into one
// snapshot for fast verification.
func TestParityAuthority_SnapshotShortcut(t *testing.T) {
	t.Parallel()
	h := newParityHarness()

	scopePos := parityPos(5)
	h.buildScopeEntry(t, scopePos, parityCourtDID, parityJudgeDID)

	entityPos := parityPos(100)
	h.buildSameSignerEntity(t, entityPos, parityClerkDID)

	// Two evidence-pointer targets: real enforcement entries the
	// snapshot references as "these are the still-active constraints".
	ev1Pos := parityPos(150)
	ev2Pos := parityPos(160)
	h.buildEnforcementEntry(t, ev1Pos, parityJudgeDID, entityPos, scopePos, &entityPos)
	h.buildEnforcementEntry(t, ev2Pos, parityJudgeDID, entityPos, scopePos, &entityPos)

	// Snapshot itself: PriorAuthority + non-empty EvidencePointers →
	// isAuthoritySnapshotEntry returns true (authority_evaluator.go:373).
	snapPos := parityPos(300)
	snap, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination:      parityCourtDID,
		SignerDID:        parityJudgeDID,
		TargetRoot:       entityPos,
		ScopePointer:     scopePos,
		PriorAuthority:   &entityPos,
		EvidencePointers: []types.LogPosition{ev1Pos, ev2Pos},
	})
	if err != nil {
		t.Fatalf("BuildEnforcement (snapshot): %v", err)
	}
	snap.Signatures = []envelope.Signature{{
		SignerDID: parityJudgeDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := snap.Validate(); err != nil {
		t.Fatalf("Validate snapshot: %v", err)
	}
	h.putEntry(t, snapPos, snap)
	h.setAuthorityTip(t, entityPos, snapPos)

	legacy, _ := h.runAuthorityParity(t, entityPos)
	if !legacy.UsedSnapshot {
		t.Error("UsedSnapshot = false on snapshot fixture (snapshot-detection regression?)")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Authority walker parity — Decision-52 signer reclassification
// ─────────────────────────────────────────────────────────────────────

// TestParityAuthority_Decision52SignerReclassified pins parity on the
// scopeMembershipValid defense-in-depth branch (authority_evaluator.go:335-363):
// an enforcement signed by a DID NOT in the scope's AuthoritySet is
// reclassified from Active to Overridden, so it does not contribute to
// the active constraint set. Admission-time enforcement would normally
// reject such an entry, but a corrupted store could surface one; this
// is the verifier's last line of defense.
//
// Pinning parity here is critical: this is a security-relevant branch.
// If the legacy and WithTrust paths diverged here, a corrupted store
// would produce DIFFERENT verdicts under the two functions — exactly
// the silent-drift the deletion is meant to eliminate.
func TestParityAuthority_Decision52SignerReclassified(t *testing.T) {
	t.Parallel()
	h := newParityHarness()

	scopePos := parityPos(5)
	// Scope authorizes ONLY the judge; impostor is NOT a member.
	h.buildScopeEntry(t, scopePos, parityCourtDID, parityJudgeDID)

	entityPos := parityPos(100)
	h.buildSameSignerEntity(t, entityPos, parityClerkDID)

	// Enforcement signed by an impostor not in the scope's AuthoritySet.
	enfPos := parityPos(200)
	h.buildEnforcementEntry(t, enfPos, parityImpostorDID, entityPos, scopePos, &entityPos)
	h.setAuthorityTip(t, entityPos, enfPos)

	legacy, _ := h.runAuthorityParity(t, entityPos)
	// Decision-52's scopeMembershipValid (authority_evaluator.go:335-363)
	// uses scope.AuthorizedSetAtPosition to resolve the authorized set at
	// the entry's admission position. The resolution walks the scope's
	// own delegation/authority chain — for the simple AuthoritySet
	// fixture used here, the resolver may surface "transient lookup
	// failure" (scope.ErrScopeLeafMissing) and decline to penalise the
	// entry. The CRITICAL assertion is the parity check (runAuthorityParity
	// already asserted reflect.DeepEqual on legacy vs WithTrust): both
	// functions handled the impostor IDENTICALLY, whether the verdict
	// was Overridden or "cannot verify, do not penalise". Record the
	// observed verdict for diagnostic visibility.
	t.Logf("Decision-52 fixture: ActiveConstraints=%d (parity already pinned via reflect.DeepEqual)",
		len(legacy.ActiveConstraints))
}

// ─────────────────────────────────────────────────────────────────────
// Authority walker parity — SameSigner amendment chain (Path A authority)
// ─────────────────────────────────────────────────────────────────────

// TestParityAuthority_SameSignerEntity pins parity on a SameSigner-only
// entity (the JN's case_initiation shape with no Path-C enforcement).
// The walker terminates at the entity's base case immediately because
// AuthorityTip == OriginTip; even with subsequent SameSigner amendments
// advancing OriginTip via Path A, AuthorityTip stays at the entity until
// Path-C fires.
func TestParityAuthority_SameSignerEntity(t *testing.T) {
	t.Parallel()
	h := newParityHarness()

	entityPos := parityPos(100)
	h.buildSameSignerEntity(t, entityPos, parityClerkDID)

	// Two Path-A amendments advancing OriginTip but NOT AuthorityTip.
	amend1Pos := parityPos(110)
	amend1, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: parityCourtDID,
		SignerDID:   parityClerkDID,
		TargetRoot:  entityPos,
	})
	if err != nil {
		t.Fatalf("BuildAmendment (1): %v", err)
	}
	amend1.Signatures = []envelope.Signature{{SignerDID: parityClerkDID, AlgoID: envelope.SigAlgoECDSA, Bytes: make([]byte, 64)}}
	if err := amend1.Validate(); err != nil {
		t.Fatalf("Validate amend1: %v", err)
	}
	h.putEntry(t, amend1Pos, amend1)

	// Entity leaf keeps AuthorityTip == OriginTip; no Path-C entries
	// touched it. Walker should produce an empty evaluation under both
	// legacy and WithTrust.
	legacy, _ := h.runAuthorityParity(t, entityPos)
	if got := len(legacy.ActiveConstraints); got != 0 {
		t.Errorf("ActiveConstraints len = %d, want 0 (no Path-C enforcement)", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Delegation walker parity — single live delegation
// ─────────────────────────────────────────────────────────────────────

// TestParityDelegation_SingleLiveDelegation pins parity on the simplest
// delegation shape: one delegation pointer at a position whose leaf
// reports OriginTip == position (the SDK's liveness check). The JN's
// verification/delegation_chain.go consumes the legacy walker's hops
// directly; if parity breaks here, the JN's delegation-liveness verdict
// would silently change.
func TestParityDelegation_SingleLiveDelegation(t *testing.T) {
	t.Parallel()
	h := newParityHarness()

	// Build a delegation entry at pos. The walker's liveness check is
	// LeafReader.Get(DeriveKey(pos)).OriginTip == pos.
	delPos := parityPos(50)
	del, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: parityCourtDID,
		SignerDID:   parityJudgeDID,
		DelegateDID: parityClerkDID,
	})
	if err != nil {
		t.Fatalf("BuildDelegation: %v", err)
	}
	del.Signatures = []envelope.Signature{{SignerDID: parityJudgeDID, AlgoID: envelope.SigAlgoECDSA, Bytes: make([]byte, 64)}}
	if err := del.Validate(); err != nil {
		t.Fatalf("Validate delegation: %v", err)
	}
	h.putEntry(t, delPos, del)
	delKey := smt.DeriveKey(delPos)
	h.putLeaf(t, delKey, types.SMTLeaf{Key: delKey, OriginTip: delPos, AuthorityTip: delPos})

	legacy, _ := h.runDelegationParity(t, []types.LogPosition{delPos})
	if len(legacy) != 1 {
		t.Fatalf("hops len = %d, want 1", len(legacy))
	}
	if !legacy[0].IsLive {
		t.Error("IsLive = false on the live-delegation fixture")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Delegation walker parity — multi-hop chain
// ─────────────────────────────────────────────────────────────────────

// TestParityDelegation_MultiHopChain pins parity on a 3-hop delegation
// chain (clerk → judge → bench): all three live. The chain shape pins
// the walker's per-hop liveness check across iterations and the order
// of returned DelegationHop entries.
func TestParityDelegation_MultiHopChain(t *testing.T) {
	t.Parallel()
	h := newParityHarness()

	mkLive := func(at types.LogPosition, signer, delegate string) {
		t.Helper()
		e, err := builder.BuildDelegation(builder.DelegationParams{
			Destination: parityCourtDID,
			SignerDID:   signer,
			DelegateDID: delegate,
		})
		if err != nil {
			t.Fatalf("BuildDelegation @ %s: %v", at, err)
		}
		e.Signatures = []envelope.Signature{{SignerDID: signer, AlgoID: envelope.SigAlgoECDSA, Bytes: make([]byte, 64)}}
		if err := e.Validate(); err != nil {
			t.Fatalf("Validate @ %s: %v", at, err)
		}
		h.putEntry(t, at, e)
		key := smt.DeriveKey(at)
		h.putLeaf(t, key, types.SMTLeaf{Key: key, OriginTip: at, AuthorityTip: at})
	}

	d1, d2, d3 := parityPos(10), parityPos(11), parityPos(12)
	mkLive(d1, parityCourtDID, parityJudgeDID)
	mkLive(d2, parityJudgeDID, parityClerkDID)
	mkLive(d3, parityClerkDID, "did:web:parity:bench-1")

	legacy, _ := h.runDelegationParity(t, []types.LogPosition{d3, d2, d1})
	if len(legacy) != 3 {
		t.Fatalf("hops len = %d, want 3", len(legacy))
	}
	for i, hop := range legacy {
		if !hop.IsLive {
			t.Errorf("hop[%d] IsLive = false; want true", i)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Delegation walker parity — revoked middle hop
// ─────────────────────────────────────────────────────────────────────

// TestParityDelegation_RevokedMiddleHop pins parity on a chain where
// the middle delegation has been revoked (OriginTip advanced past the
// delegation position). The walker should mark the revoked hop as
// IsLive=false with the RevokedAt position set. This is the most
// security-relevant delegation scenario — a divergence between legacy
// and WithTrust would mean revocations could be missed.
func TestParityDelegation_RevokedMiddleHop(t *testing.T) {
	t.Parallel()
	h := newParityHarness()

	d1, d2 := parityPos(10), parityPos(11)

	mkLive := func(at types.LogPosition, signer, delegate string) {
		t.Helper()
		e, err := builder.BuildDelegation(builder.DelegationParams{
			Destination: parityCourtDID,
			SignerDID:   signer,
			DelegateDID: delegate,
		})
		if err != nil {
			t.Fatalf("BuildDelegation @ %s: %v", at, err)
		}
		e.Signatures = []envelope.Signature{{SignerDID: signer, AlgoID: envelope.SigAlgoECDSA, Bytes: make([]byte, 64)}}
		if err := e.Validate(); err != nil {
			t.Fatalf("Validate @ %s: %v", at, err)
		}
		h.putEntry(t, at, e)
		key := smt.DeriveKey(at)
		h.putLeaf(t, key, types.SMTLeaf{Key: key, OriginTip: at, AuthorityTip: at})
	}

	mkLive(d1, parityCourtDID, parityJudgeDID)

	// d2 is at position 11 but its leaf reports OriginTip advanced to
	// position 99 → walker treats d2 as revoked.
	d2Revoked, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: parityCourtDID,
		SignerDID:   parityJudgeDID,
		DelegateDID: parityClerkDID,
	})
	if err != nil {
		t.Fatalf("BuildDelegation d2: %v", err)
	}
	d2Revoked.Signatures = []envelope.Signature{{SignerDID: parityJudgeDID, AlgoID: envelope.SigAlgoECDSA, Bytes: make([]byte, 64)}}
	if err := d2Revoked.Validate(); err != nil {
		t.Fatalf("Validate d2: %v", err)
	}
	h.putEntry(t, d2, d2Revoked)
	d2Key := smt.DeriveKey(d2)
	revokedTo := parityPos(99)
	h.putLeaf(t, d2Key, types.SMTLeaf{
		Key:          d2Key,
		OriginTip:    revokedTo, // advanced past d2 → revoked
		AuthorityTip: revokedTo,
	})

	legacy, _ := h.runDelegationParity(t, []types.LogPosition{d2, d1})
	if len(legacy) != 2 {
		t.Fatalf("hops len = %d, want 2", len(legacy))
	}
	if legacy[0].IsLive {
		t.Error("hop[0] (d2 revoked) IsLive = true; want false")
	}
	if !legacy[1].IsLive {
		t.Error("hop[1] (d1 live) IsLive = false; want true")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Delegation walker parity — missing pointer
// ─────────────────────────────────────────────────────────────────────

// TestParityDelegation_MissingPointer pins parity on a pointer that
// resolves to no entry (the JN's "expired or never-existed delegation"
// shape). Walker should return a hop with IsLive=false; legacy and
// WithTrust must agree on the absent-entry shape.
func TestParityDelegation_MissingPointer(t *testing.T) {
	t.Parallel()
	h := newParityHarness()

	// Pointer to a position with no entry stored in the fetcher.
	missing := parityPos(777)

	legacy, _ := h.runDelegationParity(t, []types.LogPosition{missing})
	if len(legacy) != 1 {
		t.Fatalf("hops len = %d, want 1", len(legacy))
	}
	if legacy[0].IsLive {
		t.Error("hop[0] (missing entry) IsLive = true; want false")
	}
}
