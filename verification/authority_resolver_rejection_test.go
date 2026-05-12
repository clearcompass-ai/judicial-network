/*
FILE PATH: verification/authority_resolver_rejection_test.go

DESCRIPTION:

	Rejection-path coverage for AuthorityResolver. Helpers
	(fakeFetcher, makeDelegation, makeRevocation) live in
	authority_resolver_test.go and are shared via the same test
	package.
*/
package verification

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
	davidson "github.com/clearcompass-ai/judicial-network/internal/testfixtures/davidsonlegacy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

func TestAuthorityResolver_RejectsExpired(t *testing.T) {
	f := newFakeFetcher()
	pos := types.LogPosition{LogDID: "did:web:x", Sequence: 1}
	ref, entry := makeDelegation(t, pos, "did:web:x", "did:key:zQ3shS", "judge",
		[]string{"case_filing"}, nil, -time.Hour) // expired
	f.put(pos, entry)

	r := &AuthorityResolver{Fetcher: f, Catalog: davidson.MustRoleCatalog()}
	auth := r.Resolve(ctx, "did:key:zQ3shS", ref, "case_filing")
	if auth.Rejection != RejectExpired {
		t.Errorf("expected RejectExpired, got %s (%s)", auth.Rejection, auth.Reason)
	}
}

func TestAuthorityResolver_RejectsRevocationTip(t *testing.T) {
	f := newFakeFetcher()
	target := schemas.LogPositionRef{LogDID: "did:web:x", Sequence: 1}
	revPos := types.LogPosition{LogDID: "did:web:x", Sequence: 1}
	f.put(revPos, makeRevocation(t, "did:web:x", target))

	r := &AuthorityResolver{Fetcher: f, Catalog: davidson.MustRoleCatalog()}
	auth := r.Resolve(ctx, "did:key:zQ3shS", target, "case_filing")
	if auth.Rejection != RejectRevoked {
		t.Errorf("expected RejectRevoked, got %s (%s)", auth.Rejection, auth.Reason)
	}
}

func TestAuthorityResolver_RejectsScopeOutsideChain(t *testing.T) {
	f := newFakeFetcher()
	institutional := "did:web:state:tn:davidson"
	cjDID := "did:key:zQ3shCJ"

	cjPos := types.LogPosition{LogDID: institutional, Sequence: 1}
	cjRef, cjEntry := makeDelegation(t, cjPos, institutional, cjDID, "chief_justice",
		[]string{"case_filing"}, nil, time.Hour) // scope LIMITED to case_filing
	f.put(cjPos, cjEntry)

	r := &AuthorityResolver{Fetcher: f, Catalog: davidson.MustRoleCatalog()}
	auth := r.Resolve(ctx, cjDID, cjRef, "case_decision") // not in scope
	if auth.Rejection != RejectScopeViolation {
		t.Errorf("expected RejectScopeViolation, got %s (%s)", auth.Rejection, auth.Reason)
	}
}

func TestAuthorityResolver_RejectsCatalogViolation(t *testing.T) {
	f := newFakeFetcher()
	institutional := "did:web:state:tn:davidson"
	clerkDID := "did:key:zQ3shCLERK"

	clerkPos := types.LogPosition{LogDID: institutional, Sequence: 1}
	clerkRef, clerkEntry := makeDelegation(t, clerkPos, institutional, clerkDID, "court_clerk",
		[]string{"case_decision"}, // case_decision is NOT in court_clerk.AllowedScope
		nil, time.Hour)
	f.put(clerkPos, clerkEntry)

	r := &AuthorityResolver{Fetcher: f, Catalog: davidson.MustRoleCatalog()}
	auth := r.Resolve(ctx, clerkDID, clerkRef, "case_decision")
	if auth.Rejection != RejectCatalogViolation {
		t.Errorf("expected RejectCatalogViolation, got %s (%s)", auth.Rejection, auth.Reason)
	}
}

func TestAuthorityResolver_RejectsGranteeMismatch(t *testing.T) {
	f := newFakeFetcher()
	pos := types.LogPosition{LogDID: "did:web:x", Sequence: 1}
	ref, entry := makeDelegation(t, pos, "did:web:x", "did:key:zQ3shTRUE", "judge",
		[]string{"case_filing"}, nil, time.Hour)
	f.put(pos, entry)

	r := &AuthorityResolver{Fetcher: f, Catalog: davidson.MustRoleCatalog()}
	auth := r.Resolve(ctx, "did:key:zQ3shIMPOSTER", ref, "case_filing")
	if auth.Rejection != RejectSignerMismatch {
		t.Errorf("expected RejectSignerMismatch, got %s (%s)", auth.Rejection, auth.Reason)
	}
}

func TestAuthorityResolver_RejectsDepthExceeded(t *testing.T) {
	f := newFakeFetcher()
	institutional := "did:web:state:tn:davidson"

	// Build a 4-hop chain: institutional → A → B → C → D. Should
	// reject because MaxDelegationDepth=3.
	a, b, c, d := "did:key:zQ3shA", "did:key:zQ3shB", "did:key:zQ3shC", "did:key:zQ3shD"

	pA := types.LogPosition{LogDID: institutional, Sequence: 1}
	rA, eA := makeDelegation(t, pA, institutional, a, "chief_justice",
		[]string{"case_filing"}, nil, time.Hour)
	f.put(pA, eA)

	pB := types.LogPosition{LogDID: a, Sequence: 1}
	rB, eB := makeDelegation(t, pB, a, b, "judge",
		[]string{"case_filing"}, &rA, time.Hour)
	f.put(pB, eB)

	pC := types.LogPosition{LogDID: b, Sequence: 1}
	rC, eC := makeDelegation(t, pC, b, c, "court_clerk",
		[]string{"case_filing"}, &rB, time.Hour)
	f.put(pC, eC)

	pD := types.LogPosition{LogDID: c, Sequence: 1}
	rD, eD := makeDelegation(t, pD, c, d, "court_staff",
		[]string{"case_filing"}, &rC, time.Hour)
	f.put(pD, eD)

	r := &AuthorityResolver{Fetcher: f, Catalog: davidson.MustRoleCatalog()}
	auth := r.Resolve(ctx, d, rD, "case_filing")
	if auth.Rejection != RejectDepthExceeded {
		t.Errorf("expected RejectDepthExceeded, got %s (%s)", auth.Rejection, auth.Reason)
	}
}

func TestAuthorityResolver_RejectsEmptyInputs(t *testing.T) {
	r := &AuthorityResolver{Fetcher: newFakeFetcher(), Catalog: davidson.MustRoleCatalog()}

	auth := r.Resolve(ctx, "", schemas.LogPositionRef{LogDID: "x", Sequence: 1}, "case_filing")
	if auth.Rejection != RejectSignerMismatch || !strings.Contains(auth.Reason, "empty") {
		t.Errorf("empty signer: got %s (%s)", auth.Rejection, auth.Reason)
	}

	auth = r.Resolve(ctx, "did:key:zQ3shS", schemas.LogPositionRef{}, "case_filing")
	if auth.Rejection != RejectMissingChainTip {
		t.Errorf("empty tip: got %s (%s)", auth.Rejection, auth.Reason)
	}
}

func TestAuthorityResolver_RejectsFetchMiss(t *testing.T) {
	r := &AuthorityResolver{Fetcher: newFakeFetcher(), Catalog: davidson.MustRoleCatalog()}
	auth := r.Resolve(ctx, "did:key:zQ3shS",
		schemas.LogPositionRef{LogDID: "did:web:x", Sequence: 7},
		"case_filing")

	if auth.Rejection != RejectFetchFailed {
		t.Errorf("expected RejectFetchFailed, got %s (%s)", auth.Rejection, auth.Reason)
	}
}

// ─── Origin evaluation via LeafReader ───────────────────────────────

// fakeLeafReader returns a synthetic leaf for any key. The OriginTip
// of the leaf points to a pre-supplied position so the resolver's
// EvaluateOrigin call surfaces a known result.
type fakeLeafReader struct {
	originTipFor map[[32]byte]types.LogPosition
}

func (f *fakeLeafReader) Get(ctx context.Context, key [32]byte) (*types.SMTLeaf, error) {
	tip, ok := f.originTipFor[key]
	if !ok {
		return nil, nil
	}
	return &types.SMTLeaf{OriginTip: tip}, nil
}

// TestAuthorityResolver_OriginRevoked_LeafReaderTip exercises the
// LeafReader-aware origin path: a delegation entry exists at pos P,
// but the SMT leaf for P's key reports OriginTip = Q where Q's
// envelope's TargetRoot points to a DIFFERENT entity. EvaluateOrigin
// classifies this as Revoked (TargetRoot != leafKey) and the resolver
// folds that into RejectRevoked.
func TestAuthorityResolver_OriginRevoked_LeafReaderTip(t *testing.T) {
	f := newFakeFetcher()
	institutional := "did:web:state:tn:davidson"
	signer := "did:key:zQ3shS"

	// The delegation entry at pos.
	delegPos := types.LogPosition{LogDID: institutional, Sequence: 1}
	delegRef, delegEntry := makeDelegation(t, delegPos, institutional, signer, "chief_justice",
		[]string{"case_filing"}, nil, time.Hour)
	f.put(delegPos, delegEntry)

	// Build the revocation envelope with a TargetRoot pointing to a
	// DIFFERENT entity than delegPos so EvaluateOrigin classifies as
	// OriginRevoked. The revocation entry is referenced by leaf
	// OriginTip.
	revPos := types.LogPosition{LogDID: institutional, Sequence: 5}
	otherEntity := types.LogPosition{LogDID: institutional, Sequence: 99}
	revBytes := canonicalEntryWithTarget(t, institutional,
		makeRevocationPayload(t, schemas.LogPositionRef{
			LogDID: institutional, Sequence: 1,
		}),
		&otherEntity)
	f.put(revPos, revBytes)

	leafKey := smt.DeriveKey(delegPos)
	lr := &fakeLeafReader{originTipFor: map[[32]byte]types.LogPosition{
		leafKey: revPos,
	}}

	r := &AuthorityResolver{
		Fetcher:    f,
		LeafReader: lr,
		Catalog:    davidson.MustRoleCatalog(),
	}
	auth := r.Resolve(ctx, signer, delegRef, "case_filing")
	if auth.Rejection != RejectRevoked {
		t.Errorf("expected RejectRevoked via origin tip, got %s (%s)", auth.Rejection, auth.Reason)
	}
}
