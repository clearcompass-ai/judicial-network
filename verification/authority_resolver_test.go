/*
FILE PATH: verification/authority_resolver_test.go

DESCRIPTION:

	Happy-path + scope-intersection coverage for AuthorityResolver.
	Helpers (fakeFetcher, makeDelegation, etc.) live in
	authority_resolver_helpers_test.go; rejection-path tests live in
	authority_resolver_rejection_test.go.
*/
package verification

import (
	"context"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/types"
	davidson "github.com/clearcompass-ai/judicial-network/internal/testfixtures/davidsonlegacy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── happy path ────────────────────────────────────────────────────

func TestAuthorityResolver_HappyPath_3Hop(t *testing.T) {
	f := newFakeFetcher()

	institutional := "did:web:state:tn:davidson"
	cjDID := "did:key:zQ3shCJ"
	judgeDID := "did:key:zQ3shJUDGE"
	clerkDID := "did:key:zQ3shCLERK"

	cjPos := types.LogPosition{LogDID: institutional, Sequence: 1}
	cjRef, cjEntry := makeDelegation(t, cjPos, institutional, cjDID, "chief_justice",
		[]string{"case_filing", "case_decision", "invite:judge", "revoke:any", "administrative", "docket_management"},
		nil, 4*365*24*time.Hour)
	f.put(cjPos, cjEntry)

	judgePos := types.LogPosition{LogDID: cjDID, Sequence: 5}
	judgeRef, judgeEntry := makeDelegation(t, judgePos, cjDID, judgeDID, "judge",
		[]string{"case_filing", "case_decision", "docket_management"},
		&cjRef, 4*365*24*time.Hour)
	f.put(judgePos, judgeEntry)

	clerkPos := types.LogPosition{LogDID: judgeDID, Sequence: 9}
	clerkRef, clerkEntry := makeDelegation(t, clerkPos, judgeDID, clerkDID, "court_clerk",
		[]string{"case_filing", "docket_management"},
		&judgeRef, 2*365*24*time.Hour)
	f.put(clerkPos, clerkEntry)

	r := &AuthorityResolver{
		Fetcher: f,
		Catalog: davidson.MustRoleCatalog(),
	}
	auth := r.Resolve(context.Background(),clerkDID, clerkRef, "case_filing")
	if !auth.OK {
		t.Fatalf("happy path should succeed, got: %+v", auth)
	}
	if auth.Role != "court_clerk" {
		t.Errorf("role: got %q want court_clerk", auth.Role)
	}
	if auth.Depth != 3 {
		t.Errorf("depth: got %d want 3", auth.Depth)
	}
}

// ─── scope intersection ────────────────────────────────────────────

func TestAuthorityResolver_ScopeIntersectionAcrossChain(t *testing.T) {
	f := newFakeFetcher()
	institutional := "did:web:state:tn:davidson"
	cjDID := "did:key:zQ3shCJ"
	judgeDID := "did:key:zQ3shJ"

	// CJ has broad scope; judge gets narrowed scope. Intersection
	// should be the narrower set.
	cjPos := types.LogPosition{LogDID: institutional, Sequence: 1}
	cjRef, cjEntry := makeDelegation(t, cjPos, institutional, cjDID, "chief_justice",
		[]string{"case_filing", "case_decision", "docket_management",
			"invite:judge", "revoke:any", "administrative"},
		nil, time.Hour)
	f.put(cjPos, cjEntry)

	judgePos := types.LogPosition{LogDID: cjDID, Sequence: 1}
	judgeRef, judgeEntry := makeDelegation(t, judgePos, cjDID, judgeDID, "judge",
		[]string{"case_filing"}, // narrower
		&cjRef, time.Hour)
	f.put(judgePos, judgeEntry)

	r := &AuthorityResolver{Fetcher: f, Catalog: davidson.MustRoleCatalog()}
	auth := r.Resolve(context.Background(),judgeDID, judgeRef, "case_filing")
	if !auth.OK {
		t.Fatalf("case_filing should pass (in both): %+v", auth)
	}
	if len(auth.EffectiveScope) != 1 || auth.EffectiveScope[0] != "case_filing" {
		t.Errorf("EffectiveScope = %v, want [case_filing]", auth.EffectiveScope)
	}

	// case_decision is in CJ's scope but NOT judge's scope; chain
	// intersection narrows to {case_filing}, so case_decision must
	// be rejected even though it's in judge.AllowedScope.
	auth = r.Resolve(context.Background(),judgeDID, judgeRef, "case_decision")
	if auth.Rejection != RejectScopeViolation {
		t.Errorf("expected RejectScopeViolation, got %s (%s)", auth.Rejection, auth.Reason)
	}
}

// ─── classifyTip ───────────────────────────────────────────────────

func TestClassifyTip(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"empty", "", ""},
		{"not json", "not json", ""},
		{"delegation", `{"schema_id":"judicial-delegation-v1"}`, schemas.SchemaJudicialDelegationV1},
		{"revocation", `{"schema_id":"judicial-revocation-v1"}`, schemas.SchemaJudicialRevocationV1},
		{"succession", `{"schema_id":"judicial-succession-v1"}`, schemas.SchemaJudicialSuccessionV1},
		{"missing field", `{"foo":"bar"}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyTip([]byte(tc.body)); got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}
