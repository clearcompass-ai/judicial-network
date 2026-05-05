/*
FILE PATH: tests/contracts/delegation_invite_test.go

DESCRIPTION:

	Pins the hierarchical-invite-control invariants the role catalog
	encodes for the Davidson deployment:

	  - Only chief_justice may grant judge.
	  - chief_justice or judge may grant court_clerk.
	  - Only judge may grant deputy_judge.
	  - Only court_clerk may grant court_staff.
	  - court_staff and deputy_judge may grant nothing.

	Each test drives a real delegation.Issue call and asserts either
	success or ErrCatalogRejection — proves the on-write gate
	matches the catalog's DelegableBy table.
*/
package contracts

import (
	"context"
	"errors"
	"testing"

	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

func TestDelegationInvite_OnlyCJCanGrantJudge(t *testing.T) {
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjDID := f.provisionKey(t, "did:key:zQ3shCJ")
	clerkDID := f.provisionKey(t, "did:key:zQ3shCLERK")

	cjPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjDID, GranteeRole: "chief_justice",
	})

	// CJ → court_clerk OK (court_clerk.DelegableBy includes chief_justice).
	clerkPos := f.issue(t, delegation.IssueRequest{
		GranterDID: cjDID, GranterRole: "chief_justice", GranterDelegationRef: &cjPos,
		GranteeDID: clerkDID, GranteeRole: "court_clerk",
	})

	// court_clerk → judge MUST be rejected (judge.DelegableBy=[chief_justice] only).
	otherJudge := f.provisionKey(t, "did:key:zQ3shJUDGE")
	_, err := delegation.Issue(context.Background(), f.buildCtx, delegation.IssueRequest{
		GranterDID: clerkDID, GranterRole: "court_clerk", GranterDelegationRef: &clerkPos,
		GranteeDID: otherJudge, GranteeRole: "judge",
	})
	if !errors.Is(err, delegation.ErrCatalogRejection) {
		t.Errorf("expected ErrCatalogRejection (clerk cannot grant judge), got: %v", err)
	}
}

func TestDelegationInvite_OnlyJudgeCanGrantDeputy(t *testing.T) {
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjDID := f.provisionKey(t, "did:key:zQ3shCJ")
	judgeDID := f.provisionKey(t, "did:key:zQ3shJUDGE")
	deputyDID := f.provisionKey(t, "did:key:zQ3shDEPUTY")

	cjPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjDID, GranteeRole: "chief_justice",
	})
	judgePos := f.issue(t, delegation.IssueRequest{
		GranterDID: cjDID, GranterRole: "chief_justice", GranterDelegationRef: &cjPos,
		GranteeDID: judgeDID, GranteeRole: "judge",
	})

	// judge → deputy_judge OK with scope confined to judge's
	// DelegableScope (which omits case_decision per Davidson policy
	// — judges keep that for themselves).
	if _, err := delegation.Issue(context.Background(), f.buildCtx, delegation.IssueRequest{
		GranterDID: judgeDID, GranterRole: "judge", GranterDelegationRef: &judgePos,
		GranteeDID: deputyDID, GranteeRole: "deputy_judge",
		Scope: []string{"case_filing", "docket_management"},
	}); err != nil {
		t.Errorf("judge → deputy_judge must succeed: %v", err)
	}

	// CJ → deputy_judge MUST be rejected.
	otherDeputy := f.provisionKey(t, "did:key:zQ3shDEPUTY2")
	_, err := delegation.Issue(context.Background(), f.buildCtx, delegation.IssueRequest{
		GranterDID: cjDID, GranterRole: "chief_justice", GranterDelegationRef: &cjPos,
		GranteeDID: otherDeputy, GranteeRole: "deputy_judge",
	})
	if !errors.Is(err, delegation.ErrCatalogRejection) {
		t.Errorf("expected ErrCatalogRejection (CJ cannot grant deputy_judge), got: %v", err)
	}
}

func TestDelegationInvite_OnlyClerkCanGrantStaff(t *testing.T) {
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjDID := f.provisionKey(t, "did:key:zQ3shCJ")
	clerkDID := f.provisionKey(t, "did:key:zQ3shCLERK")
	staffDID := f.provisionKey(t, "did:key:zQ3shSTAFF")

	cjPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjDID, GranteeRole: "chief_justice",
	})
	clerkPos := f.issue(t, delegation.IssueRequest{
		GranterDID: cjDID, GranterRole: "chief_justice", GranterDelegationRef: &cjPos,
		GranteeDID: clerkDID, GranteeRole: "court_clerk",
	})

	// clerk → staff OK.
	if _, err := delegation.Issue(context.Background(), f.buildCtx, delegation.IssueRequest{
		GranterDID: clerkDID, GranterRole: "court_clerk", GranterDelegationRef: &clerkPos,
		GranteeDID: staffDID, GranteeRole: "court_staff",
	}); err != nil {
		t.Errorf("clerk → staff must succeed: %v", err)
	}

	// CJ → staff MUST be rejected.
	otherStaff := f.provisionKey(t, "did:key:zQ3shSTAFF2")
	_, err := delegation.Issue(context.Background(), f.buildCtx, delegation.IssueRequest{
		GranterDID: cjDID, GranterRole: "chief_justice", GranterDelegationRef: &cjPos,
		GranteeDID: otherStaff, GranteeRole: "court_staff",
	})
	if !errors.Is(err, delegation.ErrCatalogRejection) {
		t.Errorf("expected ErrCatalogRejection (CJ cannot grant court_staff), got: %v", err)
	}
}

func TestDelegationInvite_DeputyCannotGrantAnything(t *testing.T) {
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjDID := f.provisionKey(t, "did:key:zQ3shCJ")
	judgeDID := f.provisionKey(t, "did:key:zQ3shJUDGE")
	deputyDID := f.provisionKey(t, "did:key:zQ3shDEPUTY")

	cjPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjDID, GranteeRole: "chief_justice",
	})
	judgePos := f.issue(t, delegation.IssueRequest{
		GranterDID: cjDID, GranterRole: "chief_justice", GranterDelegationRef: &cjPos,
		GranteeDID: judgeDID, GranteeRole: "judge",
	})
	deputyPos := f.issue(t, delegation.IssueRequest{
		GranterDID: judgeDID, GranterRole: "judge", GranterDelegationRef: &judgePos,
		GranteeDID: deputyDID, GranteeRole: "deputy_judge",
		Scope: []string{"case_filing", "docket_management"},
	})

	// deputy_judge has DelegableScope=nil and is not in any role's
	// DelegableBy. Attempts to grant any role must be rejected.
	target := f.provisionKey(t, "did:key:zQ3shTGT")
	for _, role := range []string{"judge", "court_clerk", "court_staff", "deputy_judge"} {
		_, err := delegation.Issue(context.Background(), f.buildCtx, delegation.IssueRequest{
			GranterDID:           deputyDID,
			GranterRole:          "deputy_judge",
			GranterDelegationRef: &deputyPos,
			GranteeDID:           target,
			GranteeRole:          role,
		})
		if !errors.Is(err, delegation.ErrCatalogRejection) {
			t.Errorf("deputy_judge → %s must be rejected, got: %v", role, err)
		}
	}
}

func TestDelegationInvite_GrantersScopeIntersectionEnforcedAtIssue(t *testing.T) {
	// Per Davidson roles, judge.DelegableScope explicitly omits
	// "case_decision". So even though deputy_judge.AllowedScope
	// includes case_decision, a judge cannot pass it down.
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjDID := f.provisionKey(t, "did:key:zQ3shCJ")
	judgeDID := f.provisionKey(t, "did:key:zQ3shJUDGE")
	deputyDID := f.provisionKey(t, "did:key:zQ3shDEPUTY")

	cjPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjDID, GranteeRole: "chief_justice",
	})
	judgePos := f.issue(t, delegation.IssueRequest{
		GranterDID: cjDID, GranterRole: "chief_justice", GranterDelegationRef: &cjPos,
		GranteeDID: judgeDID, GranteeRole: "judge",
	})

	_, err := delegation.Issue(context.Background(), f.buildCtx, delegation.IssueRequest{
		GranterDID:           judgeDID,
		GranterRole:          "judge",
		GranterDelegationRef: &judgePos,
		GranteeDID:           deputyDID,
		GranteeRole:          "deputy_judge",
		Scope:                []string{"case_decision"},
	})
	if !errors.Is(err, delegation.ErrCatalogRejection) {
		t.Errorf("judge cannot pass case_decision to deputy: %v", err)
	}
}

// SchemaRegistered_AllThree pins the registry registration: any
// node verifying this stream needs the three judicial-* schemas
// resolvable through schemas.Registry.
func TestDelegationInvite_SchemasRegistered(t *testing.T) {
	r := schemas.NewRegistry()
	for _, uri := range []string{
		schemas.SchemaJudicialDelegationV1,
		schemas.SchemaJudicialRevocationV1,
		schemas.SchemaJudicialSuccessionV1,
	} {
		if !r.Has(uri) {
			t.Errorf("registry missing %q", uri)
		}
	}
}
