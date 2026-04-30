/*
FILE PATH: delegation/issue_rejection_test.go

DESCRIPTION:
    Rejection-path coverage for delegation.Issue. Helpers (fakeOperator,
    stubBoundProvider, newBuildContext) live in issue_test.go and are
    shared via the same test package.
*/
package delegation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
)

// ─── request validation ────────────────────────────────────────────

func TestIssue_RejectsMissingFields(t *testing.T) {
	institutional := "did:web:da:davidson-tn"
	sp := stubBoundProvider(t, institutional)
	op := &fakeOperator{}
	bc := newBuildContext(t, sp, op)

	cases := []struct {
		name string
		req  IssueRequest
		want string
	}{
		{
			name: "missing granter",
			req:  IssueRequest{GranteeDID: "did:key:zQ3shB", GranteeRole: "judge"},
			want: "granter_did",
		},
		{
			name: "missing grantee",
			req:  IssueRequest{GranterDID: institutional, GranteeRole: "judge"},
			want: "grantee_did",
		},
		{
			name: "self-delegation",
			req:  IssueRequest{GranterDID: institutional, GranteeDID: institutional, GranteeRole: "judge"},
			want: "self-delegation",
		},
		{
			name: "missing role",
			req:  IssueRequest{GranterDID: institutional, GranteeDID: "did:key:zQ3shB"},
			want: "grantee_role",
		},
		{
			name: "non-institutional missing parent",
			req:  IssueRequest{GranterDID: "did:key:zQ3shCJ", GranterRole: "chief_justice", GranteeDID: "did:key:zQ3shB", GranteeRole: "judge"},
			want: "granter_delegation_ref",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Issue(context.Background(), bc, tc.req)
			if err == nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected ErrInvalidRequest, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err missing %q: %v", tc.want, err)
			}
		})
	}
}

// ─── catalog rejection ─────────────────────────────────────────────

func TestIssue_CatalogRejectsUnknownRole(t *testing.T) {
	institutional := "did:web:da:davidson-tn"
	sp := stubBoundProvider(t, institutional)
	op := &fakeOperator{}
	bc := newBuildContext(t, sp, op)

	_, err := Issue(context.Background(), bc, IssueRequest{
		GranterDID:  institutional,
		GranteeDID:  "did:key:zQ3shB",
		GranteeRole: "wizard",
	})
	if err == nil || !errors.Is(err, ErrCatalogRejection) {
		t.Fatalf("expected ErrCatalogRejection, got: %v", err)
	}
}

func TestIssue_CatalogRejectsExcessiveDuration(t *testing.T) {
	institutional := "did:web:da:davidson-tn"
	sp := stubBoundProvider(t, institutional)
	op := &fakeOperator{}
	bc := newBuildContext(t, sp, op)

	_, err := Issue(context.Background(), bc, IssueRequest{
		GranterDID:  institutional,
		GranteeDID:  "did:key:zQ3shCJ",
		GranteeRole: "chief_justice",
		Duration:    100 * 365 * 24 * time.Hour, // > MaxDuration
	})
	if err == nil || !errors.Is(err, ErrCatalogRejection) {
		t.Fatalf("expected ErrCatalogRejection, got: %v", err)
	}
}

func TestIssue_CatalogRejectsScopeOutsideAllowed(t *testing.T) {
	institutional := "did:web:da:davidson-tn"
	sp := stubBoundProvider(t, institutional)
	op := &fakeOperator{}
	bc := newBuildContext(t, sp, op)

	_, err := Issue(context.Background(), bc, IssueRequest{
		GranterDID:  institutional,
		GranteeDID:  "did:key:zQ3shB",
		GranteeRole: "court_staff",
		Scope:       []string{"case_decision"}, // not in court_staff.AllowedScope
	})
	if err == nil || !errors.Is(err, ErrCatalogRejection) {
		t.Fatalf("expected ErrCatalogRejection, got: %v", err)
	}
}

// ─── identity / submit failures ────────────────────────────────────

func TestIssue_HonorsSignRejected(t *testing.T) {
	institutional := "did:web:da:davidson-tn"
	sp := stubBoundProvider(t, institutional)
	sp.RejectSigning(institutional, true)
	op := &fakeOperator{}
	bc := newBuildContext(t, sp, op)

	_, err := Issue(context.Background(), bc, IssueRequest{
		GranterDID:  institutional,
		GranteeDID:  "did:key:zQ3shCJ",
		GranteeRole: "chief_justice",
	})
	if err == nil {
		t.Fatal("expected error on sign rejection")
	}
	if !errors.Is(err, ErrSignFailed) {
		t.Errorf("expected ErrSignFailed, got: %v", err)
	}
	if !errors.Is(err, identity.ErrSignRejected) {
		t.Errorf("error must wrap identity.ErrSignRejected: %v", err)
	}
	if len(op.captured) != 0 {
		t.Errorf("operator must not see entries when sign rejected")
	}
}

func TestIssue_HonorsSubmitFailed(t *testing.T) {
	institutional := "did:web:da:davidson-tn"
	sp := stubBoundProvider(t, institutional)
	op := &fakeOperator{err: errors.New("synthetic operator error")}
	bc := newBuildContext(t, sp, op)

	_, err := Issue(context.Background(), bc, IssueRequest{
		GranterDID:  institutional,
		GranteeDID:  "did:key:zQ3shCJ",
		GranteeRole: "chief_justice",
	})
	if err == nil || !errors.Is(err, ErrSubmitFailed) {
		t.Fatalf("expected ErrSubmitFailed, got: %v", err)
	}
}
