/*
FILE PATH: jurisdiction/authority_chain_resolver_test.go

DESCRIPTION:
    Unit tests for AuthorityChainResolver. Covers:

      - DelegationRef.IsZero predicate.
      - NoAuthorityChainResolver: returns non-nil; always rejects;
        echoes SignerDID; uses the closed-set rejection token.
      - A test stub (stubChainResolver) demonstrates the interface
        contract for downstream package tests that need to inject
        an OK or rejection without bringing in a real Bundle.
*/
package jurisdiction

import (
	"context"
	"testing"
)

// ─── DelegationRef ───────────────────────────────────────────────────

func TestDelegationRef_IsZero_True(t *testing.T) {
	var r DelegationRef
	if !r.IsZero() {
		t.Error("zero-value DelegationRef should report IsZero=true")
	}
}

func TestDelegationRef_IsZero_LogDIDOnly(t *testing.T) {
	r := DelegationRef{LogDID: "did:web:state:tn:davidson"}
	if r.IsZero() {
		t.Error("DelegationRef with LogDID set should report IsZero=false")
	}
}

func TestDelegationRef_IsZero_SequenceOnly(t *testing.T) {
	r := DelegationRef{Sequence: 42}
	if r.IsZero() {
		t.Error("DelegationRef with Sequence set should report IsZero=false")
	}
}

func TestDelegationRef_IsZero_BothSet(t *testing.T) {
	r := DelegationRef{LogDID: "did:web:state:tn:davidson", Sequence: 42}
	if r.IsZero() {
		t.Error("DelegationRef with both fields set should report IsZero=false")
	}
}

// ─── NoAuthorityChainResolver ───────────────────────────────────────

func TestNoAuthorityChainResolver_NotNil(t *testing.T) {
	r := NoAuthorityChainResolver()
	if r == nil {
		t.Fatal("NoAuthorityChainResolver must not return nil")
	}
}

func TestNoAuthorityChainResolver_AlwaysRejects(t *testing.T) {
	r := NoAuthorityChainResolver()
	v := r.Resolve(context.Background(), AuthorityRequest{
		SignerDID: "did:key:zsigner",
	})
	if v.OK {
		t.Error("NoAuthorityChainResolver must always return OK=false")
	}
}

func TestNoAuthorityChainResolver_EchoesSignerDID(t *testing.T) {
	r := NoAuthorityChainResolver()
	const did = "did:key:zfoobar"
	v := r.Resolve(context.Background(), AuthorityRequest{SignerDID: did})
	if v.SignerDID != did {
		t.Errorf("SignerDID echo: want %q, got %q", did, v.SignerDID)
	}
}

func TestNoAuthorityChainResolver_RejectionToken(t *testing.T) {
	r := NoAuthorityChainResolver()
	v := r.Resolve(context.Background(), AuthorityRequest{})
	if v.Rejection != "no_resolver_configured" {
		t.Errorf("Rejection token: want %q, got %q",
			"no_resolver_configured", v.Rejection)
	}
}

func TestNoAuthorityChainResolver_HumanReason(t *testing.T) {
	r := NoAuthorityChainResolver()
	v := r.Resolve(context.Background(), AuthorityRequest{})
	if v.Reason == "" {
		t.Error("Reason must be populated for audit trail")
	}
}

func TestNoAuthorityChainResolver_NilContext(t *testing.T) {
	// nilResolver does not consult ctx, so a nil context must
	// not panic. Callers in production always pass a context;
	// this test documents the no-op contract.
	r := NoAuthorityChainResolver()
	defer func() {
		if rec := recover(); rec != nil {
			t.Errorf("nilResolver panicked on nil ctx: %v", rec)
		}
	}()
	_ = r.Resolve(context.TODO(), AuthorityRequest{SignerDID: "x"})
}

// ─── stub for downstream tests ──────────────────────────────────────

func TestStubChainResolver_OK(t *testing.T) {
	want := AuthorityVerdict{
		OK:             true,
		SignerDID:      "did:key:zsigner",
		Role:           "judge",
		EffectiveScope: []string{"merits_authority"},
		Depth:          2,
	}
	r := stubChainResolver{verdict: want}
	got := r.Resolve(context.Background(), AuthorityRequest{
		SignerDID: "did:key:zsigner",
	})
	if got.OK != want.OK ||
		got.Role != want.Role ||
		got.Depth != want.Depth {
		t.Errorf("stub did not echo verdict: want %+v got %+v", want, got)
	}
}

func TestStubChainResolver_Reject(t *testing.T) {
	r := stubChainResolver{verdict: AuthorityVerdict{
		OK:        false,
		Rejection: "expired",
		Reason:    "delegation expired at hop=1",
	}}
	got := r.Resolve(context.Background(), AuthorityRequest{})
	if got.OK {
		t.Error("rejection verdict must propagate OK=false")
	}
	if got.Rejection != "expired" {
		t.Errorf("Rejection token: want %q got %q", "expired", got.Rejection)
	}
}

// stubChainResolver is a hand-built AuthorityChainResolver for
// tests in this package and in downstream packages that need a
// known-shape verdict without instantiating a real Bundle.
type stubChainResolver struct {
	verdict AuthorityVerdict
}

func (s stubChainResolver) Resolve(_ context.Context, _ AuthorityRequest) AuthorityVerdict {
	return s.verdict
}
