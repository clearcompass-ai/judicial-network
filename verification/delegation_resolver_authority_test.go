package verification

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/types"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// testRoleExtractor / testScopeExtractor read role + scope from a simple test
// payload {"role":...,"scope":[...]}, decoupling the verdict-MAPPING tests from
// the judicial codec (which the parity lock test, step 4, exercises against
// real artifacts).
func testRoleExtractor(e *envelope.Entry) string {
	var p struct {
		Role string `json:"role"`
	}
	_ = json.Unmarshal(e.DomainPayload, &p)
	return p.Role
}

func testScopeExtractor(e *envelope.Entry) []string {
	var p struct {
		Scope []string `json:"scope"`
	}
	_ = json.Unmarshal(e.DomainPayload, &p)
	return p.Scope
}

func signedRoleScopeBytes(t *testing.T, signer, role string, scope []string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"role": role, "scope": scope})
	if err != nil {
		t.Fatal(err)
	}
	return signedEntryWithPayload(t, signer, b)
}

// TestResolve_RoleAtTipAndScopeIntersection pins the verdict's two core
// outputs: role-at-tip is the role granted to the SIGNER (hops[0]), and
// EffectiveScope is the intersection tip→root.
func TestResolve_RoleAtTipAndScopeIntersection(t *testing.T) {
	// judge ← authority ← root. The delegation TO judge grants role "judge"
	// + scope {civil,criminal,family}; the delegation TO authority grants
	// {civil,criminal}. Intersection ⇒ {civil,criminal}.
	delegate := &fakeDelegateQuerier{byDID: map[string][]types.EntryWithMetadata{
		"did:web:judge":     {{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 100}}},
		"did:web:authority": {{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 50}}},
	}}
	fetcher := &delegFakeFetcher{bySeq: map[uint64][]byte{
		100: signedRoleScopeBytes(t, "did:web:authority", "judge", []string{"civil", "criminal", "family"}),
		50:  signedRoleScopeBytes(t, "did:web:root", "authority", []string{"civil", "criminal"}),
	}}
	r, _ := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: delegate, Fetcher: fetcher, LogDID: "did:web:l",
		Role: testRoleExtractor, Scope: testScopeExtractor,
	})

	v := r.Resolve(context.Background(), jurisdiction.AuthorityRequest{SignerDID: "did:web:judge"})
	if !v.OK {
		t.Fatalf("OK=false, want true: rejection=%q reason=%q", v.Rejection, v.Reason)
	}
	if v.Role != "judge" {
		t.Errorf("Role = %q, want judge (the role granted to the signer at the tip)", v.Role)
	}
	if len(v.EffectiveScope) != 2 || v.EffectiveScope[0] != "civil" || v.EffectiveScope[1] != "criminal" {
		t.Errorf("EffectiveScope = %v, want [civil criminal] (tip ∩ parent)", v.EffectiveScope)
	}
	if v.Depth != 2 {
		t.Errorf("Depth = %d, want 2", v.Depth)
	}
}

// TestResolve_RevokedTip pins the no-SMT revocation: a revocation tip yields a
// fail-closed RejectRevoked verdict.
func TestResolve_RevokedTip(t *testing.T) {
	delegate := &fakeDelegateQuerier{byDID: map[string][]types.EntryWithMetadata{
		"did:web:judge": {{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 7}}},
	}}
	fetcher := &delegFakeFetcher{bySeq: map[uint64][]byte{
		7: signedRevocationBytes(t, "did:web:authority"),
	}}
	r, _ := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: delegate, Fetcher: fetcher, LogDID: "did:web:l",
		Role: testRoleExtractor, Scope: testScopeExtractor,
	})
	v := r.Resolve(context.Background(), jurisdiction.AuthorityRequest{SignerDID: "did:web:judge"})
	if v.OK || v.Rejection != string(RejectRevoked) {
		t.Fatalf("a revocation tip must reject with RejectRevoked, got OK=%v rejection=%q", v.OK, v.Rejection)
	}
}

// TestResolve_Expired pins per-hop expiry parity: a live but expired grant is
// rejected with RejectExpired.
func TestResolve_Expired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	delegate := &fakeDelegateQuerier{byDID: map[string][]types.EntryWithMetadata{
		"did:web:judge": {{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 9}}},
	}}
	fetcher := &delegFakeFetcher{bySeq: map[uint64][]byte{
		9: signedRoleScopeBytes(t, "did:web:root", "judge", []string{"civil"}),
	}}
	r, _ := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: delegate, Fetcher: fetcher, LogDID: "did:web:l",
		Role:   testRoleExtractor,
		Scope:  testScopeExtractor,
		Expiry: func(*envelope.Entry) (time.Time, bool) { return past, true },
	})
	v := r.Resolve(context.Background(), jurisdiction.AuthorityRequest{SignerDID: "did:web:judge"})
	if v.OK || v.Rejection != string(RejectExpired) {
		t.Fatalf("an expired hop must reject with RejectExpired, got OK=%v rejection=%q", v.OK, v.Rejection)
	}
}

// TestResolve_NoChainAndEmptySigner pins the fail-closed entry conditions.
func TestResolve_NoChainAndEmptySigner(t *testing.T) {
	r, _ := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: &fakeDelegateQuerier{byDID: map[string][]types.EntryWithMetadata{}},
		Fetcher:  &delegFakeFetcher{bySeq: map[uint64][]byte{}},
		LogDID:   "did:web:l",
	})
	if v := r.Resolve(context.Background(), jurisdiction.AuthorityRequest{SignerDID: ""}); v.OK || v.Rejection != string(RejectSignerMismatch) {
		t.Errorf("empty signer must reject with RejectSignerMismatch, got OK=%v rejection=%q", v.OK, v.Rejection)
	}
	if v := r.Resolve(context.Background(), jurisdiction.AuthorityRequest{SignerDID: "did:web:nobody"}); v.OK || v.Rejection != string(RejectMissingChainTip) {
		t.Errorf("a signer with no delegation must reject with RejectMissingChainTip, got OK=%v rejection=%q", v.OK, v.Rejection)
	}
}
