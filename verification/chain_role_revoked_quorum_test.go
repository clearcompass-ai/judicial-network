package verification

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// TestChainRoleResolver_RevokedCosignerDropped_RealResolver (#124 D7) proves the
// multi-sig quorum drops a REVOKED cosigner through the REAL SMTAuthorityResolver
// reading a real BuildRevocation-advanced leaf — NOT a stubbed authority verdict
// (the existing G19 tests inject fakeAuthority/backsNobody, so they never exercise
// the resolver boundary for a genuinely-revoked cosigner).
//
// Two judge cosigners each hold a real grant; cosigner B's grant is revoked on the
// SMT (its leaf OriginTip advanced off its own position, exactly as Path A
// BuildRevocation commits it). B is dropped (ErrSignerUnknown) and does not count
// toward quorum; the live cosigner A resolves to its verified role. The
// drop -> insufficient_signers quorum recompute itself is pinned at the gate by
// api/exchange/handlers TestBundleSubmitGate_CaseInitiation_SelfAssertedClerk_RejectedG19.
func TestChainRoleResolver_RevokedCosignerDropped_RealResolver(t *testing.T) {
	const (
		judgeA = "did:key:zJUDGE_A"
		judgeB = "did:key:zJUDGE_B"
	)
	f := newFakeFetcher()
	posA := at(1)
	posB := at(2)
	revPos := at(3)
	refA := mkJNDeleg(t, f, posA, saInst, judgeA, "judge", []string{"case_decision"}, nil, time.Hour)
	refB := mkJNDeleg(t, f, posB, saInst, judgeB, "judge", []string{"case_decision"}, nil, time.Hour)

	leaf := &fakeLeafReader{originTipFor: map[[32]byte]types.LogPosition{
		smt.DeriveKey(posA): posA,   // A live: OriginTip == its own position
		smt.DeriveKey(posB): revPos, // B revoked: OriginTip advanced off posB
	}}
	authority := NewSMTAuthorityResolver(f, leaf)

	caps := []schemas.SignedByCapacity{
		cap(judgeA, "judge", &refA),
		cap(judgeB, "judge", &refB),
	}
	r, err := NewChainRoleResolverFrom(context.Background(), caps, authority)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	if e, err := r.LookupRole(judgeA); err != nil || e.Role != "judge" {
		t.Fatalf("live cosigner must resolve to its verified role: got (%+v, %v), want role=judge", e, err)
	}
	if _, err := r.LookupRole(judgeB); !errors.Is(err, ErrSignerUnknown) {
		t.Fatalf("revoked cosigner must be dropped (ErrSignerUnknown) — proven through the real "+
			"SMTAuthorityResolver reading a real revoked leaf, not a stub — got %v", err)
	}
}
