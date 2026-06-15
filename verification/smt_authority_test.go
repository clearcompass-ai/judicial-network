/*
FILE PATH: verification/smt_authority_test.go

Lock tests for SMTAuthorityResolver — the G19 gate over the SDK+Tooling walk.

Fixtures use the REAL producer (builder.BuildDelegation), so each entry carries
Header.DelegateDID == payload.GranteeDID exactly as delegation/issue.go mints it.
The libs walk reads the header for the grantee-chain (splice) check; a hand-built
envelope without DelegateDID (the older AuthorityResolver helpers) would not
exercise that path faithfully.
*/
package verification

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

const smtAuthLogDID = "did:web:state:tn:davidson"

func at(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: smtAuthLogDID, Sequence: seq}
}

// mkJNDeleg mints a judicial-delegation-v1 entry via the REAL producer (so the
// header DelegateDID/SignerDID mirror the payload grantee/granter), stores it in
// f, and returns the chain ref the child hop points back to.
func mkJNDeleg(
	t *testing.T, f *fakeFetcher, pos types.LogPosition,
	granter, grantee, role string, scope []string,
	parent *schemas.LogPositionRef, expiresIn time.Duration,
) schemas.LogPositionRef {
	t.Helper()
	now := time.Now().UTC()
	issued := now
	if expiresIn <= 0 {
		issued = now.Add(2 * expiresIn) // pre-date so payload Validate passes
	}
	p := &schemas.JudicialDelegationPayload{
		SchemaID:             schemas.SchemaJudicialDelegationV1,
		GranterDID:           granter,
		GranteeDID:           grantee,
		Role:                 role,
		Scope:                scope,
		ExpiresAt:            now.Add(expiresIn).Format(time.RFC3339Nano),
		IssuedAt:             issued.Format(time.RFC3339Nano),
		GranterDelegationRef: parent,
	}
	by, err := schemas.MarshalJudicialDelegationPayload(p)
	if err != nil {
		t.Fatalf("marshal delegation: %v", err)
	}
	entry, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:test.exchange",
		SignerDID:   granter,
		DelegateDID: grantee,
		Payload:     by,
	})
	if err != nil {
		t.Fatalf("BuildDelegation: %v", err)
	}
	entry.Signatures = []envelope.Signature{{SignerDID: granter, AlgoID: envelope.SigAlgoECDSA, Bytes: make([]byte, 64)}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry validate: %v", err)
	}
	b, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	f.put(pos, b)
	return schemas.LogPositionRef{LogDID: pos.LogDID, Sequence: pos.Sequence}
}

// liveLeaves returns a leaf reader marking each position LIVE (OriginTip == pos).
func liveLeaves(ps ...types.LogPosition) *fakeLeafReader {
	m := make(map[[32]byte]types.LogPosition, len(ps))
	for _, p := range ps {
		m[smt.DeriveKey(p)] = p
	}
	return &fakeLeafReader{originTipFor: m}
}

func reqFor(did string, ref schemas.LogPositionRef) jurisdiction.AuthorityRequest {
	return jurisdiction.AuthorityRequest{
		SignerDID:     did,
		DelegationRef: jurisdiction.DelegationRef{LogDID: ref.LogDID, Sequence: ref.Sequence},
	}
}

const (
	saInst  = "did:web:state:tn:davidson"
	saCJ    = "did:key:zQ3shCJ"
	saJudge = "did:key:zQ3shJUDGE"
)

// TestSMTAuthorityResolver_LiveChain_RoleMatch: a live judge grant resolves OK
// with the chain-tip role.
func TestSMTAuthorityResolver_LiveChain_RoleMatch(t *testing.T) {
	f := newFakeFetcher()
	judgePos := at(1)
	ref := mkJNDeleg(t, f, judgePos, saInst, saJudge, "judge", []string{"case_filing"}, nil, time.Hour)

	r := NewSMTAuthorityResolver(f, liveLeaves(judgePos))
	v := r.Resolve(context.Background(), reqFor(saJudge, ref))
	if !v.OK {
		t.Fatalf("expected OK, got rejection=%s reason=%s", v.Rejection, v.Reason)
	}
	if v.Role != "judge" {
		t.Errorf("Role = %q, want judge", v.Role)
	}
}

// TestSMTAuthorityResolver_RevokedSelfTargeting_NotLive is THE fix: a real
// self-targeting delegation revocation (the ledger advanced the judge leaf's
// OriginTip OFF its own position) makes the gate verdict NOT OK. The retired
// EvaluateOrigin path read this exact geometry as Amended ⇒ LIVE and admitted
// the revoked judge; OriginTip==position catches it.
func TestSMTAuthorityResolver_RevokedSelfTargeting_NotLive(t *testing.T) {
	f := newFakeFetcher()
	judgePos := at(1)
	revPos := at(2)
	ref := mkJNDeleg(t, f, judgePos, saInst, saJudge, "judge", []string{"case_filing"}, nil, time.Hour)

	// The judge leaf's OriginTip now points to the revocation (≠ judgePos).
	leaf := &fakeLeafReader{originTipFor: map[[32]byte]types.LogPosition{
		smt.DeriveKey(judgePos): revPos,
	}}

	r := NewSMTAuthorityResolver(f, leaf)
	v := r.Resolve(context.Background(), reqFor(saJudge, ref))
	if v.OK {
		t.Fatal("a revoked judge MUST NOT verify (the EvaluateOrigin false-negative must be impossible here)")
	}
	if v.Rejection != "revoked" {
		t.Errorf("Rejection = %q, want revoked", v.Rejection)
	}
}

// TestSMTAuthorityResolver_BorrowedRef_Splice: a cosigner cannot borrow another
// signer's delegation_ref — the grantee chain would not start at the cosigner,
// so the libs grantee-link returns ErrChainBroken.
func TestSMTAuthorityResolver_BorrowedRef_Splice(t *testing.T) {
	f := newFakeFetcher()
	judgePos := at(1)
	// A real grant to saJudge.
	ref := mkJNDeleg(t, f, judgePos, saInst, saJudge, "judge", []string{"case_filing"}, nil, time.Hour)

	r := NewSMTAuthorityResolver(f, liveLeaves(judgePos))
	// An imposter presents the judge's ref as its own chain tip.
	v := r.Resolve(context.Background(), reqFor("did:key:zQ3shIMPOSTER", ref))
	if v.OK {
		t.Fatal("a borrowed delegation_ref must not verify")
	}
	if v.Rejection != "chain_broken" {
		t.Errorf("Rejection = %q, want chain_broken", v.Rejection)
	}
}

// TestSMTAuthorityResolver_Expired_NotLive: an expired leaf delegation is not
// live (domain expiry hook), so the verdict is NOT OK.
func TestSMTAuthorityResolver_Expired_NotLive(t *testing.T) {
	f := newFakeFetcher()
	judgePos := at(1)
	ref := mkJNDeleg(t, f, judgePos, saInst, saJudge, "judge", []string{"case_filing"}, nil, -time.Hour) // expired

	r := NewSMTAuthorityResolver(f, liveLeaves(judgePos))
	v := r.Resolve(context.Background(), reqFor(saJudge, ref))
	if v.OK {
		t.Fatal("an expired delegation must not verify")
	}
}

// TestSMTAuthorityResolver_TwoHopChain: inst → CJ → judge. The judge resolves
// OK across two grantee-linked hops; the chain-tip role is the leaf's.
func TestSMTAuthorityResolver_TwoHopChain(t *testing.T) {
	f := newFakeFetcher()
	cjPos := at(1)
	judgePos := at(2)
	cjRef := mkJNDeleg(t, f, cjPos, saInst, saCJ, "chief_justice", []string{"case_filing"}, nil, time.Hour)
	judgeRef := mkJNDeleg(t, f, judgePos, saCJ, saJudge, "judge", []string{"case_filing"}, &cjRef, time.Hour)

	r := NewSMTAuthorityResolver(f, liveLeaves(cjPos, judgePos))
	v := r.Resolve(context.Background(), reqFor(saJudge, judgeRef))
	if !v.OK {
		t.Fatalf("two-hop chain must verify, got rejection=%s reason=%s", v.Rejection, v.Reason)
	}
	if v.Role != "judge" || v.Depth != 2 {
		t.Errorf("Role=%q Depth=%d, want judge / 2", v.Role, v.Depth)
	}
}

// TestSMTAuthorityResolver_RevokedMidChain: revoking the CJ hop (the judge's
// granter) breaks the judge's authority even though the judge's own leaf is
// live — liveness is enforced on EVERY hop.
func TestSMTAuthorityResolver_RevokedMidChain(t *testing.T) {
	f := newFakeFetcher()
	cjPos := at(1)
	judgePos := at(2)
	cjRevPos := at(3)
	cjRef := mkJNDeleg(t, f, cjPos, saInst, saCJ, "chief_justice", []string{"case_filing"}, nil, time.Hour)
	judgeRef := mkJNDeleg(t, f, judgePos, saCJ, saJudge, "judge", []string{"case_filing"}, &cjRef, time.Hour)

	// Judge leaf live; CJ leaf revoked (OriginTip advanced off cjPos).
	leaf := &fakeLeafReader{originTipFor: map[[32]byte]types.LogPosition{
		smt.DeriveKey(judgePos): judgePos,
		smt.DeriveKey(cjPos):    cjRevPos,
	}}

	r := NewSMTAuthorityResolver(f, leaf)
	v := r.Resolve(context.Background(), reqFor(saJudge, judgeRef))
	if v.OK {
		t.Fatal("a revoked granter hop must invalidate the downstream judge")
	}
	if v.Rejection != "revoked" {
		t.Errorf("Rejection = %q, want revoked", v.Rejection)
	}
}

// TestSMTAuthorityResolver_SucceededLeaf_NotLive (D-group): a superseded
// delegation — its leaf OriginTip advanced off its own position via a
// succession — is rejected at the gate. The successor governs, not the old
// grant (the retired AuthorityResolver "followed through" the superseded grant;
// OriginTip==position refuses it). Same liveness geometry as a revocation.
func TestSMTAuthorityResolver_SucceededLeaf_NotLive(t *testing.T) {
	f := newFakeFetcher()
	judgePos := at(1)
	succPos := at(2)
	ref := mkJNDeleg(t, f, judgePos, saInst, saJudge, "judge", []string{"case_filing"}, nil, time.Hour)

	leaf := &fakeLeafReader{originTipFor: map[[32]byte]types.LogPosition{
		smt.DeriveKey(judgePos): succPos, // succession advanced the tip ⇒ superseded
	}}

	r := NewSMTAuthorityResolver(f, leaf)
	v := r.Resolve(context.Background(), reqFor(saJudge, ref))
	if v.OK {
		t.Fatal("a superseded (succeeded) delegation MUST NOT verify at the gate — the successor governs")
	}
	if v.Rejection != "revoked" {
		t.Errorf("Rejection = %q, want revoked (succession is a liveness lapse on the old leaf)", v.Rejection)
	}
}
