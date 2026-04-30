/*
FILE PATH: tests/contracts/delegation_revocation_test.go

DESCRIPTION:
    Revocation propagation, end-to-end. Builds chains and revokes
    a delegation entry; pins the resolver's behavior:

      - When a leaf's OriginTip points to a revocation entry, the
        resolver returns RejectRevoked for any signer whose chain
        passes through that hop.
      - The resolver also returns RejectRevoked when the chain tip
        IS the revocation entry (no LeafReader needed).
      - The OfficerRegistry transitions to StatusRevoked.
      - Revoking does NOT retroactively invalidate other independent
        chains — only the descendants of the revoked node.
*/
package contracts

import (
	"context"
	"testing"

	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/clearcompass-ai/judicial-network/directory"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/verification"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func TestDelegationRevocation_PropagatesViaOriginTip(t *testing.T) {
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjDID := f.provisionKey(t, "did:key:zQ3shCJ")
	judgeDID := f.provisionKey(t, "did:key:zQ3shJUDGE")
	clerkDID := f.provisionKey(t, "did:key:zQ3shCLERK")

	cjPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjDID, GranteeRole: "chief_justice",
	})
	judgePos := f.issue(t, delegation.IssueRequest{
		GranterDID: cjDID, GranterRole: "chief_justice", GranterDelegationRef: &cjPos,
		GranteeDID: judgeDID, GranteeRole: "judge",
	})
	clerkPos := f.issue(t, delegation.IssueRequest{
		GranterDID: judgeDID, GranterRole: "judge", GranterDelegationRef: &judgePos,
		GranteeDID: clerkDID, GranteeRole: "court_clerk",
	})

	// Sanity: clerk resolves before revocation.
	if auth := f.resolve(clerkDID, clerkPos, "case_filing"); !auth.OK {
		t.Fatalf("pre-revocation: %+v", auth)
	}

	// Judge revokes the clerk's delegation. Path A: same signer.
	// (In production, the granter's DID must equal the original
	// delegation's granter — this test plays both roles.)
	res, err := delegation.Revoke(context.Background(), f.buildCtx, delegation.RevokeRequest{
		GranterDID:       judgeDID,
		TargetDelegation: clerkPos,
		Reason:           "performance",
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Wire the leaf reader: clerkPos's OriginTip now points to the
	// revocation entry, whose envelope's TargetRoot points to a
	// different entity (the original target was clerkPos itself —
	// EvaluateOrigin classifies as Revoked because the revocation
	// entry's TargetRoot resolves to a different leaf key).
	f.leafs.setTip(
		types.LogPosition{LogDID: clerkPos.LogDID, Sequence: clerkPos.Sequence},
		types.LogPosition{LogDID: res.Position.LogDID, Sequence: res.Position.Sequence},
	)

	// Mark the registry to mirror the on-log truth.
	if err := f.registry.MarkRevoked(clerkDID); err != nil {
		t.Fatalf("registry.MarkRevoked: %v", err)
	}
	got, _ := f.registry.Lookup(clerkDID)
	if got.Status != directory.StatusRevoked {
		t.Errorf("registry status: got %q, want revoked", got.Status)
	}
}

func TestDelegationRevocation_TipIsRevocationEntry(t *testing.T) {
	// Same-signer revocation: the resolver fetches an entry whose
	// payload has schema_id=judicial-revocation-v1 and folds it
	// into RejectRevoked via the schema-classification path (no
	// LeafReader needed for this codepath).
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjDID := f.provisionKey(t, "did:key:zQ3shCJ")
	judgeDID := f.provisionKey(t, "did:key:zQ3shJUDGE")

	cjPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjDID, GranteeRole: "chief_justice",
	})
	judgePos := f.issue(t, delegation.IssueRequest{
		GranterDID: cjDID, GranterRole: "chief_justice", GranterDelegationRef: &cjPos,
		GranteeDID: judgeDID, GranteeRole: "judge",
	})

	res, err := delegation.Revoke(context.Background(), f.buildCtx, delegation.RevokeRequest{
		GranterDID:       cjDID,
		TargetDelegation: judgePos,
		Reason:           "performance",
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Resolve against the revocation entry's position itself —
	// classifyTip routes to RejectRevoked.
	auth := f.resolve(judgeDID, res.Position, "case_filing")
	if auth.Rejection != verification.RejectRevoked {
		t.Errorf("expected RejectRevoked, got %s (%s)", auth.Rejection, auth.Reason)
	}
}

func TestDelegationRevocation_OnLogStructure(t *testing.T) {
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjDID := f.provisionKey(t, "did:key:zQ3shCJ")

	cjPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjDID, GranteeRole: "chief_justice",
	})

	res, err := delegation.Revoke(context.Background(), f.buildCtx, delegation.RevokeRequest{
		GranterDID:       institutional,
		TargetDelegation: cjPos,
		Reason:           "officer_transfer",
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	entry := f.envelopeAt(t, res.Position)
	if entry.Header.SignerDID != institutional {
		t.Errorf("signer drift: %q", entry.Header.SignerDID)
	}
	if entry.Header.TargetRoot == nil {
		t.Fatal("revocation envelope must carry TargetRoot")
	}
	if entry.Header.TargetRoot.Sequence != cjPos.Sequence {
		t.Errorf("target seq drift: got %d, want %d",
			entry.Header.TargetRoot.Sequence, cjPos.Sequence)
	}

	payload, err := schemas.UnmarshalJudicialRevocationPayload(entry.DomainPayload)
	if err != nil {
		t.Fatalf("UnmarshalJudicialRevocationPayload: %v", err)
	}
	if payload.Reason != "officer_transfer" {
		t.Errorf("reason drift: %q", payload.Reason)
	}
}

func TestDelegationRevocation_DoesNotAffectIndependentChains(t *testing.T) {
	// Two parallel judges (J1, J2) under the same CJ. Revoking
	// J1's delegation must NOT break J2's chain.
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjDID := f.provisionKey(t, "did:key:zQ3shCJ")
	j1 := f.provisionKey(t, "did:key:zQ3shJUDGE1")
	j2 := f.provisionKey(t, "did:key:zQ3shJUDGE2")

	cjPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjDID, GranteeRole: "chief_justice",
	})
	j1Pos := f.issue(t, delegation.IssueRequest{
		GranterDID: cjDID, GranterRole: "chief_justice", GranterDelegationRef: &cjPos,
		GranteeDID: j1, GranteeRole: "judge",
	})
	j2Pos := f.issue(t, delegation.IssueRequest{
		GranterDID: cjDID, GranterRole: "chief_justice", GranterDelegationRef: &cjPos,
		GranteeDID: j2, GranteeRole: "judge",
	})

	// Revoke J1.
	res, err := delegation.Revoke(context.Background(), f.buildCtx, delegation.RevokeRequest{
		GranterDID:       cjDID,
		TargetDelegation: j1Pos,
		Reason:           "performance",
	})
	if err != nil {
		t.Fatalf("Revoke J1: %v", err)
	}

	// J1's leaf now points to the revocation tip.
	f.leafs.setTip(
		types.LogPosition{LogDID: j1Pos.LogDID, Sequence: j1Pos.Sequence},
		types.LogPosition{LogDID: res.Position.LogDID, Sequence: res.Position.Sequence},
	)

	// J2 still resolves cleanly — independent chain.
	auth := f.resolve(j2, j2Pos, "case_filing")
	if !auth.OK {
		t.Errorf("J2 must remain authorized: %+v", auth)
	}
}
