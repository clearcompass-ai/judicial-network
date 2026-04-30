/*
FILE PATH: tests/contracts/delegation_succession_test.go

DESCRIPTION:
    The CJ-death scenario, end-to-end. Builds a 3-hop chain
    (institutional → CJ_old → judge → court_clerk), then publishes
    a judicial-succession-v1 entry naming a successor for the
    chief-justice slot. Pins:

      - The succession is a Path A entry signed by the
        institutional DID with on-payload Authority_Set
        cosignatures.
      - When the leafBackend reports OriginTip = succession_pos
        for CJ_old's leaf, AuthorityResolver passes through
        (succession is authority-preserving).
      - The OfficerRegistry transitions CJ_old → succeeded with
        SuccessorDID = CJ_new.
      - Downstream chains (judge → court_clerk) continue to
        Resolve OK because their granter_delegation_ref still
        points at CJ_old, and CJ_old's chain entry is still
        live (not revoked).
      - Inheritance modes (full / narrowed / clean_slate) all
        produce on-log entries that round-trip through
        UnmarshalJudicialSuccessionPayload.
*/
package contracts

import (
	"context"
	"strings"
	"testing"

	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/clearcompass-ai/judicial-network/directory"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func TestDelegationSuccession_CJDeath_DownstreamChainsSurvive(t *testing.T) {
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjOld := f.provisionKey(t, "did:key:zQ3shCJ_OLD")
	cjNew := f.provisionKey(t, "did:key:zQ3shCJ_NEW")
	judgeDID := f.provisionKey(t, "did:key:zQ3shJUDGE")
	clerkDID := f.provisionKey(t, "did:key:zQ3shCLERK")

	// Build the chain rooted under the old CJ.
	cjOldPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjOld, GranteeRole: "chief_justice",
	})
	judgePos := f.issue(t, delegation.IssueRequest{
		GranterDID: cjOld, GranterRole: "chief_justice", GranterDelegationRef: &cjOldPos,
		GranteeDID: judgeDID, GranteeRole: "judge",
	})
	clerkPos := f.issue(t, delegation.IssueRequest{
		GranterDID: judgeDID, GranterRole: "judge", GranterDelegationRef: &judgePos,
		GranteeDID: clerkDID, GranteeRole: "court_clerk",
	})

	// Sanity: clerk's chain resolves before the succession.
	if auth := f.resolve(clerkDID, clerkPos, "case_filing"); !auth.OK {
		t.Fatalf("pre-succession chain must resolve: %+v", auth)
	}

	// Publish the succession entry: institutional Authority_Set
	// names CJ_new as successor with full inheritance.
	res, err := delegation.Succeed(context.Background(), f.buildCtx, delegation.SuccessionRequest{
		SignerDID:        institutional,
		TargetDelegation: cjOldPos,
		SuccessorDID:     cjNew,
		Reason:           "death_in_office",
		Inheritance:      schemas.InheritanceFull,
		AuthoritySetCosigs: []string{
			"did:key:zQ3shCOSIG1",
			"did:key:zQ3shCOSIG2",
		},
	})
	if err != nil {
		t.Fatalf("Succeed: %v", err)
	}

	// Wire the leaf reader so EvaluateOrigin reports CJ_old's tip
	// has advanced to the succession position.
	f.leafs.setTip(
		types.LogPosition{LogDID: cjOldPos.LogDID, Sequence: cjOldPos.Sequence},
		types.LogPosition{LogDID: res.Position.LogDID, Sequence: res.Position.Sequence},
	)

	// Mark the registry to mirror the on-log truth.
	if err := f.registry.MarkSucceeded(cjOld, cjNew); err != nil {
		t.Fatalf("registry.MarkSucceeded: %v", err)
	}
	got, err := f.registry.Lookup(cjOld)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Status != directory.StatusSucceeded {
		t.Errorf("registry status: got %q, want succeeded", got.Status)
	}
	if got.SuccessorDID != cjNew {
		t.Errorf("registry successor: got %q, want %q", got.SuccessorDID, cjNew)
	}

	// Clerk's chain still resolves: succession at the CJ_old hop
	// is authority-preserving (the institutional Authority_Set
	// cosigned the redirect).
	auth := f.resolve(clerkDID, clerkPos, "case_filing")
	if !auth.OK {
		t.Fatalf("downstream chain must survive succession: %+v", auth)
	}
	if auth.Depth != 3 {
		t.Errorf("post-succession depth: got %d, want 3", auth.Depth)
	}
}

func TestDelegationSuccession_NarrowedInheritance_OnLogStructure(t *testing.T) {
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjOld := f.provisionKey(t, "did:key:zQ3shCJ_OLD")

	cjOldPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjOld, GranteeRole: "chief_justice",
	})

	res, err := delegation.Succeed(context.Background(), f.buildCtx, delegation.SuccessionRequest{
		SignerDID:        institutional,
		TargetDelegation: cjOldPos,
		SuccessorDID:     "did:key:zQ3shCJ_NEW",
		Reason:           "removal",
		Inheritance:      schemas.InheritanceNarrowed,
		NarrowedScope:    []string{"case_filing", "docket_management"},
	})
	if err != nil {
		t.Fatalf("Succeed (narrowed): %v", err)
	}

	// Round-trip through SDK envelope + schema decoder.
	entry := f.envelopeAt(t, res.Position)
	payload, err := schemas.UnmarshalJudicialSuccessionPayload(entry.DomainPayload)
	if err != nil {
		t.Fatalf("UnmarshalJudicialSuccessionPayload: %v", err)
	}
	if payload.Inheritance != schemas.InheritanceNarrowed {
		t.Errorf("inheritance drift: %q", payload.Inheritance)
	}
	if len(payload.NarrowedScope) != 2 {
		t.Errorf("narrowed_scope drift: %v", payload.NarrowedScope)
	}
}

func TestDelegationSuccession_CleanSlateInheritance(t *testing.T) {
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjOld := f.provisionKey(t, "did:key:zQ3shCJ_OLD")

	cjOldPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjOld, GranteeRole: "chief_justice",
	})

	res, err := delegation.Succeed(context.Background(), f.buildCtx, delegation.SuccessionRequest{
		SignerDID:        institutional,
		TargetDelegation: cjOldPos,
		SuccessorDID:     "did:key:zQ3shCJ_NEW",
		Reason:           "resignation",
		Inheritance:      schemas.InheritanceCleanSlate,
	})
	if err != nil {
		t.Fatalf("Succeed (clean_slate): %v", err)
	}
	entry := f.envelopeAt(t, res.Position)
	payload, err := schemas.UnmarshalJudicialSuccessionPayload(entry.DomainPayload)
	if err != nil {
		t.Fatalf("UnmarshalJudicialSuccessionPayload: %v", err)
	}
	if payload.Inheritance != schemas.InheritanceCleanSlate {
		t.Errorf("inheritance drift: %q", payload.Inheritance)
	}
	if len(payload.NarrowedScope) != 0 {
		t.Errorf("clean_slate must have no narrowed_scope: %v", payload.NarrowedScope)
	}
}

func TestDelegationSuccession_OnLogPayloadCosignaturesPreserved(t *testing.T) {
	// Pins that AuthoritySetCosigs round-trips through the on-log
	// payload. Auditors reading the log must see who cosigned a
	// CJ-replacement decision.
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjOld := f.provisionKey(t, "did:key:zQ3shCJ_OLD")

	cjOldPos := f.issue(t, delegation.IssueRequest{
		GranterDID: institutional, GranteeDID: cjOld, GranteeRole: "chief_justice",
	})

	cosigs := []string{
		"did:key:zQ3shCOSIG1",
		"did:key:zQ3shCOSIG2",
		"did:key:zQ3shCOSIG3",
	}
	res, err := delegation.Succeed(context.Background(), f.buildCtx, delegation.SuccessionRequest{
		SignerDID:          institutional,
		TargetDelegation:   cjOldPos,
		SuccessorDID:       "did:key:zQ3shCJ_NEW",
		Reason:             "death_in_office",
		Inheritance:        schemas.InheritanceFull,
		AuthoritySetCosigs: cosigs,
	})
	if err != nil {
		t.Fatalf("Succeed: %v", err)
	}

	entry := f.envelopeAt(t, res.Position)
	payload, err := schemas.UnmarshalJudicialSuccessionPayload(entry.DomainPayload)
	if err != nil {
		t.Fatalf("UnmarshalJudicialSuccessionPayload: %v", err)
	}
	if len(payload.AuthoritySetCosigs) != len(cosigs) {
		t.Fatalf("cosig len: got %d, want %d", len(payload.AuthoritySetCosigs), len(cosigs))
	}
	for i, c := range cosigs {
		if payload.AuthoritySetCosigs[i] != c {
			t.Errorf("cosig[%d]: got %q, want %q", i, payload.AuthoritySetCosigs[i], c)
		}
	}
}

func TestDelegationSuccession_RegistryPreventsRevocationAfterSucceed(t *testing.T) {
	r := directory.NewInMemoryRegistry()
	cjOld := "did:key:zQ3shCJ_OLD"
	if err := r.Add(directory.Officer{
		DID: cjOld, Alias: "Hon. Old Williams", Role: "chief_justice",
		DelegationRef: schemas.LogPositionRef{LogDID: "did:web:da:davidson-tn", Sequence: 1},
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := r.MarkSucceeded(cjOld, "did:key:zQ3shCJ_NEW"); err != nil {
		t.Fatalf("MarkSucceeded: %v", err)
	}
	err := r.MarkRevoked(cjOld)
	if err == nil || !strings.Contains(err.Error(), "succeeded") {
		t.Errorf("expected illegal-transition rejection, got: %v", err)
	}
}
