/*
FILE PATH: tests/contracts/delegation_revocation_real_test.go

DESCRIPTION:

	The REAL-producer liveness vector for the revoked-judge lock (#124 E1).

	The existing gate lock (verification/smt_authority_test.go) hand-sets the
	leaf's OriginTip via a synthetic reader — it locks the logic on one engine
	but the test author writes the post-revocation state directly. This test
	closes that gap: it mints a real delegation chain and a real
	delegation.Revoke through the real ledger backend, REBUILDS the OriginTip
	projection from the log (Path-A path compression), and asserts the LIVE
	gate (SMTAuthorityResolver, OriginTip==position) rejects the revoked judge.

	No leaf is hand-set — the revocation drives the liveness signal end to end.
*/
package contracts

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/types"
	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// rebuildOriginTips derives every delegation leaf's OriginTip from the
// submitted entries — exactly the ledger's Path-A rule, as a PROJECTION
// rebuilt from the log (Rebuild-From-The-Log-Alone): a fresh
// judicial-delegation-v1 entry's tip is its own position (live); a
// judicial-revocation-v1 entry advances its target_delegation's tip to the
// revocation's position (revoked). Because the tip is derived from the real
// revocation rather than hand-set, a real BuildRevocation — not the test
// author — produces the liveness signal.
func rebuildOriginTips(t *testing.T, lb *ledgerBackend) *leafBackend {
	t.Helper()
	proj := newLeafBackend()
	lb.mu.RLock()
	maxSeq, logDID := lb.nextSeq, lb.logDID
	lb.mu.RUnlock()

	for seq := uint64(1); seq <= maxSeq; seq++ {
		meta, _ := lb.Fetch(context.Background(), types.LogPosition{LogDID: logDID, Sequence: seq})
		if meta == nil {
			continue
		}
		e, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			continue
		}
		var probe struct {
			SchemaID         string `json:"schema_id"`
			TargetDelegation struct {
				LogDID   string `json:"log_did"`
				Sequence uint64 `json:"sequence"`
			} `json:"target_delegation"`
		}
		if json.Unmarshal(e.DomainPayload, &probe) != nil {
			continue
		}
		thisPos := types.LogPosition{LogDID: logDID, Sequence: seq}
		switch probe.SchemaID {
		case schemas.SchemaJudicialDelegationV1:
			proj.setTip(thisPos, thisPos) // fresh grant: tip == own position
		case schemas.SchemaJudicialRevocationV1:
			target := types.LogPosition{LogDID: probe.TargetDelegation.LogDID, Sequence: probe.TargetDelegation.Sequence}
			proj.setTip(target, thisPos) // Path A: advance the target's tip
		}
	}
	return proj
}

func (f *contractFixture) gate(t *testing.T) *verification.SMTAuthorityResolver {
	t.Helper()
	return verification.NewSMTAuthorityResolver(f.ledger, rebuildOriginTips(t, f.ledger))
}

func (f *contractFixture) gateResolve(signerDID string, ref schemas.LogPositionRef, action string, g *verification.SMTAuthorityResolver) jurisdiction.AuthorityVerdict {
	return g.Resolve(context.Background(), jurisdiction.AuthorityRequest{
		SignerDID:       signerDID,
		DelegationRef:   jurisdiction.DelegationRef{LogDID: ref.LogDID, Sequence: ref.Sequence},
		RequestedAction: action,
	})
}

// TestRealRevocation_GateRejectsRevokedJudge is the producer vector #124 E1:
// real Issue + real Revoke → projection rebuilt from the log → the live gate
// rejects the revoked judge via OriginTip != position.
func TestRealRevocation_GateRejectsRevokedJudge(t *testing.T) {
	f := newFixture(t)
	institutional := f.provisionKey(t, f.institutionalDID)
	cjDID := f.provisionKey(t, "did:key:zQ3shCJrev")
	judgeDID := f.provisionKey(t, "did:key:zQ3shJUDGErev")

	// Real chain: institutional -> chief_justice -> judge.
	cjPos := f.issue(t, delegation.IssueRequest{
		GranterDID:  institutional,
		GranteeDID:  cjDID,
		GranteeRole: "chief_justice",
	})
	judgePos := f.issue(t, delegation.IssueRequest{
		GranterDID:           cjDID,
		GranterRole:          "chief_justice",
		GranterDelegationRef: &cjPos,
		GranteeDID:           judgeDID,
		GranteeRole:          "judge",
	})

	// Pre-revocation: the rebuilt projection makes the judge LIVE; the gate
	// authorizes case_filing.
	if v := f.gateResolve(judgeDID, judgePos, "case_filing", f.gate(t)); !v.OK {
		t.Fatalf("pre-revocation: judge must verify, got rejection %q", v.Rejection)
	}

	// REAL revocation: the chief_justice (the judge's granter) revokes the judge.
	if _, err := delegation.Revoke(context.Background(), f.buildCtx, delegation.RevokeRequest{
		GranterDID:       cjDID,
		TargetDelegation: judgePos,
		Reason:           "officer_transfer",
	}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Post-revocation: rebuild the projection FROM THE LOG. The judge leaf's
	// OriginTip now points at the revocation (!= its own position), so the
	// live gate MUST reject — the EvaluateOrigin false-negative is impossible
	// here by construction (OriginTip==position).
	v := f.gateResolve(judgeDID, judgePos, "case_filing", f.gate(t))
	if v.OK {
		t.Fatalf("revoked judge MUST NOT verify — a real BuildRevocation advanced the OriginTip; the gate has to see it")
	}
	if v.Rejection == "" {
		t.Errorf("expected a rejection token for the revoked judge, got empty")
	}
}
