/*
FILE PATH: delegation/issue_test.go

DESCRIPTION:

	Tests for delegation.Issue. Wires StubProvider + a fake ledger
	submitter and pins:
	  - happy path institutional → CJ → judge issuance with a real
	    sign-and-submit round trip;
	  - request validation (missing fields, self-delegation);
	  - catalog rejection (unauthorized delegator, scope outside
	    AllowedScope, excessive duration);
	  - identity rejection (user declined sign).
*/
package delegation

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
	davidson "github.com/clearcompass-ai/judicial-network/internal/testfixtures/davidsonlegacy"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ─── fakes ──────────────────────────────────────────────────────────

type fakeLedger struct {
	mu       sync.Mutex
	captured [][]byte
	err      error
	nextSeq  uint64
}

func (f *fakeLedger) SubmitCanonical(ctx context.Context, canonical []byte) (schemas.LogPositionRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return schemas.LogPositionRef{}, f.err
	}
	f.captured = append(f.captured, append([]byte(nil), canonical...))
	f.nextSeq++
	return schemas.LogPositionRef{LogDID: "did:web:test.exchange", Sequence: f.nextSeq}, nil
}

// stubBoundProvider returns a StubProvider with one bound DID/key.
func stubBoundProvider(t *testing.T, did string) *identity.StubProvider {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	sp := identity.NewStubProvider()
	sp.BindKey(did, priv)
	return sp
}

func newBuildContext(t *testing.T, sp *identity.StubProvider, op *fakeLedger) *BuildContext {
	t.Helper()
	return &BuildContext{
		Identity:         sp,
		Submitter:        op,
		Catalog:          davidson.MustRoleCatalog(),
		ExchangeDID:      "did:web:test.exchange",
		InstitutionalDID: "did:web:state:tn:davidson",
	}
}

// ─── happy path ────────────────────────────────────────────────────

func TestIssue_HappyPath_InstitutionalGrantsCJ(t *testing.T) {
	institutional := "did:web:state:tn:davidson"
	cjDID := "did:key:zQ3shCJ"

	sp := stubBoundProvider(t, institutional)
	op := &fakeLedger{}
	bc := newBuildContext(t, sp, op)

	res, err := Issue(context.Background(), bc, IssueRequest{
		GranterDID:  institutional,
		GranterRole: "", // institutional grant
		GranteeDID:  cjDID,
		GranteeRole: "chief_justice",
		Rationale:   "Newly elected; sworn 2026-08-01.",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res.Position.Sequence != 1 {
		t.Errorf("position seq = %d, want 1", res.Position.Sequence)
	}
	if res.Payload.Role != "chief_justice" {
		t.Errorf("role drift: %q", res.Payload.Role)
	}
	if len(res.Payload.Scope) == 0 {
		t.Error("scope should default to role.DefaultScope")
	}

	// The captured canonical bytes must round-trip through the SDK.
	if len(op.captured) != 1 {
		t.Fatalf("expected 1 submit, got %d", len(op.captured))
	}
	entry, err := envelope.Deserialize(op.captured[0])
	if err != nil {
		t.Fatalf("ledger received malformed bytes: %v", err)
	}
	if entry.Header.SignerDID != institutional {
		t.Errorf("entry signer drift: %q", entry.Header.SignerDID)
	}
	if len(entry.Signatures) != 1 || len(entry.Signatures[0].Bytes) != 64 {
		t.Errorf("signature wire format unexpected: %+v", entry.Signatures)
	}
}

func TestIssue_HappyPath_CJ_GrantsJudge(t *testing.T) {
	cjDID := "did:key:zQ3shCJ"
	judgeDID := "did:key:zQ3shJUDGE"
	parentRef := schemas.LogPositionRef{LogDID: "did:web:state:tn:davidson", Sequence: 1}

	sp := stubBoundProvider(t, cjDID)
	op := &fakeLedger{}
	bc := newBuildContext(t, sp, op)

	res, err := Issue(context.Background(), bc, IssueRequest{
		GranterDID:           cjDID,
		GranterRole:          "chief_justice",
		GranterDelegationRef: &parentRef,
		GranteeDID:           judgeDID,
		GranteeRole:          "judge",
		Duration:             4 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res.Payload.Role != "judge" {
		t.Errorf("role drift: %q", res.Payload.Role)
	}
	if res.Payload.GranterDelegationRef == nil ||
		res.Payload.GranterDelegationRef.Sequence != parentRef.Sequence {
		t.Errorf("granter_delegation_ref not preserved: %+v", res.Payload.GranterDelegationRef)
	}
}

// (Rejection-path tests live in issue_rejection_test.go.)
