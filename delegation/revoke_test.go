/*
FILE PATH: delegation/revoke_test.go

DESCRIPTION:
    Tests for delegation.Revoke. Helpers (fakeOperator,
    stubBoundProvider, newBuildContext) are shared from issue_test.go.
*/
package delegation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

func TestRevoke_HappyPath(t *testing.T) {
	cjDID := "did:key:zQ3shCJ"
	target := schemas.LogPositionRef{LogDID: "did:web:da:davidson-tn", Sequence: 7}

	sp := stubBoundProvider(t, cjDID)
	op := &fakeOperator{}
	bc := newBuildContext(t, sp, op)

	res, err := Revoke(context.Background(), bc, RevokeRequest{
		GranterDID:       cjDID,
		TargetDelegation: target,
		Reason:           "performance",
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if res.Payload.Reason != "performance" {
		t.Errorf("reason drift: %q", res.Payload.Reason)
	}
	if res.Payload.TargetDelegation.Sequence != 7 {
		t.Errorf("target seq drift: %d", res.Payload.TargetDelegation.Sequence)
	}
	if len(op.captured) != 1 {
		t.Fatalf("expected 1 submit, got %d", len(op.captured))
	}

	// Round-trip through SDK envelope decode.
	entry, err := envelope.Deserialize(op.captured[0])
	if err != nil {
		t.Fatalf("operator received malformed bytes: %v", err)
	}
	if entry.Header.SignerDID != cjDID {
		t.Errorf("signer drift: %q", entry.Header.SignerDID)
	}
	if entry.Header.TargetRoot == nil {
		t.Fatal("revocation envelope must carry TargetRoot")
	}
	if entry.Header.TargetRoot.Sequence != 7 {
		t.Errorf("envelope target seq drift: %d", entry.Header.TargetRoot.Sequence)
	}
}

func TestRevoke_RejectsMissingFields(t *testing.T) {
	cjDID := "did:key:zQ3shCJ"
	sp := stubBoundProvider(t, cjDID)
	op := &fakeOperator{}
	bc := newBuildContext(t, sp, op)

	cases := []struct {
		name string
		req  RevokeRequest
		want string
	}{
		{
			name: "missing granter",
			req: RevokeRequest{
				TargetDelegation: schemas.LogPositionRef{LogDID: "x", Sequence: 1},
				Reason:           "performance",
			},
			want: "granter_did",
		},
		{
			name: "missing target log_did",
			req:  RevokeRequest{GranterDID: cjDID, Reason: "performance"},
			want: "target_delegation",
		},
		{
			name: "missing reason",
			req: RevokeRequest{
				GranterDID:       cjDID,
				TargetDelegation: schemas.LogPositionRef{LogDID: "x", Sequence: 1},
			},
			want: "reason required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Revoke(context.Background(), bc, tc.req)
			if err == nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected ErrInvalidRequest, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err missing %q: %v", tc.want, err)
			}
		})
	}
}

func TestRevoke_HonorsSignRejected(t *testing.T) {
	cjDID := "did:key:zQ3shCJ"
	sp := stubBoundProvider(t, cjDID)
	sp.RejectSigning(cjDID, true)
	op := &fakeOperator{}
	bc := newBuildContext(t, sp, op)

	_, err := Revoke(context.Background(), bc, RevokeRequest{
		GranterDID:       cjDID,
		TargetDelegation: schemas.LogPositionRef{LogDID: "x", Sequence: 1},
		Reason:           "performance",
	})
	if err == nil || !errors.Is(err, ErrSignFailed) {
		t.Fatalf("expected ErrSignFailed, got: %v", err)
	}
}

func TestRevoke_HonorsSubmitFailed(t *testing.T) {
	cjDID := "did:key:zQ3shCJ"
	sp := stubBoundProvider(t, cjDID)
	op := &fakeOperator{err: errors.New("synthetic")}
	bc := newBuildContext(t, sp, op)

	_, err := Revoke(context.Background(), bc, RevokeRequest{
		GranterDID:       cjDID,
		TargetDelegation: schemas.LogPositionRef{LogDID: "x", Sequence: 1},
		Reason:           "performance",
	})
	if err == nil || !errors.Is(err, ErrSubmitFailed) {
		t.Fatalf("expected ErrSubmitFailed, got: %v", err)
	}
}
