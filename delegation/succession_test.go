/*
FILE PATH: delegation/succession_test.go

DESCRIPTION:
    Tests for delegation.Succeed. Helpers (fakeOperator,
    stubBoundProvider, newBuildContext) are shared from
    issue_test.go.
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

func TestSucceed_HappyPath_FullInheritance(t *testing.T) {
	institutional := "did:web:da:davidson-tn"
	successor := "did:key:zQ3shCJ_NEW"
	target := schemas.LogPositionRef{LogDID: institutional, Sequence: 7}

	sp := stubBoundProvider(t, institutional)
	op := &fakeOperator{}
	bc := newBuildContext(t, sp, op)

	res, err := Succeed(context.Background(), bc, SuccessionRequest{
		SignerDID:        institutional,
		TargetDelegation: target,
		SuccessorDID:     successor,
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
	if res.Payload.SuccessorDID != successor {
		t.Errorf("successor drift: %q", res.Payload.SuccessorDID)
	}
	if res.Payload.Inheritance != schemas.InheritanceFull {
		t.Errorf("inheritance drift: %q", res.Payload.Inheritance)
	}
	if len(res.Payload.AuthoritySetCosigs) != 2 {
		t.Errorf("cosigs not preserved: %v", res.Payload.AuthoritySetCosigs)
	}

	// Round-trip through SDK envelope decode.
	if len(op.captured) != 1 {
		t.Fatalf("expected 1 submit, got %d", len(op.captured))
	}
	entry, err := envelope.Deserialize(op.captured[0])
	if err != nil {
		t.Fatalf("operator received malformed bytes: %v", err)
	}
	if entry.Header.SignerDID != institutional {
		t.Errorf("signer drift: %q", entry.Header.SignerDID)
	}
	if entry.Header.TargetRoot == nil || entry.Header.TargetRoot.Sequence != 7 {
		t.Errorf("envelope target drift: %+v", entry.Header.TargetRoot)
	}
}

func TestSucceed_NarrowedInheritance(t *testing.T) {
	institutional := "did:web:da:davidson-tn"
	sp := stubBoundProvider(t, institutional)
	op := &fakeOperator{}
	bc := newBuildContext(t, sp, op)

	res, err := Succeed(context.Background(), bc, SuccessionRequest{
		SignerDID:        institutional,
		TargetDelegation: schemas.LogPositionRef{LogDID: institutional, Sequence: 1},
		SuccessorDID:     "did:key:zQ3shNEW",
		Reason:           "removal",
		Inheritance:      schemas.InheritanceNarrowed,
		NarrowedScope:    []string{"case_filing", "docket_management"},
	})
	if err != nil {
		t.Fatalf("Succeed (narrowed): %v", err)
	}
	if len(res.Payload.NarrowedScope) != 2 {
		t.Errorf("narrowed_scope not preserved: %v", res.Payload.NarrowedScope)
	}
}

func TestSucceed_RejectsMissingFields(t *testing.T) {
	institutional := "did:web:da:davidson-tn"
	sp := stubBoundProvider(t, institutional)
	op := &fakeOperator{}
	bc := newBuildContext(t, sp, op)

	cases := []struct {
		name string
		req  SuccessionRequest
		want string
	}{
		{
			name: "missing signer",
			req: SuccessionRequest{
				TargetDelegation: schemas.LogPositionRef{LogDID: "x", Sequence: 1},
				SuccessorDID:     "did:key:zQ3shS",
				Reason:           "death_in_office",
				Inheritance:      schemas.InheritanceFull,
			},
			want: "signer_did",
		},
		{
			name: "missing target log_did",
			req: SuccessionRequest{
				SignerDID:    institutional,
				SuccessorDID: "did:key:zQ3shS",
				Reason:       "death_in_office",
				Inheritance:  schemas.InheritanceFull,
			},
			want: "target_delegation",
		},
		{
			name: "missing successor",
			req: SuccessionRequest{
				SignerDID:        institutional,
				TargetDelegation: schemas.LogPositionRef{LogDID: "x", Sequence: 1},
				Reason:           "death_in_office",
				Inheritance:      schemas.InheritanceFull,
			},
			want: "successor_did",
		},
		{
			name: "missing reason",
			req: SuccessionRequest{
				SignerDID:        institutional,
				TargetDelegation: schemas.LogPositionRef{LogDID: "x", Sequence: 1},
				SuccessorDID:     "did:key:zQ3shS",
				Inheritance:      schemas.InheritanceFull,
			},
			want: "reason required",
		},
		{
			name: "bad inheritance",
			req: SuccessionRequest{
				SignerDID:        institutional,
				TargetDelegation: schemas.LogPositionRef{LogDID: "x", Sequence: 1},
				SuccessorDID:     "did:key:zQ3shS",
				Reason:           "death_in_office",
				Inheritance:      "expanded",
			},
			want: "inheritance must be one of",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Succeed(context.Background(), bc, tc.req)
			if err == nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("expected ErrInvalidRequest, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err missing %q: %v", tc.want, err)
			}
		})
	}
}

// Narrowed inheritance with empty NarrowedScope triggers the schema's
// own validate guard inside MarshalJudicialSuccessionPayload — comes
// back wrapped in ErrInvalidRequest because the marshal happens after
// the request-validate gate.
func TestSucceed_NarrowedRequiresScope(t *testing.T) {
	institutional := "did:web:da:davidson-tn"
	sp := stubBoundProvider(t, institutional)
	op := &fakeOperator{}
	bc := newBuildContext(t, sp, op)

	_, err := Succeed(context.Background(), bc, SuccessionRequest{
		SignerDID:        institutional,
		TargetDelegation: schemas.LogPositionRef{LogDID: "x", Sequence: 1},
		SuccessorDID:     "did:key:zQ3shS",
		Reason:           "removal",
		Inheritance:      schemas.InheritanceNarrowed,
		// NarrowedScope deliberately empty — schema guard should fire.
	})
	if err == nil {
		t.Fatal("expected error on narrowed without scope")
	}
	if !strings.Contains(err.Error(), "narrowed_scope") {
		t.Errorf("err should mention narrowed_scope: %v", err)
	}
}

func TestSucceed_HonorsSubmitFailed(t *testing.T) {
	institutional := "did:web:da:davidson-tn"
	sp := stubBoundProvider(t, institutional)
	op := &fakeOperator{err: errors.New("synthetic")}
	bc := newBuildContext(t, sp, op)

	_, err := Succeed(context.Background(), bc, SuccessionRequest{
		SignerDID:        institutional,
		TargetDelegation: schemas.LogPositionRef{LogDID: "x", Sequence: 1},
		SuccessorDID:     "did:key:zQ3shS",
		Reason:           "death_in_office",
		Inheritance:      schemas.InheritanceFull,
	})
	if err == nil || !errors.Is(err, ErrSubmitFailed) {
		t.Fatalf("expected ErrSubmitFailed, got: %v", err)
	}
}
