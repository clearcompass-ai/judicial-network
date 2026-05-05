/*
FILE PATH: delegation/cosigned_rejection_test.go

DESCRIPTION:

	Structural and sign-rejection coverage for signAndSubmitCosigned.
	Helpers (unsignedEntryFor, cosignedDisplay, fakeLedger,
	stubBoundProvider, newBuildContext) are shared from
	cosigned_test.go and issue_test.go in the same test package.
*/
package delegation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ─── structural rejection ───────────────────────────────────────────

func TestSignAndSubmitCosigned_RejectsEmptyCosigners(t *testing.T) {
	primary := "did:key:zQ3shP"
	sp := stubBoundProvider(t, primary)
	bc := newBuildContext(t, sp, &fakeLedger{})

	entry := unsignedEntryFor(t, primary)
	_, err := SignAndSubmitCosigned(context.Background(), bc, entry,
		cosignedDisplay(), "test", nil)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("err should mention empty cosigner list: %v", err)
	}
}

func TestSignAndSubmitCosigned_RejectsCosignerEqualPrimary(t *testing.T) {
	primary := "did:key:zQ3shP"
	sp := stubBoundProvider(t, primary)
	bc := newBuildContext(t, sp, &fakeLedger{})

	entry := unsignedEntryFor(t, primary)
	_, err := SignAndSubmitCosigned(context.Background(), bc, entry,
		cosignedDisplay(), "test", []string{primary})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
	if !strings.Contains(err.Error(), "primary") {
		t.Errorf("err should mention primary collision: %v", err)
	}
}

func TestSignAndSubmitCosigned_RejectsDuplicateCosigners(t *testing.T) {
	primary := "did:key:zQ3shP"
	sp := stubBoundProvider(t, primary)
	bc := newBuildContext(t, sp, &fakeLedger{})

	entry := unsignedEntryFor(t, primary)
	_, err := SignAndSubmitCosigned(context.Background(), bc, entry,
		cosignedDisplay(), "test", []string{"did:key:zQ3shA", "did:key:zQ3shA"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("err should mention duplicate: %v", err)
	}
}

func TestSignAndSubmitCosigned_RejectsEmptyCosignerDID(t *testing.T) {
	primary := "did:key:zQ3shP"
	sp := stubBoundProvider(t, primary)
	bc := newBuildContext(t, sp, &fakeLedger{})

	entry := unsignedEntryFor(t, primary)
	_, err := SignAndSubmitCosigned(context.Background(), bc, entry,
		cosignedDisplay(), "test", []string{""})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
}

func TestSignAndSubmitCosigned_RejectsTooManyCosigners(t *testing.T) {
	primary := "did:key:zQ3shP"
	sp := stubBoundProvider(t, primary)
	bc := newBuildContext(t, sp, &fakeLedger{})

	cosigners := make([]string, MaxCosigners+1)
	for i := range cosigners {
		cosigners[i] = "did:key:cosigner-" + string(rune('A'+i%26))
	}
	entry := unsignedEntryFor(t, primary)
	_, err := SignAndSubmitCosigned(context.Background(), bc, entry,
		cosignedDisplay(), "test", cosigners)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
}

func TestSignAndSubmitCosigned_RejectsNilDeps(t *testing.T) {
	_, err := SignAndSubmitCosigned(context.Background(), nil, nil, nil, "x", nil)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("nil bc: %v", err)
	}

	bc := newBuildContext(t, identity.NewStubProvider(), &fakeLedger{})
	_, err = SignAndSubmitCosigned(context.Background(), bc, nil,
		cosignedDisplay(), "x", []string{"did:key:zQ3shA"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("nil entry: %v", err)
	}
}

func TestSignAndSubmitCosigned_RejectsEmptyHeaderSigner(t *testing.T) {
	bc := newBuildContext(t, identity.NewStubProvider(), &fakeLedger{})

	// Construct an Entry with an empty Header.SignerDID directly.
	// The SDK's NewUnsignedEntry would reject this, but the test
	// targets the guard in signAndSubmitCosigned that fires before
	// any SDK call so the wallet is never asked to sign an
	// improperly-formed entry.
	entry := emptySignerEntry()

	_, err := SignAndSubmitCosigned(context.Background(), bc, entry,
		cosignedDisplay(), "x", []string{"did:key:zQ3shA"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
	if !strings.Contains(err.Error(), "SignerDID") {
		t.Errorf("err should mention SignerDID: %v", err)
	}
}

// ─── sign rejection ─────────────────────────────────────────────────

func TestSignAndSubmitCosigned_PrimaryRejection(t *testing.T) {
	primary := "did:key:zQ3shP"
	cosigner := "did:key:zQ3shC"
	sp := stubBoundProvider(t, primary)
	priv, _ := secp256k1.GeneratePrivateKey()
	sp.BindKey(cosigner, priv)
	sp.RejectSigning(primary, true)

	op := &fakeLedger{}
	bc := newBuildContext(t, sp, op)
	entry := unsignedEntryFor(t, primary)

	_, err := SignAndSubmitCosigned(context.Background(), bc, entry,
		cosignedDisplay(), "test", []string{cosigner})
	if !errors.Is(err, ErrSignFailed) {
		t.Errorf("expected ErrSignFailed, got: %v", err)
	}
	if !errors.Is(err, identity.ErrSignRejected) {
		t.Errorf("error must wrap identity.ErrSignRejected: %v", err)
	}
	if len(op.captured) != 0 {
		t.Errorf("ledger must not see entries when primary rejects")
	}
}

func TestSignAndSubmitCosigned_CosignerRejection(t *testing.T) {
	primary := "did:key:zQ3shP"
	cosigner := "did:key:zQ3shC"
	sp := stubBoundProvider(t, primary)
	priv, _ := secp256k1.GeneratePrivateKey()
	sp.BindKey(cosigner, priv)
	sp.RejectSigning(cosigner, true)

	op := &fakeLedger{}
	bc := newBuildContext(t, sp, op)
	entry := unsignedEntryFor(t, primary)

	_, err := SignAndSubmitCosigned(context.Background(), bc, entry,
		cosignedDisplay(), "test", []string{cosigner})
	if !errors.Is(err, ErrSignFailed) {
		t.Errorf("expected ErrSignFailed, got: %v", err)
	}
	if !errors.Is(err, identity.ErrSignRejected) {
		t.Errorf("error must wrap identity.ErrSignRejected: %v", err)
	}
	if len(op.captured) != 0 {
		t.Errorf("ledger must not see entries when cosigner rejects")
	}
}

func TestSignAndSubmitCosigned_CosignerUnknown(t *testing.T) {
	primary := "did:key:zQ3shP"
	sp := stubBoundProvider(t, primary)
	op := &fakeLedger{}
	bc := newBuildContext(t, sp, op)
	entry := unsignedEntryFor(t, primary)

	_, err := SignAndSubmitCosigned(context.Background(), bc, entry,
		cosignedDisplay(), "test", []string{"did:key:zQ3shGHOST"})
	if !errors.Is(err, ErrSignFailed) {
		t.Errorf("expected ErrSignFailed, got: %v", err)
	}
	if !errors.Is(err, identity.ErrSignerNotFound) {
		t.Errorf("error must wrap identity.ErrSignerNotFound: %v", err)
	}
}
