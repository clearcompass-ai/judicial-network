// FILE PATH: escrow/override_test.go
//
// Tests for Phase 6 escrow-override structural validation. The
// SDK's cosign.Verify is the cryptographic source of truth
// (covered by attesta/crypto/cosign/escrow_override_test.go);
// these tests cover JN's pre-flight checks and the
// PurposeTag() constant:
//
//  1. VerifyAndWrap rejects a nil WitnessKeySet (ErrEscrowOverride).
//  2. VerifyAndWrap rejects zero EscrowID.
//  3. VerifyAndWrap rejects zero DecisionHash.
//  4. VerifyAndWrap rejects zero Effective.
//  5. VerifyAndWrap rejects an empty signature slice.
//  6. PurposeTag returns cosign.PurposeEscrowOverride exactly.
//  7. PurposeTag is distinct from PurposeTreeHead (cross-purpose
//     replay defence — Trust Alignment 9).
package escrow

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/types"
)

func TestVerifyAndWrap_RejectsNilSet(t *testing.T) {
	_, err := VerifyAndWrap(OverrideAuthorization{
		EscrowID:     [32]byte{0x01},
		DecisionHash: [32]byte{0x02},
		Effective:    1,
		Signatures:   []types.WitnessSignature{{SchemeTag: 1, SigBytes: []byte{0x03}}},
	}, nil)
	if !errors.Is(err, ErrEscrowOverride) {
		t.Fatalf("want ErrEscrowOverride, got %v", err)
	}
}

func TestVerifyAndWrap_RejectsZeroEscrowID(t *testing.T) {
	_, err := VerifyAndWrap(OverrideAuthorization{
		DecisionHash: [32]byte{0x02},
		Effective:    1,
		Signatures:   []types.WitnessSignature{{SchemeTag: 1, SigBytes: []byte{0x03}}},
	}, &cosign.WitnessKeySet{})
	if !errors.Is(err, ErrEscrowOverride) {
		t.Fatalf("want ErrEscrowOverride, got %v", err)
	}
}

func TestVerifyAndWrap_RejectsZeroDecisionHash(t *testing.T) {
	_, err := VerifyAndWrap(OverrideAuthorization{
		EscrowID:   [32]byte{0x01},
		Effective:  1,
		Signatures: []types.WitnessSignature{{SchemeTag: 1, SigBytes: []byte{0x03}}},
	}, &cosign.WitnessKeySet{})
	if !errors.Is(err, ErrEscrowOverride) {
		t.Fatalf("want ErrEscrowOverride, got %v", err)
	}
}

func TestVerifyAndWrap_RejectsZeroEffective(t *testing.T) {
	_, err := VerifyAndWrap(OverrideAuthorization{
		EscrowID:     [32]byte{0x01},
		DecisionHash: [32]byte{0x02},
		Signatures:   []types.WitnessSignature{{SchemeTag: 1, SigBytes: []byte{0x03}}},
	}, &cosign.WitnessKeySet{})
	if !errors.Is(err, ErrEscrowOverride) {
		t.Fatalf("want ErrEscrowOverride, got %v", err)
	}
}

func TestVerifyAndWrap_RejectsNoSignatures(t *testing.T) {
	_, err := VerifyAndWrap(OverrideAuthorization{
		EscrowID:     [32]byte{0x01},
		DecisionHash: [32]byte{0x02},
		Effective:    1,
	}, &cosign.WitnessKeySet{})
	if !errors.Is(err, ErrEscrowOverride) {
		t.Fatalf("want ErrEscrowOverride, got %v", err)
	}
}

func TestPurposeTag_IsEscrowOverride(t *testing.T) {
	got := PurposeTag()
	if got != cosign.PurposeEscrowOverride {
		t.Fatalf("PurposeTag = %q, want %q", got, cosign.PurposeEscrowOverride)
	}
}

func TestPurposeTag_DistinctFromTreeHead(t *testing.T) {
	// Trust Alignment 9: cross-purpose replay must be
	// structurally impossible. The two Purpose strings live in
	// disjoint ECDSA digest spaces because they DIFFER as bytes.
	if PurposeTag() == cosign.PurposeTreeHead {
		t.Fatalf("PurposeEscrowOverride must NOT equal PurposeTreeHead (cross-purpose replay defence)")
	}
}

func TestPurposeTag_DistinctFromRotation(t *testing.T) {
	if PurposeTag() == cosign.PurposeRotation {
		t.Fatalf("PurposeEscrowOverride must NOT equal PurposeRotation")
	}
}

func TestPurposeTag_DistinctFromGossipEventV1(t *testing.T) {
	if PurposeTag() == cosign.PurposeGossipEventV1 {
		t.Fatalf("PurposeEscrowOverride must NOT equal PurposeGossipEventV1")
	}
}
