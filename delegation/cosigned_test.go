/*
FILE PATH: delegation/cosigned_test.go

DESCRIPTION:

	Tests for the inline cosignature pipeline. Pins:
	  - happy path: 1 primary + 1 cosigner produces a 2-sig envelope
	    whose canonical bytes round-trip through envelope.Deserialize;
	  - N-cosigner case (Authority_Set 2-of-3 + primary = 3 sigs);
	  - structural validation (empty list, duplicate, primary in list,
	    too many, nil ctx fields);
	  - sign rejection (primary or any cosigner declines → no submit);
	  - unknown signer (cosigner not bound on the IdentityProvider);
	  - all signatures share the same SigningPayload digest (envelope
	    round-trip + recover identity from each signature).

	Helpers (fakeLedger, stubBoundProvider, newBuildContext) come
	from issue_test.go; both files are in the delegation_test package.
*/
package delegation

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// ─── helpers ────────────────────────────────────────────────────────

// unsignedEntryFor returns a fresh unsigned envelope ready to feed
// into signAndSubmitCosigned. Header.SignerDID equals primary.
func unsignedEntryFor(t *testing.T, primary string) *envelope.Entry {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	header := envelope.ControlHeader{
		Destination:   "did:web:test.exchange",
		SignerDID:     primary,
		AuthorityPath: &auth,
	}
	entry, err := envelope.NewUnsignedEntry(header, []byte(`{"event_type":"test","filed_by":"bar:TN:1"}`))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return entry
}

// cosignedDisplay returns a typed-data display valid for the
// cosigned-pipeline tests.
func cosignedDisplay() *identity.TypedDataDisplay {
	return &identity.TypedDataDisplay{
		Domain: identity.EIP712Domain{
			Name:    "Judicial Network",
			Version: "v1",
			Salt:    "did:web:state:tn:davidson",
		},
		PrimaryType: "AttorneyFiling",
		Fields: []identity.EIP712Field{
			{Name: "filed_by", Type: "string", Value: "bar:TN:1"},
			{Name: "event_type", Type: "string", Value: "motion_continuance"},
		},
	}
}

// ─── happy paths ────────────────────────────────────────────────────

func TestSignAndSubmitCosigned_HappyPath_OneCosigner(t *testing.T) {
	primary := "did:key:zQ3shCLERK"
	cj := "did:key:zQ3shCJ"

	sp := stubBoundProvider(t, primary)
	priv2, _ := secp256k1.GeneratePrivateKey()
	sp.BindKey(cj, priv2)

	op := &fakeLedger{}
	bc := newBuildContext(t, sp, op)

	entry := unsignedEntryFor(t, primary)
	pos, err := SignAndSubmitCosigned(context.Background(), bc, entry,
		cosignedDisplay(), "Filing on behalf of attorney bar:TN:1",
		[]string{cj})
	if err != nil {
		t.Fatalf("signAndSubmitCosigned: %v", err)
	}
	if pos.Sequence != 1 {
		t.Errorf("position seq drift: %d", pos.Sequence)
	}
	if len(op.captured) != 1 {
		t.Fatalf("expected 1 submit, got %d", len(op.captured))
	}

	// Round-trip through SDK envelope decode and inspect signatures.
	got, err := envelope.Deserialize(op.captured[0])
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if len(got.Signatures) != 2 {
		t.Fatalf("len(Signatures) = %d, want 2", len(got.Signatures))
	}
	if got.Signatures[0].SignerDID != primary {
		t.Errorf("Signatures[0]: got %q want %q", got.Signatures[0].SignerDID, primary)
	}
	if got.Signatures[1].SignerDID != cj {
		t.Errorf("Signatures[1]: got %q want %q", got.Signatures[1].SignerDID, cj)
	}
	for i, s := range got.Signatures {
		if s.AlgoID != envelope.SigAlgoECDSA {
			t.Errorf("Signatures[%d] alg drift: %d", i, s.AlgoID)
		}
		if len(s.Bytes) != 64 {
			t.Errorf("Signatures[%d] should be 64-byte R||S, got %d", i, len(s.Bytes))
		}
	}
}

func TestSignAndSubmitCosigned_AuthoritySet_TwoCosigners(t *testing.T) {
	institutional := "did:web:state:tn:davidson"
	cosigA := "did:key:zQ3shCOSIG_A"
	cosigB := "did:key:zQ3shCOSIG_B"

	sp := stubBoundProvider(t, institutional)
	for _, did := range []string{cosigA, cosigB} {
		priv, _ := secp256k1.GeneratePrivateKey()
		sp.BindKey(did, priv)
	}
	op := &fakeLedger{}
	bc := newBuildContext(t, sp, op)

	entry := unsignedEntryFor(t, institutional)
	pos, err := SignAndSubmitCosigned(context.Background(), bc, entry,
		cosignedDisplay(), "Authority_Set succession",
		[]string{cosigA, cosigB})
	if err != nil {
		t.Fatalf("signAndSubmitCosigned: %v", err)
	}
	if pos.Sequence != 1 {
		t.Errorf("position seq drift: %d", pos.Sequence)
	}
	got, _ := envelope.Deserialize(op.captured[0])
	if len(got.Signatures) != 3 {
		t.Errorf("len(Signatures) = %d, want 3", len(got.Signatures))
	}
}

// TestSignAndSubmitCosigned_AllSignaturesShareDigest pins the
// invariant that every Signature recovers a public key matching
// the bound key for its SignerDID over the SAME digest. This is
// the contract verifiers depend on — cosignatures over a
// different digest break authority.
func TestSignAndSubmitCosigned_AllSignaturesShareDigest(t *testing.T) {
	primary := "did:key:zQ3shPRIMARY"
	cosigner := "did:key:zQ3shCOSIGNER"

	sp := identity.NewStubProvider()
	primPriv, _ := secp256k1.GeneratePrivateKey()
	cosPriv, _ := secp256k1.GeneratePrivateKey()
	sp.BindKey(primary, primPriv)
	sp.BindKey(cosigner, cosPriv)

	op := &fakeLedger{}
	bc := newBuildContext(t, sp, op)

	entry := unsignedEntryFor(t, primary)
	if _, err := SignAndSubmitCosigned(context.Background(), bc, entry,
		cosignedDisplay(), "test", []string{cosigner}); err != nil {
		t.Fatalf("signAndSubmitCosigned: %v", err)
	}

	got, _ := envelope.Deserialize(op.captured[0])
	digest := sha256.Sum256(envelope.SigningPayload(got))

	// Each signature must round-trip via RecoverCompact-equivalent.
	// SDK's SigAlgoECDSA strips the recovery byte, so we cannot
	// recover-and-compare. Instead, verify the signature with the
	// bound public key directly via dcrecdsa (parsing R||S).
	for i, s := range got.Signatures {
		if len(s.Bytes) != 64 {
			t.Fatalf("Signatures[%d] not 64 bytes", i)
		}
		var bound *secp256k1.PublicKey
		switch s.SignerDID {
		case primary:
			bound = primPriv.PubKey()
		case cosigner:
			bound = cosPriv.PubKey()
		default:
			t.Fatalf("unexpected signer %q", s.SignerDID)
		}
		// Reconstruct a compact signature for verification by
		// re-prepending a recovery byte (0). The dcrd package
		// VerifyCompact path is RecoverCompact; we use a different
		// route — parse R/S manually and call ecdsa.Signature.Verify.
		r := new(secp256k1.ModNScalar)
		s2 := new(secp256k1.ModNScalar)
		var rb, sb [32]byte
		copy(rb[:], s.Bytes[:32])
		copy(sb[:], s.Bytes[32:])
		r.SetBytes(&rb)
		s2.SetBytes(&sb)
		sig := dcrecdsa.NewSignature(r, s2)
		if !sig.Verify(digest[:], bound) {
			t.Errorf("Signatures[%d] (signer=%s) does not verify against bound pubkey",
				i, s.SignerDID)
		}
	}
}

// emptySignerEntry returns an Entry constructed bare, with no
// Header.SignerDID. Used by the structural-rejection test in
// cosigned_rejection_test.go to exercise the guard inside
// signAndSubmitCosigned that runs before any SDK call.
func emptySignerEntry() *envelope.Entry {
	return &envelope.Entry{}
}
