package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	sdksigs "github.com/baseproof/baseproof/crypto/signatures"
)

// TestAdmissionAuthorizer_MintHeader_VerifiesAgainstJ proves the JN-minted
// WriteAuthorization is exactly what the ledger's gate 5 accepts: it round-trips
// through Encode/Decode, recovers J's address, and verifies against an authorized
// set of {J} — and is rejected against a set that excludes J.
func TestAdmissionAuthorizer_MintHeader_VerifiesAgainstJ(t *testing.T) {
	// J — the JN's admission EOA.
	j, err := sdksigs.GenerateKey()
	if err != nil {
		t.Fatalf("generate J: %v", err)
	}
	jAddr, err := sdksigs.AddressFromPubkey(sdksigs.PubKeyBytes(&j.PublicKey))
	if err != nil {
		t.Fatalf("derive J address: %v", err)
	}

	var anchor [32]byte
	for i := range anchor {
		anchor[i] = byte(i + 1)
	}
	a := NewAdmissionAuthorizer(j, func(string) ([32]byte, error) { return anchor, nil })

	// Confirm the authorizer reports J's address (the value that must be in the
	// ledger's admission keyset for gate 5 to accept).
	gotAddr, err := a.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	if gotAddr != jAddr {
		t.Fatalf("Address() = %x, want %x", gotAddr, jAddr)
	}

	logDID := "did:web:state:tn:davidson"
	signed := buildSignedCommentary(t, logDID)

	hdrB64, err := a.MintHeader(signed)
	if err != nil {
		t.Fatalf("MintHeader: %v", err)
	}

	// Decode exactly as the ledger gate does (base64 → DecodeWriteAuthorization).
	raw, err := base64.StdEncoding.DecodeString(hdrB64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	wa, err := authz.DecodeWriteAuthorization(raw)
	if err != nil {
		t.Fatalf("DecodeWriteAuthorization: %v", err)
	}
	if wa.AsOfAnchor != anchor {
		t.Fatalf("as-of anchor not bound: got %x want %x", wa.AsOfAnchor, anchor)
	}

	entry, err := envelope.Deserialize(signed)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	id, err := envelope.EntryIdentity(entry)
	if err != nil {
		t.Fatalf("entry identity: %v", err)
	}

	// Authorized set = {J} → accept, recovered address == J.
	addr, err := authz.VerifyWriteAuthorization(wa, logDID, id, [][20]byte{jAddr})
	if err != nil {
		t.Fatalf("VerifyWriteAuthorization (authorized): %v", err)
	}
	if addr != jAddr {
		t.Fatalf("recovered %x, want J %x", addr, jAddr)
	}

	// Authorized set excludes J → ErrUnauthorizedWriter (the gate's 403 path).
	var other [20]byte
	other[0] = 0xFF
	if _, err := authz.VerifyWriteAuthorization(wa, logDID, id, [][20]byte{other}); err == nil {
		t.Fatalf("expected rejection when J is not in the authorized set")
	}

	// Wrong log DID must not verify (cross-log replay defence).
	if _, err := authz.VerifyWriteAuthorization(wa, "did:web:other:log", id, [][20]byte{jAddr}); err == nil {
		t.Fatalf("expected rejection for a different log DID")
	}
}

// buildSignedCommentary builds + signs a commentary entry and returns its
// canonical wire bytes — the bytes the JN would forward to the ledger.
func buildSignedCommentary(t *testing.T, logDID string) []byte {
	t.Helper()
	signer, err := sdksigs.GenerateKey()
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	unsigned, err := builder.BuildCommentary(builder.CommentaryParams{
		Destination: logDID,
		SignerDID:   "did:key:zSignerTest",
		Payload:     []byte("hello"),
	})
	if err != nil {
		t.Fatalf("BuildCommentary: %v", err)
	}
	digest := sha256.Sum256(envelope.SigningPayload(unsigned))
	sig, err := sdksigs.SignEntry(digest, signer)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry, err := envelope.NewEntry(unsigned.Header, unsigned.DomainPayload, []envelope.Signature{
		{SignerDID: "did:key:zSignerTest", AlgoID: envelope.SigAlgoECDSA, Bytes: sig},
	})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	signed, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return signed
}
