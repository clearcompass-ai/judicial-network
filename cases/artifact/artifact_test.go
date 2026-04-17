package artifact

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/dustinxie/ecc"
)

// ─── Unit: EncryptArtifact → DecryptArtifact roundtrip ──────────────

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	plaintext := []byte("Motion to Dismiss — Case 2027-CR-4471, Davidson County Criminal Division")

	ciphertext, key, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		t.Fatalf("EncryptArtifact: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext equals plaintext — encryption did nothing")
	}

	recovered, err := artifact.DecryptArtifact(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptArtifact: %v", err)
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("decrypted content doesn't match original\n  got:  %q\n  want: %q", recovered, plaintext)
	}
}

// ─── Unit: Different plaintexts produce different keys ──────────────

func TestEncryptArtifact_UniqueKeys(t *testing.T) {
	_, key1, err := artifact.EncryptArtifact([]byte("document A"))
	if err != nil {
		t.Fatalf("encrypt A: %v", err)
	}

	_, key2, err := artifact.EncryptArtifact([]byte("document B"))
	if err != nil {
		t.Fatalf("encrypt B: %v", err)
	}

	if key1.Key == key2.Key {
		t.Error("two encryptions produced the same key — randomness failure")
	}
}

// ─── Unit: Wrong key fails decryption ───────────────────────────────

func TestDecrypt_WrongKey_Fails(t *testing.T) {
	plaintext := []byte("sealed evidence exhibit")

	ciphertext, _, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Encrypt something else to get a different key.
	_, wrongKey, err := artifact.EncryptArtifact([]byte("other document"))
	if err != nil {
		t.Fatalf("encrypt other: %v", err)
	}

	_, err = artifact.DecryptArtifact(ciphertext, wrongKey)
	if err == nil {
		t.Fatal("expected decryption failure with wrong key, got nil")
	}
}

// ─── Unit: CID computation is deterministic ─────────────────────────

func TestCID_Deterministic(t *testing.T) {
	data := []byte("court filing content — deterministic hash test")

	cid1 := storage.Compute(data)
	cid2 := storage.Compute(data)

	if !cid1.Equal(cid2) {
		t.Fatalf("CID not deterministic: %s vs %s", cid1, cid2)
	}
}

// ─── Unit: Different data produces different CIDs ───────────────────

func TestCID_DifferentData_DifferentCIDs(t *testing.T) {
	cid1 := storage.Compute([]byte("document version 1"))
	cid2 := storage.Compute([]byte("document version 2"))

	if cid1.Equal(cid2) {
		t.Fatal("different data produced the same CID")
	}
}

// ─── Unit: CID verifies its own data ────────────────────────────────

func TestCID_Verify(t *testing.T) {
	data := []byte("evidence exhibit — tamper detection test")
	cid := storage.Compute(data)

	if !cid.Verify(data) {
		t.Fatal("CID failed to verify its own data")
	}

	tampered := append([]byte{}, data...)
	tampered[0] ^= 0xFF
	if cid.Verify(tampered) {
		t.Fatal("CID verified tampered data — hash collision or bug")
	}
}

// ─── Unit: CID string roundtrip ─────────────────────────────────────

func TestCID_StringRoundtrip(t *testing.T) {
	data := []byte("CID serialization test")
	cid := storage.Compute(data)

	s := cid.String()
	if s == "" {
		t.Fatal("CID.String() returned empty")
	}

	parsed, err := storage.ParseCID(s)
	if err != nil {
		t.Fatalf("ParseCID: %v", err)
	}

	if !parsed.Equal(cid) {
		t.Fatalf("CID roundtrip failed: %s → %s", cid, parsed)
	}
}

// ─── Unit: Delegation key generation + unwrap roundtrip ─────────────

func TestDelegationKey_GenerateUnwrap_Roundtrip(t *testing.T) {
	// Generate an owner keypair (simulates the exchange's master key).
	ownerPriv, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
	if err != nil {
		t.Fatalf("generate owner key: %v", err)
	}

	// 65-byte uncompressed public key.
	ownerPub := make([]byte, 65)
	ownerPub[0] = 0x04
	ownerPub = append(ownerPub[:1], append(ownerPriv.PublicKey.X.Bytes(), ownerPriv.PublicKey.Y.Bytes()...)...)
	// Pad to exactly 65 bytes.
	if len(ownerPub) < 65 {
		padded := make([]byte, 65)
		padded[0] = 0x04
		xBytes := ownerPriv.PublicKey.X.Bytes()
		yBytes := ownerPriv.PublicKey.Y.Bytes()
		copy(padded[1+32-len(xBytes):33], xBytes)
		copy(padded[33+32-len(yBytes):65], yBytes)
		ownerPub = padded
	}

	// Generate delegation key.
	pkDel, wrappedSkDel, err := lifecycle.GenerateDelegationKey(ownerPub)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}

	if len(pkDel) != 65 {
		t.Fatalf("pkDel length = %d, want 65", len(pkDel))
	}
	if pkDel[0] != 0x04 {
		t.Error("pkDel should start with 0x04 (uncompressed)")
	}
	if len(wrappedSkDel) == 0 {
		t.Fatal("wrappedSkDel is empty")
	}

	// Unwrap using owner's private key.
	ownerSecretKey := make([]byte, 32)
	ownerPrivBytes := ownerPriv.D.Bytes()
	copy(ownerSecretKey[32-len(ownerPrivBytes):], ownerPrivBytes)

	skDel, err := lifecycle.UnwrapDelegationKey(wrappedSkDel, ownerSecretKey)
	if err != nil {
		t.Fatalf("UnwrapDelegationKey: %v", err)
	}

	if len(skDel) != 32 {
		t.Fatalf("unwrapped skDel length = %d, want 32", len(skDel))
	}

	// Verify pkDel and skDel are a matching keypair.
	c := ecc.P256k1()
	x, y := c.ScalarBaseMult(skDel)
	derivedPub := make([]byte, 65)
	derivedPub[0] = 0x04
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(derivedPub[1+32-len(xBytes):33], xBytes)
	copy(derivedPub[33+32-len(yBytes):65], yBytes)

	if !bytes.Equal(derivedPub, pkDel) {
		t.Error("unwrapped skDel does not match pkDel — keypair mismatch")
	}
}

// ─── Unit: ReEncryptArtifact produces new key, same content ─────────

func TestReEncryptArtifact(t *testing.T) {
	plaintext := []byte("re-encryption test — custody transfer scenario")

	ct1, key1, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}

	ct2, key2, err := artifact.ReEncryptArtifact(ct1, key1)
	if err != nil {
		t.Fatalf("ReEncryptArtifact: %v", err)
	}

	// New key should differ.
	if key1.Key == key2.Key {
		t.Error("re-encryption produced the same key")
	}

	// New ciphertext should differ.
	if bytes.Equal(ct1, ct2) {
		t.Error("re-encryption produced the same ciphertext")
	}

	// Decrypt with new key should yield original plaintext.
	recovered, err := artifact.DecryptArtifact(ct2, key2)
	if err != nil {
		t.Fatalf("decrypt re-encrypted: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Error("re-encrypted content doesn't match original")
	}

	// Old key should NOT decrypt new ciphertext.
	_, err = artifact.DecryptArtifact(ct2, key1)
	if err == nil {
		t.Error("old key should not decrypt re-encrypted ciphertext")
	}
}
