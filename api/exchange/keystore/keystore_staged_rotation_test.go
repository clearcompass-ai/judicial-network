/*
FILE PATH: exchange/keystore/keystore_staged_rotation_test.go

Tests for the secp256k1 entry-signing + staged-rotation surface added for
the JN secp256k1 alignment (Phase 1, additive/dormant): SignEntry must
produce a 64-byte SigAlgoECDSA signature the SDK's VerifyEntry accepts, and
StageNextKey must keep the retiring key signable until CommitRotation
promotes the new one (the old-key-signs chain of custody).
*/
package keystore

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

func TestMemoryKeyStore_SignEntry_VerifiesUnderSDK(t *testing.T) {
	ks := NewMemoryKeyStore()
	const did = "did:web:clerk.example.gov"
	info, err := ks.GenerateSecp256k1(did, "signing")
	if err != nil {
		t.Fatalf("GenerateSecp256k1: %v", err)
	}

	digest := sha256.Sum256([]byte("canonical entry signing payload"))
	sig, err := ks.SignEntry(did, digest)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("SignEntry len = %d, want 64 (R||S SigAlgoECDSA)", len(sig))
	}

	pub, err := signatures.ParsePubKey(info.PublicKey)
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}
	if err := signatures.VerifyEntry(digest, sig, pub); err != nil {
		t.Fatalf("VerifyEntry rejected a SignEntry signature: %v", err)
	}
}

func TestMemoryKeyStore_StagedRotation_OldKeySignsUntilCommit(t *testing.T) {
	ks := NewMemoryKeyStore()
	const did = "did:web:publisher.example.gov"
	if _, err := ks.GenerateSecp256k1(did, "signing"); err != nil {
		t.Fatalf("GenerateSecp256k1: %v", err)
	}
	oldPub, _ := ks.PublicKeySecp256k1(did)

	staged, err := ks.StageNextKey(did, 1)
	if err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}
	if bytes.Equal(staged.PublicKey, oldPub) {
		t.Fatal("staged key must differ from the current key")
	}

	// Before commit: the OLD key is still active + signable (old-key-signs).
	cur, _ := ks.PublicKeySecp256k1(did)
	if !bytes.Equal(cur, oldPub) {
		t.Error("current key changed before CommitRotation")
	}
	digest := sha256.Sum256([]byte("rotation entry naming the new key"))
	sig, err := ks.SignEntry(did, digest)
	if err != nil {
		t.Fatalf("SignEntry (old key, pre-commit): %v", err)
	}
	oldPK, _ := signatures.ParsePubKey(oldPub)
	if err := signatures.VerifyEntry(digest, sig, oldPK); err != nil {
		t.Fatalf("pre-commit signature must verify under the OLD key: %v", err)
	}

	// After commit: the staged key is active.
	if _, err := ks.CommitRotation(did); err != nil {
		t.Fatalf("CommitRotation: %v", err)
	}
	cur2, _ := ks.PublicKeySecp256k1(did)
	if !bytes.Equal(cur2, staged.PublicKey) {
		t.Error("current key not promoted to the staged key after CommitRotation")
	}
	sig2, err := ks.SignEntry(did, digest)
	if err != nil {
		t.Fatalf("SignEntry (new key, post-commit): %v", err)
	}
	newPK, _ := signatures.ParsePubKey(staged.PublicKey)
	if err := signatures.VerifyEntry(digest, sig2, newPK); err != nil {
		t.Fatalf("post-commit signature must verify under the NEW key: %v", err)
	}
}

func TestMemoryKeyStore_CommitRotation_NoPending(t *testing.T) {
	ks := NewMemoryKeyStore()
	const did = "did:web:notary.example.gov"
	if _, err := ks.GenerateSecp256k1(did, "signing"); err != nil {
		t.Fatalf("GenerateSecp256k1: %v", err)
	}
	if _, err := ks.CommitRotation(did); err == nil {
		t.Fatal("CommitRotation with no pending rotation must error")
	}
}
