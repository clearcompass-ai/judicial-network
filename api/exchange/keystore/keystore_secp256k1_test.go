/*
FILE PATH: exchange/keystore/keystore_secp256k1_test.go

DESCRIPTION:

	Contract tests for the secp256k1 surface of MemoryKeyStore.
	Pin the wire format (65-byte SignCompact, 65-byte uncompressed
	pubkey), the recoverability invariant (recovery from sig+digest
	yields the bound pubkey), and the keystore's interaction with
	Destroy/List across both curves.
*/
package keystore

import (
	"strings"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func nonZeroDigest32() [32]byte {
	var d [32]byte
	for i := range d {
		d[i] = byte(i + 1)
	}
	return d
}

// ─── GenerateSecp256k1 ──────────────────────────────────────────────

func TestMemoryKeyStore_GenerateSecp256k1_Basic(t *testing.T) {
	ks := NewMemoryKeyStore()
	info, err := ks.GenerateSecp256k1("did:key:zQ3shA", "signing")
	if err != nil {
		t.Fatalf("GenerateSecp256k1: %v", err)
	}
	if info.Curve != CurveSecp256k1 {
		t.Errorf("Curve = %q, want %q", info.Curve, CurveSecp256k1)
	}
	if len(info.PublicKey) != 65 {
		t.Errorf("PublicKey len = %d, want 65 (uncompressed)", len(info.PublicKey))
	}
	if info.PublicKey[0] != 0x04 {
		t.Errorf("PublicKey[0] = %#x, want 0x04 (uncompressed prefix)", info.PublicKey[0])
	}
	if info.DID != "did:key:zQ3shA" {
		t.Errorf("DID drift: %q", info.DID)
	}
	if info.Purpose != "signing" {
		t.Errorf("Purpose drift: %q", info.Purpose)
	}
	if !strings.Contains(info.KeyID, "secp256k1") {
		t.Errorf("KeyID should mark curve: %q", info.KeyID)
	}
}

func TestMemoryKeyStore_GenerateSecp256k1_RejectsEmptyDID(t *testing.T) {
	ks := NewMemoryKeyStore()
	if _, err := ks.GenerateSecp256k1("", "signing"); err == nil {
		t.Fatal("expected error on empty DID")
	}
}

// ─── ImportSecp256k1 ────────────────────────────────────────────────

func TestMemoryKeyStore_ImportSecp256k1(t *testing.T) {
	ks := NewMemoryKeyStore()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	info, err := ks.ImportSecp256k1("did:key:zQ3shIMP", "signing", priv)
	if err != nil {
		t.Fatalf("ImportSecp256k1: %v", err)
	}
	if string(info.PublicKey) != string(priv.PubKey().SerializeUncompressed()) {
		t.Error("imported pubkey does not match input key")
	}
}

func TestMemoryKeyStore_ImportSecp256k1_RejectsNil(t *testing.T) {
	ks := NewMemoryKeyStore()
	if _, err := ks.ImportSecp256k1("did:key:x", "signing", nil); err == nil {
		t.Fatal("expected error on nil key")
	}
}

// ─── SignSecp256k1 round-trip ───────────────────────────────────────

func TestMemoryKeyStore_SignSecp256k1_Recoverable(t *testing.T) {
	ks := NewMemoryKeyStore()
	info, err := ks.GenerateSecp256k1("did:key:zQ3shB", "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	digest := nonZeroDigest32()
	sig, err := ks.SignSecp256k1("did:key:zQ3shB", digest)
	if err != nil {
		t.Fatalf("SignSecp256k1: %v", err)
	}
	if len(sig) != 65 {
		t.Errorf("sig len = %d, want 65 (recoverByte || R || S)", len(sig))
	}

	// Recover the pubkey from the sig + digest. Must equal the
	// bound pubkey — proves the signature was produced by the
	// claimed key over the claimed digest.
	recovered, _, err := ecdsa.RecoverCompact(sig, digest[:])
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	gotPub := recovered.SerializeUncompressed()
	if string(gotPub) != string(info.PublicKey) {
		t.Error("recovered pubkey != bound pubkey (signature does not authenticate the digest)")
	}
}

func TestMemoryKeyStore_SignSecp256k1_UnknownDID(t *testing.T) {
	ks := NewMemoryKeyStore()
	_, err := ks.SignSecp256k1("did:key:zQ3shNONE", nonZeroDigest32())
	if err == nil || !strings.Contains(err.Error(), "no secp256k1 key") {
		t.Fatalf("expected unknown-key error, got: %v", err)
	}
}

func TestMemoryKeyStore_SignSecp256k1_Deterministic_GivenSameInputs(t *testing.T) {
	// dcrd's ecdsa.Sign uses RFC 6979 deterministic nonces, so
	// signing the same digest with the same key twice produces
	// byte-identical signatures. Pin the property — anything else
	// surprises auditors and breaks idempotent submission paths.
	ks := NewMemoryKeyStore()
	priv, _ := secp256k1.GeneratePrivateKey()
	if _, err := ks.ImportSecp256k1("did:key:zQ3shD", "signing", priv); err != nil {
		t.Fatalf("Import: %v", err)
	}
	digest := nonZeroDigest32()

	a, err := ks.SignSecp256k1("did:key:zQ3shD", digest)
	if err != nil {
		t.Fatalf("Sign a: %v", err)
	}
	b, err := ks.SignSecp256k1("did:key:zQ3shD", digest)
	if err != nil {
		t.Fatalf("Sign b: %v", err)
	}
	if string(a) != string(b) {
		t.Error("RFC 6979 deterministic sign should produce identical signatures")
	}
}

// ─── PublicKeySecp256k1 ─────────────────────────────────────────────

func TestMemoryKeyStore_PublicKeySecp256k1_HappyPath(t *testing.T) {
	ks := NewMemoryKeyStore()
	info, _ := ks.GenerateSecp256k1("did:key:zQ3shC", "signing")

	got, err := ks.PublicKeySecp256k1("did:key:zQ3shC")
	if err != nil {
		t.Fatalf("PublicKeySecp256k1: %v", err)
	}
	if string(got) != string(info.PublicKey) {
		t.Error("returned pubkey != generated pubkey")
	}

	// Mutating the returned slice must not affect the stored key.
	got[0] = 0xFF
	got2, _ := ks.PublicKeySecp256k1("did:key:zQ3shC")
	if got2[0] != 0x04 {
		t.Errorf("returned slice should be a fresh copy; stored key was mutated (got2[0]=%#x)", got2[0])
	}
}

func TestMemoryKeyStore_PublicKeySecp256k1_UnknownDID(t *testing.T) {
	ks := NewMemoryKeyStore()
	_, err := ks.PublicKeySecp256k1("did:key:zQ3shNONE")
	if err == nil || !strings.Contains(err.Error(), "no secp256k1 key") {
		t.Fatalf("expected unknown-key error, got: %v", err)
	}
}

// ─── Cross-curve interaction ────────────────────────────────────────

func TestMemoryKeyStore_BothCurvesForSameDID(t *testing.T) {
	ks := NewMemoryKeyStore()
	did := "did:key:zQ3shDUAL"

	// Provision both curves.
	if _, err := ks.Generate(did, "signing"); err != nil {
		t.Fatalf("Generate Ed25519: %v", err)
	}
	if _, err := ks.GenerateSecp256k1(did, "signing"); err != nil {
		t.Fatalf("Generate secp256k1: %v", err)
	}

	// Both Sign paths work independently.
	if _, err := ks.Sign(did, []byte("ed-data")); err != nil {
		t.Errorf("Ed25519 Sign: %v", err)
	}
	if _, err := ks.SignSecp256k1(did, nonZeroDigest32()); err != nil {
		t.Errorf("secp256k1 Sign: %v", err)
	}

	// List sees both keys.
	if got := len(ks.List()); got != 2 {
		t.Errorf("List len = %d, want 2 (one per curve)", got)
	}

	// Destroy nukes both.
	if err := ks.Destroy(did); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := ks.Sign(did, []byte("after destroy")); err == nil {
		t.Error("Ed25519 Sign should fail after Destroy")
	}
	if _, err := ks.SignSecp256k1(did, nonZeroDigest32()); err == nil {
		t.Error("secp256k1 Sign should fail after Destroy")
	}
}

// ─── Concurrency smoke test ─────────────────────────────────────────

func TestMemoryKeyStore_Secp256k1_ConcurrentSafe(t *testing.T) {
	ks := NewMemoryKeyStore()
	dids := []string{"did:key:zQ3shP", "did:key:zQ3shQ", "did:key:zQ3shR"}
	for _, d := range dids {
		ks.GenerateSecp256k1(d, "signing")
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			did := dids[idx%len(dids)]
			for j := 0; j < 50; j++ {
				_, _ = ks.SignSecp256k1(did, nonZeroDigest32())
				_, _ = ks.PublicKeySecp256k1(did)
			}
		}(i)
	}
	wg.Wait()
}
