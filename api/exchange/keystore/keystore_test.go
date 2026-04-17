package keystore

import (
	"testing"
)

func TestMemoryKeyStore_Generate(t *testing.T) {
	ks := NewMemoryKeyStore()
	info, err := ks.Generate("did:web:test:judge", "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if info.DID != "did:web:test:judge" {
		t.Errorf("DID = %q", info.DID)
	}
	if info.KeyID == "" {
		t.Error("KeyID must be set")
	}
	if len(info.PublicKey) == 0 {
		t.Error("PublicKey must be set")
	}
	if info.Purpose != "signing" {
		t.Errorf("Purpose = %q", info.Purpose)
	}
}

func TestMemoryKeyStore_Sign(t *testing.T) {
	ks := NewMemoryKeyStore()
	ks.Generate("did:web:test:judge", "signing")

	sig, err := ks.Sign("did:web:test:judge", []byte("test data"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Error("signature must not be empty")
	}
}

func TestMemoryKeyStore_Sign_UnknownDID(t *testing.T) {
	ks := NewMemoryKeyStore()
	_, err := ks.Sign("did:web:nonexistent", []byte("test"))
	if err == nil {
		t.Fatal("expected error for unknown DID")
	}
}

func TestMemoryKeyStore_PublicKey(t *testing.T) {
	ks := NewMemoryKeyStore()
	ks.Generate("did:web:test", "signing")

	pub, err := ks.PublicKey("did:web:test")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if len(pub) == 0 {
		t.Error("public key must not be empty")
	}
}

func TestMemoryKeyStore_PublicKey_UnknownDID(t *testing.T) {
	ks := NewMemoryKeyStore()
	_, err := ks.PublicKey("did:web:nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown DID")
	}
}

func TestMemoryKeyStore_Rotate(t *testing.T) {
	ks := NewMemoryKeyStore()
	orig, _ := ks.Generate("did:web:test", "signing")
	rotated, err := ks.Rotate("did:web:test", 1)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if string(rotated.PublicKey) == string(orig.PublicKey) {
		t.Error("rotated key should have different PublicKey")
	}
	// Sign should work after rotation.
	_, err = ks.Sign("did:web:test", []byte("after rotation"))
	if err != nil {
		t.Fatalf("sign after rotate: %v", err)
	}
}

func TestMemoryKeyStore_List(t *testing.T) {
	ks := NewMemoryKeyStore()
	ks.Generate("did:web:a", "signing")
	ks.Generate("did:web:b", "encryption")

	keys := ks.List()
	if len(keys) != 2 {
		t.Errorf("List = %d, want 2", len(keys))
	}
}

func TestMemoryKeyStore_Destroy(t *testing.T) {
	ks := NewMemoryKeyStore()
	ks.Generate("did:web:test", "signing")

	if err := ks.Destroy("did:web:test"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	// Sign should fail after destroy.
	_, err := ks.Sign("did:web:test", []byte("after destroy"))
	if err == nil {
		t.Fatal("sign after destroy should fail")
	}
}

func TestMemoryKeyStore_ExportForEscrow(t *testing.T) {
	ks := NewMemoryKeyStore()
	ks.Generate("did:web:test", "signing")

	priv, err := ks.ExportForEscrow("did:web:test")
	if err != nil {
		t.Fatalf("ExportForEscrow: %v", err)
	}
	if len(priv) == 0 {
		t.Error("exported key must not be empty")
	}
}

func TestMemoryKeyStore_ExportForEscrow_UnknownDID(t *testing.T) {
	ks := NewMemoryKeyStore()
	_, err := ks.ExportForEscrow("did:web:nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown DID")
	}
}

func TestMemoryKeyStore_ImplementsInterface(t *testing.T) {
	var _ KeyStore = (*MemoryKeyStore)(nil)
}
