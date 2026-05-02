/*
FILE PATH: api/exchange/keystore/vault/vault_ed25519_test.go

DESCRIPTION:
    Ed25519 round-trip tests for the Vault Transit keystore. Mock
    Vault server lives in vault_fakeserver_test.go.
*/
package vault

import (
	"crypto/ed25519"
	"testing"
)

func TestVault_Ed25519_RoundTrip(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	info, err := ks.Generate("did:web:test:operator", "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(info.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("PublicKey len = %d, want %d", len(info.PublicKey), ed25519.PublicKeySize)
	}
	msg := []byte("authentic")
	sig, err := ks.Sign("did:web:test:operator", msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(info.PublicKey, msg, sig) {
		t.Error("ed25519.Verify failed")
	}
}
