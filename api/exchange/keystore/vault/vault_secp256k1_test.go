/*
FILE PATH: api/exchange/keystore/vault/vault_secp256k1_test.go

DESCRIPTION:

	secp256k1 round-trip tests for the Vault Transit keystore. Mock
	Vault server lives in vault_fakeserver_test.go.
*/
package vault

import (
	"testing"

	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

func TestVault_Secp256k1_GenerateAndPubKey(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	info, err := ks.GenerateSecp256k1("did:web:test:judge", "signing")
	if err != nil {
		t.Fatalf("GenerateSecp256k1: %v", err)
	}
	if len(info.PublicKey) != 65 || info.PublicKey[0] != 0x04 {
		t.Errorf("PublicKey shape wrong: len=%d prefix=%x", len(info.PublicKey), info.PublicKey[0])
	}
	if info.Curve != keystore.CurveSecp256k1 {
		t.Errorf("Curve = %q, want secp256k1", info.Curve)
	}
}

func TestVault_Secp256k1_SignRoundTripsViaRecovery(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	info, err := ks.GenerateSecp256k1("did:web:test:judge", "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	sig, err := ks.SignSecp256k1("did:web:test:judge", digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("sig len = %d, want 65", len(sig))
	}
	pub, _, err := decredecdsa.RecoverCompact(sig, digest[:])
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if recovered := pub.SerializeUncompressed(); string(recovered) != string(info.PublicKey) {
		t.Errorf("recovered pubkey != stored pubkey")
	}
}

func TestVault_Secp256k1_GenerateRequiresDID(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	if _, err := ks.GenerateSecp256k1("", "signing"); err == nil {
		t.Error("expected error for empty DID")
	}
}
