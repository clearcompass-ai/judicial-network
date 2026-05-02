/*
FILE PATH: api/exchange/keystore/vault/vault_ed25519.go

DESCRIPTION:
    Ed25519 surface for the Vault Transit backend. Ed25519 is the
    legacy curve in the keystore.KeyStore contract; the protocol curve
    is secp256k1. Ed25519 paths remain wired so the operator's
    institutional bootstrap key (which historically uses Ed25519) keeps
    working while the protocol path moves to secp256k1.

    Vault Transit Ed25519 returns raw 64-byte signatures (no marshaling
    flag) and accepts the input as base64.
*/
package vault

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

func (k *KeyStore) Generate(did, purpose string) (*keystore.KeyInfo, error) {
	if did == "" {
		return nil, fmt.Errorf("vault: Generate: did required")
	}
	name := keyName(did, keystore.CurveEd25519)
	if err := k.createKey(name, "ed25519"); err != nil {
		return nil, err
	}
	pub, err := k.fetchPublicKey(name, keystore.CurveEd25519)
	if err != nil {
		return nil, err
	}
	info := &keystore.KeyInfo{
		KeyID:     fmt.Sprintf("%s#key-1", did),
		DID:       did,
		Purpose:   purpose,
		Curve:     keystore.CurveEd25519,
		PublicKey: pub,
		Created:   time.Now().UTC(),
	}
	k.mu.Lock()
	k.keysEd[did] = info
	k.mu.Unlock()
	return info, nil
}

func (k *KeyStore) Sign(did string, data []byte) ([]byte, error) {
	name := keyName(did, keystore.CurveEd25519)
	return k.signEd25519(name, data)
}

func (k *KeyStore) PublicKey(did string) (ed25519.PublicKey, error) {
	pub, err := k.fetchPublicKey(keyName(did, keystore.CurveEd25519), keystore.CurveEd25519)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(pub), nil
}
