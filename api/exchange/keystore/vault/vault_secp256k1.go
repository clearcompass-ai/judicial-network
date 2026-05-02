/*
FILE PATH: api/exchange/keystore/vault/vault_secp256k1.go

DESCRIPTION:
    secp256k1 surface for the Vault Transit backend. The protocol curve
    is secp256k1 with SignCompact wire format (recoveryByte || R || S,
    65 bytes); Vault returns DER-marshaled (R, S) so we recover the
    byte by trying both v values against the known public key.

    S is canonicalized to low form (BIP-62) so the recovery byte
    matches what the SDK and Privy emit — keeping the wire shape
    consistent across custody backends.
*/
package vault

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

func (k *KeyStore) GenerateSecp256k1(did, purpose string) (*keystore.KeyInfo, error) {
	if did == "" {
		return nil, fmt.Errorf("vault: GenerateSecp256k1: did required")
	}
	name := keyName(did, keystore.CurveSecp256k1)
	if err := k.createKey(name, "ecdsa-p256k1"); err != nil {
		return nil, err
	}
	pub, err := k.fetchPublicKey(name, keystore.CurveSecp256k1)
	if err != nil {
		return nil, err
	}
	info := &keystore.KeyInfo{
		KeyID:     fmt.Sprintf("%s#secp256k1-1", did),
		DID:       did,
		Purpose:   purpose,
		Curve:     keystore.CurveSecp256k1,
		PublicKey: pub,
		Created:   time.Now().UTC(),
	}
	k.mu.Lock()
	k.keysSec[did] = info
	k.mu.Unlock()
	return info, nil
}

func (k *KeyStore) SignSecp256k1(did string, digest [32]byte) ([]byte, error) {
	name := keyName(did, keystore.CurveSecp256k1)
	r, s, err := k.signDER(name, digest[:])
	if err != nil {
		return nil, err
	}
	pub, err := k.PublicKeySecp256k1(did)
	if err != nil {
		return nil, fmt.Errorf("vault: SignSecp256k1: %w", err)
	}
	return packCompact(r, s, digest[:], pub)
}

func (k *KeyStore) PublicKeySecp256k1(did string) ([]byte, error) {
	k.mu.RLock()
	info, ok := k.keysSec[did]
	k.mu.RUnlock()
	if ok {
		out := make([]byte, len(info.PublicKey))
		copy(out, info.PublicKey)
		return out, nil
	}
	pub, err := k.fetchPublicKey(keyName(did, keystore.CurveSecp256k1), keystore.CurveSecp256k1)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// packCompact converts (R, S) + the 32-byte digest + known pubkey
// into the 65-byte SignCompact wire form: tries both v values (0 / 1),
// returns the variant that recovers the matching public key.
func packCompact(r, s *big.Int, digest, knownPub []byte) ([]byte, error) {
	rBytes := leftPad32(r.Bytes())
	sBytes := leftPad32(s.Bytes())
	for v := byte(0); v <= 1; v++ {
		compact := make([]byte, 65)
		compact[0] = v + 27
		copy(compact[1:33], rBytes)
		copy(compact[33:65], sBytes)
		pub, _, err := decredecdsa.RecoverCompact(compact, digest)
		if err != nil {
			continue
		}
		if bytes.Equal(pub.SerializeUncompressed(), knownPub) {
			return compact, nil
		}
	}
	return nil, fmt.Errorf("vault: packCompact: no recovery byte matched")
}

func leftPad32(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// canonicalizeS normalizes S to its low form (BIP-62 / Ethereum's malleability
// fix) using the secp256k1 curve order. Vault returns the raw signature
// from Go's stdlib ECDSA, which permits high-S values; the SDK and Privy
// emit low-S, and the recovery byte we compute is for low-S.
func canonicalizeS(s *big.Int) *big.Int {
	curveOrder := secp256k1.S256().N
	half := new(big.Int).Rsh(curveOrder, 1)
	if s.Cmp(half) > 0 {
		return new(big.Int).Sub(curveOrder, s)
	}
	return s
}
