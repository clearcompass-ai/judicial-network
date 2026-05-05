/*
FILE PATH: exchange/keystore/keystore.go

DESCRIPTION:

	Key custody interface. The exchange holds private keys on behalf
	of signers. This interface abstracts the backing store — in-memory
	for tests, HSM for production, vault for cloud deployments.

	The keystore never exports private keys (except for the dedicated
	escrow path). It signs bytes and returns signatures. Same model
	as AWS KMS or PKCS#11.

	Two curves coexist: Ed25519 (legacy, used by some non-protocol
	paths) and secp256k1 (the protocol curve — every Attesta log
	entry's signature is over secp256k1). The secp256k1 methods
	(GenerateSecp256k1, SignSecp256k1, PublicKeySecp256k1) are the
	fix for the pre-existing mismatch where Sign returned Ed25519
	bytes but the entry asserted SigAlgoECDSA.

	Production path: callers route SIGN operations to whichever
	custody backend the deployment uses (Privy via IdentityProvider
	for user wallets; this keystore for system DIDs like the
	institutional/ledger key).

KEY DEPENDENCIES:
  - attesta/did: DID creation (guide §17)
  - attesta/crypto/escrow: SplitGF256, EncryptForNode (guide §15)
  - github.com/decred/dcrd/dcrec/secp256k1/v4 (curve operations,
    via keystore_secp256k1.go)
*/
package keystore

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Curve names recorded in KeyInfo.Curve. The Attesta protocol curve
// is secp256k1; Ed25519 is retained for non-protocol paths.
const (
	CurveEd25519   = "ed25519"
	CurveSecp256k1 = "secp256k1"
)

// KeyStore is the interface for key custody operations. Both curves
// (Ed25519 + secp256k1) are addressable per DID; a single DID may
// have keys on either or both curves.
type KeyStore interface {
	// Generate creates a new Ed25519 keypair, stores the private key,
	// returns the public key and a key ID.
	Generate(did string, purpose string) (*KeyInfo, error)

	// Sign signs bytes with the Ed25519 private key for the given DID.
	// Returns the 64-byte Ed25519 signature.
	Sign(did string, data []byte) ([]byte, error)

	// PublicKey returns the Ed25519 public key for a DID.
	PublicKey(did string) (ed25519.PublicKey, error)

	// GenerateSecp256k1 creates a new secp256k1 keypair, stores the
	// private key, returns KeyInfo (with Curve=CurveSecp256k1 and
	// PublicKey set to the 65-byte uncompressed key).
	GenerateSecp256k1(did string, purpose string) (*KeyInfo, error)

	// SignSecp256k1 signs a 32-byte digest with the secp256k1 key
	// for the given DID. Returns the 65-byte SignCompact output
	// (recoveryByte || R || S) — the wire format Privy returns and
	// the SDK accepts. Callers MUST pass the typed-data digest;
	// the keystore does NOT hash again.
	SignSecp256k1(did string, digest [32]byte) ([]byte, error)

	// PublicKeySecp256k1 returns the uncompressed (65-byte) secp256k1
	// public key for a DID. Returns an error if the DID has no
	// secp256k1 key.
	PublicKeySecp256k1(did string) ([]byte, error)

	// List returns all managed keys (both curves; KeyInfo.Curve
	// distinguishes).
	List() []*KeyInfo

	// Rotate marks a key as rotated and generates a replacement.
	Rotate(did string, tier int) (*KeyInfo, error)

	// Destroy permanently deletes a private key (for expungement).
	// Removes BOTH curves' keys for the DID if both exist.
	Destroy(did string) error

	// ExportForEscrow exports the raw Ed25519 private key bytes for
	// escrow splitting. Only callable during escrow operations.
	ExportForEscrow(did string) (ed25519.PrivateKey, error)
}

// KeyInfo describes a managed key without exposing the private
// material. Curve distinguishes Ed25519 (legacy paths) from
// secp256k1 (the Attesta protocol curve). PublicKey holds the raw
// public-key bytes for the named curve: 32 bytes for Ed25519, 65
// bytes (uncompressed, 0x04 prefix) for secp256k1.
type KeyInfo struct {
	KeyID        string     `json:"key_id"`
	DID          string     `json:"did"`
	Purpose      string     `json:"purpose"` // "signing" | "encryption" | "delegation"
	Curve        string     `json:"curve"`   // CurveEd25519 | CurveSecp256k1
	PublicKey    []byte     `json:"public_key"`
	Created      time.Time  `json:"created"`
	Rotated      *time.Time `json:"rotated,omitempty"`
	RotationTier int        `json:"rotation_tier,omitempty"`
}

// MemoryKeyStore is an in-memory implementation for development and
// tests. Holds Ed25519 and secp256k1 keys in parallel maps so the two
// curves can be addressed independently for the same DID.
type MemoryKeyStore struct {
	mu       sync.RWMutex
	keys     map[string]*managedKey
	keysSecp map[string]*managedSecpKey
}

type managedKey struct {
	info       *KeyInfo
	privateKey ed25519.PrivateKey
}

type managedSecpKey struct {
	info       *KeyInfo
	privateKey *secp256k1.PrivateKey
}

// NewMemoryKeyStore creates an in-memory key store.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{
		keys:     make(map[string]*managedKey),
		keysSecp: make(map[string]*managedSecpKey),
	}
}

func (m *MemoryKeyStore) Generate(did string, purpose string) (*KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("keystore: generate: %w", err)
	}

	info := &KeyInfo{
		KeyID:     fmt.Sprintf("%s#key-1", did),
		DID:       did,
		Purpose:   purpose,
		Curve:     CurveEd25519,
		PublicKey: pub,
		Created:   time.Now().UTC(),
	}

	m.keys[did] = &managedKey{info: info, privateKey: priv}
	return info, nil
}

func (m *MemoryKeyStore) Sign(did string, data []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mk, ok := m.keys[did]
	if !ok {
		return nil, fmt.Errorf("keystore: no key for %s", did)
	}

	return ed25519.Sign(mk.privateKey, data), nil
}

func (m *MemoryKeyStore) PublicKey(did string) (ed25519.PublicKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mk, ok := m.keys[did]
	if !ok {
		return nil, fmt.Errorf("keystore: no key for %s", did)
	}
	return ed25519.PublicKey(mk.info.PublicKey), nil
}

func (m *MemoryKeyStore) List() []*KeyInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*KeyInfo, 0, len(m.keys)+len(m.keysSecp))
	for _, mk := range m.keys {
		result = append(result, mk.info)
	}
	for _, mk := range m.keysSecp {
		result = append(result, mk.info)
	}
	return result
}

func (m *MemoryKeyStore) Rotate(did string, tier int) (*KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	old, ok := m.keys[did]
	if !ok {
		return nil, fmt.Errorf("keystore: no key for %s", did)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("keystore: rotate: %w", err)
	}

	now := time.Now().UTC()
	info := &KeyInfo{
		KeyID:        fmt.Sprintf("%s#key-%d", did, tier),
		DID:          did,
		Purpose:      old.info.Purpose,
		Curve:        CurveEd25519,
		PublicKey:    pub,
		Created:      now,
		Rotated:      &now,
		RotationTier: tier,
	}

	m.keys[did] = &managedKey{info: info, privateKey: priv}
	return info, nil
}

func (m *MemoryKeyStore) Destroy(did string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, hasEd := m.keys[did]
	_, hasSecp := m.keysSecp[did]
	if !hasEd && !hasSecp {
		return fmt.Errorf("keystore: no key for %s", did)
	}
	delete(m.keys, did)
	delete(m.keysSecp, did)
	return nil
}

func (m *MemoryKeyStore) ExportForEscrow(did string) (ed25519.PrivateKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mk, ok := m.keys[did]
	if !ok {
		return nil, fmt.Errorf("keystore: no key for %s", did)
	}
	// Return a copy to prevent mutation.
	cp := make(ed25519.PrivateKey, len(mk.privateKey))
	copy(cp, mk.privateKey)
	return cp, nil
}
