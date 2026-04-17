/*
FILE PATH: exchange/keystore/keystore.go

DESCRIPTION:
    Key custody interface. The exchange holds private keys on behalf
    of signers. This interface abstracts the backing store — in-memory
    for tests, HSM for production, vault for cloud deployments.

    The keystore never exports private keys. It signs bytes and
    returns signatures. Same model as AWS KMS or PKCS#11.

KEY DEPENDENCIES:
    - ortholog-sdk/did: DID creation (guide §17)
    - ortholog-sdk/crypto/escrow: SplitGF256, EncryptForNode (guide §15)
*/
package keystore

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"
)

// KeyStore is the interface for key custody operations.
type KeyStore interface {
	// Generate creates a new Ed25519 keypair, stores the private key,
	// returns the public key and a key ID.
	Generate(did string, purpose string) (*KeyInfo, error)

	// Sign signs bytes with the private key for the given DID.
	// Returns the Ed25519 signature.
	Sign(did string, data []byte) ([]byte, error)

	// PublicKey returns the public key for a DID.
	PublicKey(did string) (ed25519.PublicKey, error)

	// List returns all managed keys.
	List() []*KeyInfo

	// Rotate marks a key as rotated and generates a replacement.
	Rotate(did string, tier int) (*KeyInfo, error)

	// Destroy permanently deletes a private key (for expungement).
	Destroy(did string) error

	// Export exports the raw private key bytes for escrow splitting.
	// Only callable during escrow operations.
	ExportForEscrow(did string) (ed25519.PrivateKey, error)
}

// KeyInfo describes a managed key without exposing the private material.
type KeyInfo struct {
	KeyID      string           `json:"key_id"`
	DID        string           `json:"did"`
	Purpose    string           `json:"purpose"` // "signing" | "encryption" | "delegation"
	PublicKey  ed25519.PublicKey `json:"public_key"`
	Created    time.Time        `json:"created"`
	Rotated    *time.Time       `json:"rotated,omitempty"`
	RotationTier int            `json:"rotation_tier,omitempty"`
}

// MemoryKeyStore is an in-memory implementation for development and tests.
type MemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*managedKey
}

type managedKey struct {
	info       *KeyInfo
	privateKey ed25519.PrivateKey
}

// NewMemoryKeyStore creates an in-memory key store.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{
		keys: make(map[string]*managedKey),
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
	return mk.info.PublicKey, nil
}

func (m *MemoryKeyStore) List() []*KeyInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*KeyInfo, 0, len(m.keys))
	for _, mk := range m.keys {
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
		PublicKey:     pub,
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

	if _, ok := m.keys[did]; !ok {
		return fmt.Errorf("keystore: no key for %s", did)
	}
	delete(m.keys, did)
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
