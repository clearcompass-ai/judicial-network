/*
FILE PATH: parties/privacy.go
DESCRIPTION: Vendor-specific DID generation and mapping for sealed parties.
KEY ARCHITECTURAL DECISIONS:
    - Issue 1 fix: Uses did.NewWebDID (opaque) NOT did.GenerateDIDKey
      (embeds public key in DID string, decodable by anyone).
    - Vendor DIDs are did:web:<exchangeDomain>:holder:<uuid>.
    - Exchange resolves the DID via its HTTP endpoint, enforcing access control.
    - Local in-memory mapping table (Postgres-backed in production).
    - GenerateDIDKey remains correct for test fixtures and operator bootstrap.
OVERVIEW: GenerateVendorDID → opaque DID. ResolveVendorDID → real DID lookup.
KEY DEPENDENCIES: ortholog-sdk/did (NewWebDID only)
*/
package parties

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/did"
)

var ErrVendorDIDNotFound = errors.New("parties/privacy: vendor DID not found")

// VendorDIDStore maps vendor-specific DIDs to real DIDs.
// In-memory for SDK testing. Production: Postgres or KMS-backed.
type VendorDIDStore struct {
	mu    sync.RWMutex
	byVendor map[string]string // vendor DID → real DID
	byReal   map[string]string // real DID → vendor DID
}

// NewVendorDIDStore creates an empty in-memory store.
func NewVendorDIDStore() *VendorDIDStore {
	return &VendorDIDStore{
		byVendor: make(map[string]string),
		byReal:   make(map[string]string),
	}
}

// GenerateVendorDID creates an opaque vendor-specific DID for a sealed party.
// Uses did.NewWebDID with a random UUID path — the exchange controls resolution.
//
// Issue 1 fix: NOT did.GenerateDIDKey. GenerateDIDKey produces
// "did:key:f<hex_pubkey>" where anyone can decode the public key from
// the DID string. Sealed parties need opaque identifiers.
func GenerateVendorDID(exchangeDomain string, realDID string, store *VendorDIDStore) (string, error) {
	if exchangeDomain == "" {
		return "", fmt.Errorf("parties/privacy: empty exchange domain")
	}
	if realDID == "" {
		return "", fmt.Errorf("parties/privacy: empty real DID")
	}

	// Check if mapping already exists.
	store.mu.RLock()
	existing, ok := store.byReal[realDID]
	store.mu.RUnlock()
	if ok {
		return existing, nil
	}

	// Generate random UUID for the path.
	uuidBytes := make([]byte, 16)
	if _, err := rand.Read(uuidBytes); err != nil {
		return "", fmt.Errorf("parties/privacy: generate uuid: %w", err)
	}
	uuid := hex.EncodeToString(uuidBytes)

	// did:web:<exchangeDomain>:holder:<uuid>
	vendorDID := did.NewWebDID(exchangeDomain, "holder/"+uuid)

	// Store bidirectional mapping.
	store.mu.Lock()
	store.byVendor[vendorDID] = realDID
	store.byReal[realDID] = vendorDID
	store.mu.Unlock()

	return vendorDID, nil
}

// ResolveVendorDID looks up the real DID for a vendor-specific DID.
// Access control: caller must be authorized (scope authority officer).
func ResolveVendorDID(vendorDID string, store *VendorDIDStore) (string, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	realDID, ok := store.byVendor[vendorDID]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrVendorDIDNotFound, vendorDID)
	}
	return realDID, nil
}

// LookupVendorDID returns the vendor DID for a real DID.
func LookupVendorDID(realDID string, store *VendorDIDStore) (string, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	vendorDID, ok := store.byReal[realDID]
	if !ok {
		return "", fmt.Errorf("%w: no vendor DID for %s", ErrVendorDIDNotFound, realDID)
	}
	return vendorDID, nil
}

// MappingCount returns the number of stored mappings.
func (s *VendorDIDStore) MappingCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byVendor)
}
