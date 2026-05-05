/*
FILE PATH: cases/artifact/del_key_store_memory.go

DESCRIPTION:

	In-memory DelegationKeyStore for development and tests. Maps
	artifact CID to ECIES-wrapped PRE delegation key bytes. Production
	deployments swap this for a database- or KMS-backed implementation
	via dependency injection — same interface, different backend.

	The store is goroutine-safe so the test harness and dev binary
	can hand a single instance to both publish and grant flows
	without locking concerns at the call site.
*/
package artifact

import (
	"fmt"
	"sync"

	"github.com/clearcompass-ai/attesta/storage"
)

// InMemoryDelegationKeyStore is the reference DelegationKeyStore for
// dev / test. Stores ECIES-wrapped PRE delegation keys keyed by the
// artifact CID's string form.
type InMemoryDelegationKeyStore struct {
	mu    sync.RWMutex
	store map[string][]byte
}

// NewInMemoryDelegationKeyStore creates an empty in-memory store.
func NewInMemoryDelegationKeyStore() *InMemoryDelegationKeyStore {
	return &InMemoryDelegationKeyStore{store: make(map[string][]byte)}
}

// Store records the wrapped key under the artifact CID. Replaces
// any existing entry — the SDK's PRE flow regenerates the
// delegation keypair per publish, so collisions are not possible
// in normal operation but the contract here is overwrite-safe.
func (s *InMemoryDelegationKeyStore) Store(cid storage.CID, wrapped []byte) error {
	if len(wrapped) == 0 {
		return fmt.Errorf("artifact: InMemoryDelegationKeyStore.Store: empty wrapped key")
	}
	cp := make([]byte, len(wrapped))
	copy(cp, wrapped)
	s.mu.Lock()
	s.store[cid.String()] = cp
	s.mu.Unlock()
	return nil
}

// Get returns a fresh copy of the wrapped key bytes for cid.
// Returns ErrDelKeyNotFound when no entry exists.
func (s *InMemoryDelegationKeyStore) Get(cid storage.CID) ([]byte, error) {
	s.mu.RLock()
	v, ok := s.store[cid.String()]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrDelKeyNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

// Delete removes the wrapped key for cid. Idempotent — deleting a
// missing key is a no-op + nil error so expungement flows can call
// it without first checking existence.
func (s *InMemoryDelegationKeyStore) Delete(cid storage.CID) error {
	s.mu.Lock()
	delete(s.store, cid.String())
	s.mu.Unlock()
	return nil
}

// ErrDelKeyNotFound is returned by Get when no wrapped key exists
// for the supplied CID. Stable sentinel for callers that distinguish
// "no key" from "store unavailable".
var ErrDelKeyNotFound = fmt.Errorf("artifact: delegation key not found")

// Compile-time check that InMemoryDelegationKeyStore implements
// the DelegationKeyStore interface defined in publish.go.
var _ DelegationKeyStore = (*InMemoryDelegationKeyStore)(nil)
