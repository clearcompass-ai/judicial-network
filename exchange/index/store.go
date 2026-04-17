/*
FILE PATH: exchange/index/store.go

DESCRIPTION:
    Local index mapping domain identifiers → log positions. Populated
    by the scanner reading the operator sequentially. Queried by the
    business API for docket lookup, party search, etc.

    This is the equivalent of crt.sh's database for CT — the log is
    append-only and position-addressed, the index provides search.

    In-memory for now. Production would back this with SQLite,
    Postgres, or BadgerDB for persistence across restarts.
*/
package index

import (
	"sync"
)

// LogIndex wraps an IndexStore with log-specific convenience methods.
type LogIndex struct {
	Store *IndexStore
}

// NewLogIndex creates a log index.
func NewLogIndex() *LogIndex {
	return &LogIndex{Store: NewIndexStore()}
}

// IndexStore is a thread-safe multi-map from string keys to log positions.
type IndexStore struct {
	mu sync.RWMutex

	// docket → positions (a docket has multiple entries: root + filings)
	dockets map[string]map[string][]uint64 // logID → docket → positions

	// DID → positions (all entries by a signer)
	dids map[string]map[string][]uint64 // logID → DID → positions

	// artifact CID → position
	cids map[string]map[string]uint64 // logID → CID → position

	// party name → positions
	parties map[string]map[string][]uint64 // logID → name → positions

	// entry type → positions
	types map[string]map[string][]uint64 // logID → type → positions

	// schema ref → positions
	schemas map[string]map[string][]uint64 // logID → schema → positions

	// last scanned position per log
	scanPos map[string]uint64
}

// NewIndexStore creates an empty index store.
func NewIndexStore() *IndexStore {
	return &IndexStore{
		dockets: make(map[string]map[string][]uint64),
		dids:    make(map[string]map[string][]uint64),
		cids:    make(map[string]map[string]uint64),
		parties: make(map[string]map[string][]uint64),
		types:   make(map[string]map[string][]uint64),
		schemas: make(map[string]map[string][]uint64),
		scanPos: make(map[string]uint64),
	}
}

func ensureSubmap[V any](m map[string]map[string]V, logID string) map[string]V {
	if _, ok := m[logID]; !ok {
		m[logID] = make(map[string]V)
	}
	return m[logID]
}

func (s *IndexStore) AddDocketMapping(logID, docket string, pos uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub := ensureSubmap(s.dockets, logID)
	sub[docket] = append(sub[docket], pos)
}

func (s *IndexStore) AddDIDMapping(logID, did string, pos uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub := ensureSubmap(s.dids, logID)
	sub[did] = append(sub[did], pos)
}

func (s *IndexStore) AddCIDMapping(logID, cid string, pos uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub := ensureSubmap(s.cids, logID)
	sub[cid] = pos
}

func (s *IndexStore) AddPartyMapping(logID, name string, pos uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub := ensureSubmap(s.parties, logID)
	sub[name] = append(sub[name], pos)
}

func (s *IndexStore) AddTypeMapping(logID, entryType string, pos uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub := ensureSubmap(s.types, logID)
	sub[entryType] = append(sub[entryType], pos)
}

func (s *IndexStore) AddSchemaMapping(logID, schema string, pos uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub := ensureSubmap(s.schemas, logID)
	sub[schema] = append(sub[schema], pos)
}

// Query methods.

func (s *IndexStore) LookupDocket(logID, docket string) []uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sub, ok := s.dockets[logID]; ok {
		return sub[docket]
	}
	return nil
}

func (s *IndexStore) LookupDID(logID, did string) []uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sub, ok := s.dids[logID]; ok {
		return sub[did]
	}
	return nil
}

func (s *IndexStore) LookupCID(logID, cid string) (uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sub, ok := s.cids[logID]; ok {
		pos, found := sub[cid]
		return pos, found
	}
	return 0, false
}

func (s *IndexStore) LookupParty(logID, name string) []uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sub, ok := s.parties[logID]; ok {
		return sub[name]
	}
	return nil
}

func (s *IndexStore) LastScannedPosition(logID string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scanPos[logID]
}

func (s *IndexStore) SetLastScannedPosition(logID string, pos uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanPos[logID] = pos
}
