package index

import (
	"testing"
)

// -------------------------------------------------------------------------
// 1) DID mapping
// -------------------------------------------------------------------------

func TestIndexStore_AddDIDMapping(t *testing.T) {
	s := NewIndexStore()
	s.AddDIDMapping("log1", "did:web:judge", 42)
	positions := s.LookupDID("log1", "did:web:judge")
	if len(positions) != 1 || positions[0] != 42 {
		t.Errorf("LookupDID = %v, want [42]", positions)
	}
}

func TestIndexStore_DID_MultiplePositions(t *testing.T) {
	s := NewIndexStore()
	s.AddDIDMapping("log1", "did:web:judge", 10)
	s.AddDIDMapping("log1", "did:web:judge", 20)
	positions := s.LookupDID("log1", "did:web:judge")
	if len(positions) != 2 {
		t.Errorf("LookupDID = %d, want 2", len(positions))
	}
}

// -------------------------------------------------------------------------
// 2) Docket mapping
// -------------------------------------------------------------------------

func TestIndexStore_AddDocketMapping(t *testing.T) {
	s := NewIndexStore()
	s.AddDocketMapping("log1", "2027-CR-001", 100)
	positions := s.LookupDocket("log1", "2027-CR-001")
	if len(positions) != 1 || positions[0] != 100 {
		t.Errorf("LookupDocket = %v, want [100]", positions)
	}
}

// -------------------------------------------------------------------------
// 3) CID mapping (returns uint64, bool)
// -------------------------------------------------------------------------

func TestIndexStore_AddCIDMapping(t *testing.T) {
	s := NewIndexStore()
	s.AddCIDMapping("log1", "sha256:abc", 200)
	pos, ok := s.LookupCID("log1", "sha256:abc")
	if !ok {
		t.Fatal("CID should be found")
	}
	if pos != 200 {
		t.Errorf("LookupCID = %d, want 200", pos)
	}
}

func TestIndexStore_LookupCID_NotFound(t *testing.T) {
	s := NewIndexStore()
	_, ok := s.LookupCID("log1", "nonexistent")
	if ok {
		t.Error("unknown CID should return false")
	}
}

// -------------------------------------------------------------------------
// 4) Schema mapping
// -------------------------------------------------------------------------

func TestIndexStore_AddSchemaMapping(t *testing.T) {
	s := NewIndexStore()
	s.AddSchemaMapping("log1", "tn-criminal-v1", 5)
	// Schema uses AddSchemaMapping; lookup would follow same pattern.
	// Just verify no panic on add.
}

// -------------------------------------------------------------------------
// 5) Party mapping
// -------------------------------------------------------------------------

func TestIndexStore_AddPartyMapping(t *testing.T) {
	s := NewIndexStore()
	s.AddPartyMapping("log1", "John Doe", 300)
	positions := s.LookupParty("log1", "John Doe")
	if len(positions) != 1 || positions[0] != 300 {
		t.Errorf("LookupParty = %v, want [300]", positions)
	}
}

// -------------------------------------------------------------------------
// 6) Type mapping
// -------------------------------------------------------------------------

func TestIndexStore_AddTypeMapping(t *testing.T) {
	s := NewIndexStore()
	s.AddTypeMapping("log1", "delegation", 10)
	s.AddTypeMapping("log1", "delegation", 20)
	// No panic on add.
}

// -------------------------------------------------------------------------
// 7) Unknown lookups return empty
// -------------------------------------------------------------------------

func TestIndexStore_LookupUnknown_Empty(t *testing.T) {
	s := NewIndexStore()
	if pos := s.LookupDID("log1", "nonexistent"); len(pos) != 0 {
		t.Errorf("unknown DID = %v", pos)
	}
	if pos := s.LookupDocket("log1", "nonexistent"); len(pos) != 0 {
		t.Errorf("unknown docket = %v", pos)
	}
	if pos := s.LookupParty("log1", "nonexistent"); len(pos) != 0 {
		t.Errorf("unknown party = %v", pos)
	}
}

// -------------------------------------------------------------------------
// 8) Scan position watermark
// -------------------------------------------------------------------------

func TestIndexStore_ScanPosition(t *testing.T) {
	s := NewIndexStore()
	if pos := s.LastScannedPosition("log1"); pos != 0 {
		t.Errorf("initial = %d, want 0", pos)
	}
	s.SetLastScannedPosition("log1", 500)
	if pos := s.LastScannedPosition("log1"); pos != 500 {
		t.Errorf("after set = %d, want 500", pos)
	}
}

// -------------------------------------------------------------------------
// 9) Cross-log isolation
// -------------------------------------------------------------------------

func TestIndexStore_CrossLogIsolation(t *testing.T) {
	s := NewIndexStore()
	s.AddDIDMapping("log1", "did:web:judge", 10)
	s.AddDIDMapping("log2", "did:web:judge", 20)

	l1 := s.LookupDID("log1", "did:web:judge")
	l2 := s.LookupDID("log2", "did:web:judge")

	if len(l1) != 1 || l1[0] != 10 {
		t.Errorf("log1 = %v", l1)
	}
	if len(l2) != 1 || l2[0] != 20 {
		t.Errorf("log2 = %v", l2)
	}
}

// -------------------------------------------------------------------------
// 10) LogIndex construction
// -------------------------------------------------------------------------

func TestNewLogIndex_NotNil(t *testing.T) {
	idx := NewLogIndex()
	if idx == nil {
		t.Fatal("NewLogIndex must not return nil")
	}
}
