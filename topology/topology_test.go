package topology

import (
	"testing"
)

// -------------------------------------------------------------------------
// 1) NewHierarchy
// -------------------------------------------------------------------------

func TestNewHierarchy_NotNil(t *testing.T) {
	h := NewHierarchy()
	if h == nil {
		t.Fatal("must not be nil")
	}
	if h.ByDID == nil || h.ByLevel == nil {
		t.Fatal("maps must be initialized")
	}
}

// -------------------------------------------------------------------------
// 2) Add sets Root when ParentDID is empty
// -------------------------------------------------------------------------

func TestHierarchy_Add_SetsRoot(t *testing.T) {
	h := NewHierarchy()
	state := &JurisdictionNode{DID: "did:web:courts.tn.gov", Name: "Tennessee", Level: LevelState}
	h.Add(state)
	if h.Root != state {
		t.Error("node with empty ParentDID should become Root")
	}
}

// -------------------------------------------------------------------------
// 3) Add indexes by DID and Level
// -------------------------------------------------------------------------

func TestHierarchy_Add_IndexesByDIDAndLevel(t *testing.T) {
	h := NewHierarchy()
	h.Add(&JurisdictionNode{DID: "did:web:tn", Level: LevelState})
	h.Add(&JurisdictionNode{DID: "did:web:davidson", Level: LevelCounty, ParentDID: "did:web:tn"})
	h.Add(&JurisdictionNode{DID: "did:web:shelby", Level: LevelCounty, ParentDID: "did:web:tn"})

	if len(h.ByDID) != 3 {
		t.Errorf("ByDID = %d, want 3", len(h.ByDID))
	}
	if len(h.ByLevel[LevelCounty]) != 2 {
		t.Errorf("counties = %d, want 2", len(h.ByLevel[LevelCounty]))
	}
}

// -------------------------------------------------------------------------
// 4) Parent: known child returns parent
// -------------------------------------------------------------------------

func TestHierarchy_Parent_Found(t *testing.T) {
	h := NewHierarchy()
	h.Add(&JurisdictionNode{DID: "did:web:tn", Name: "TN", Level: LevelState})
	h.Add(&JurisdictionNode{DID: "did:web:davidson", Name: "Davidson", Level: LevelCounty, ParentDID: "did:web:tn"})

	p := h.Parent("did:web:davidson")
	if p == nil || p.DID != "did:web:tn" {
		t.Errorf("Parent = %v", p)
	}
}

// -------------------------------------------------------------------------
// 5) Parent: unknown → nil
// -------------------------------------------------------------------------

func TestHierarchy_Parent_Unknown(t *testing.T) {
	h := NewHierarchy()
	if p := h.Parent("did:web:nonexistent"); p != nil {
		t.Errorf("unknown should be nil, got %v", p)
	}
}

// -------------------------------------------------------------------------
// 6) Parent: root has no parent
// -------------------------------------------------------------------------

func TestHierarchy_Parent_RootReturnsNil(t *testing.T) {
	h := NewHierarchy()
	h.Add(&JurisdictionNode{DID: "did:web:tn", Level: LevelState})
	if p := h.Parent("did:web:tn"); p != nil {
		t.Error("root should have nil parent")
	}
}

// -------------------------------------------------------------------------
// 7) AnchorChain follows AnchorDID (NOT ParentDID)
// -------------------------------------------------------------------------

func TestHierarchy_AnchorChain_FollowsAnchorDID(t *testing.T) {
	h := NewHierarchy()
	h.Add(&JurisdictionNode{DID: "did:web:federal", Name: "Federal"})
	h.Add(&JurisdictionNode{DID: "did:web:tn", Name: "TN", ParentDID: "did:web:federal", AnchorDID: "did:web:federal"})
	h.Add(&JurisdictionNode{DID: "did:web:davidson", Name: "Davidson", ParentDID: "did:web:tn", AnchorDID: "did:web:tn"})

	chain := h.AnchorChain("did:web:davidson")
	// Should be: [davidson, tn, federal]
	if len(chain) != 3 {
		t.Fatalf("chain = %v, want 3 entries", chain)
	}
	if chain[0] != "did:web:davidson" {
		t.Errorf("chain[0] = %q, want davidson", chain[0])
	}
	if chain[1] != "did:web:tn" {
		t.Errorf("chain[1] = %q, want tn", chain[1])
	}
	if chain[2] != "did:web:federal" {
		t.Errorf("chain[2] = %q, want federal", chain[2])
	}
}

// -------------------------------------------------------------------------
// 8) AnchorChain includes self
// -------------------------------------------------------------------------

func TestHierarchy_AnchorChain_IncludesSelf(t *testing.T) {
	h := NewHierarchy()
	h.Add(&JurisdictionNode{DID: "did:web:standalone", Name: "Standalone"})
	chain := h.AnchorChain("did:web:standalone")
	if len(chain) < 1 || chain[0] != "did:web:standalone" {
		t.Errorf("chain should start with self, got %v", chain)
	}
}

// -------------------------------------------------------------------------
// 9) AnchorChain: cycle detection
// -------------------------------------------------------------------------

func TestHierarchy_AnchorChain_CycleDetection(t *testing.T) {
	h := NewHierarchy()
	h.Add(&JurisdictionNode{DID: "did:web:a", AnchorDID: "did:web:b"})
	h.Add(&JurisdictionNode{DID: "did:web:b", AnchorDID: "did:web:a"})

	chain := h.AnchorChain("did:web:a")
	// Must terminate. visited map prevents infinite loop.
	if len(chain) > 3 {
		t.Errorf("cycle should be detected, got chain len %d", len(chain))
	}
}

// -------------------------------------------------------------------------
// 10) AnchorChain: no AnchorDID stops at self
// -------------------------------------------------------------------------

func TestHierarchy_AnchorChain_NoAnchor(t *testing.T) {
	h := NewHierarchy()
	h.Add(&JurisdictionNode{DID: "did:web:solo", Name: "Solo"})
	chain := h.AnchorChain("did:web:solo")
	if len(chain) != 1 {
		t.Errorf("no anchor should give [self], got %v", chain)
	}
}

// -------------------------------------------------------------------------
// 11) SpokeConfig: construction + AllLogDIDs
// -------------------------------------------------------------------------

func TestSpokeConfig_AllLogDIDs(t *testing.T) {
	cfg := NewSpokeConfig(
		"did:web:court",
		"did:web:court:officers",
		"did:web:court:cases",
		"did:web:court:parties",
	)
	dids := cfg.AllLogDIDs()

	didSet := map[string]bool{}
	for _, d := range dids {
		didSet[d] = true
	}
	for _, want := range []string{"did:web:court:officers", "did:web:court:cases", "did:web:court:parties"} {
		if !didSet[want] {
			t.Errorf("AllLogDIDs missing %q, got %v", want, dids)
		}
	}
}

// -------------------------------------------------------------------------
// 12) JurisdictionNode fields
// -------------------------------------------------------------------------

func TestJurisdictionNode_AllFields(t *testing.T) {
	n := JurisdictionNode{
		DID:       "did:web:courts.nashville.gov",
		Name:      "Davidson County",
		Level:     LevelCounty,
		ParentDID: "did:web:courts.tn.gov",
		AnchorDID: "did:web:courts.tn.gov:anchor",
		Region:    "Middle Tennessee",
		FIPSCode:  "47037",
	}
	if n.FIPSCode != "47037" {
		t.Errorf("FIPSCode = %q", n.FIPSCode)
	}
	if n.Region != "Middle Tennessee" {
		t.Errorf("Region = %q", n.Region)
	}
}

// -------------------------------------------------------------------------
// 13) JurisdictionLevel constants ordered
// -------------------------------------------------------------------------

func TestJurisdictionLevel_Ordering(t *testing.T) {
	if LevelFederal >= LevelState {
		t.Error("Federal should be < State")
	}
	if LevelState >= LevelCounty {
		t.Error("State should be < County")
	}
	if LevelCounty >= LevelMunicipal {
		t.Error("County should be < Municipal")
	}
}
