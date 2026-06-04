package topology

import (
	"context"
	"testing"
)

func hier(nodes ...*JurisdictionNode) *Hierarchy {
	h := NewHierarchy()
	for _, n := range nodes {
		h.Add(n)
	}
	return h
}

func chainDIDs(r *AnchorChainResult) []string {
	out := make([]string, len(r.Chain))
	for i, n := range r.Chain {
		out[i] = n.LogDID
	}
	return out
}

func eqDIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Positive: county → state → federal-root resolves the full chain to a genuine
// state root (the common practical case), with depth = chain index.
func TestDiscoverAnchorChain_ReachesStateRoot(t *testing.T) {
	h := hier(
		&JurisdictionNode{DID: "did:county", AnchorDID: "did:state", Level: LevelCounty, FIPSCode: "47037"},
		&JurisdictionNode{DID: "did:state", AnchorDID: "did:federal", Level: LevelState},
		&JurisdictionNode{DID: "did:federal", AnchorDID: "", Level: LevelFederal}, // root
	)
	res, err := DiscoverAnchorChain(context.Background(), "did:county", h, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := chainDIDs(res); !eqDIDs(got, []string{"did:county", "did:state", "did:federal"}) {
		t.Fatalf("chain = %v, want [did:county did:state did:federal]", got)
	}
	if !res.Valid || res.StateRootDID != "did:federal" {
		t.Fatalf("Valid=%v StateRootDID=%q, want true / did:federal", res.Valid, res.StateRootDID)
	}
	if res.Chain[0].Depth != 0 || res.Chain[2].Depth != 2 {
		t.Fatalf("depths = %d,%d, want 0..2", res.Chain[0].Depth, res.Chain[2].Depth)
	}
}

// Positive: a self-anchoring node is its own state root.
func TestDiscoverAnchorChain_SelfAnchorRoot(t *testing.T) {
	h := hier(&JurisdictionNode{DID: "did:state", AnchorDID: "did:state", Level: LevelState})
	res, _ := DiscoverAnchorChain(context.Background(), "did:state", h, nil, nil)
	if !res.Valid || res.StateRootDID != "did:state" || len(res.Chain) != 1 {
		t.Fatalf("res = %+v, want [did:state] valid root", res)
	}
}

// Negative / regression: a cycle truncates the walk at the repeat and is NOT a
// valid root (would otherwise loop or mis-report a root).
func TestDiscoverAnchorChain_CycleNotValid(t *testing.T) {
	h := hier(
		&JurisdictionNode{DID: "did:a", AnchorDID: "did:b"},
		&JurisdictionNode{DID: "did:b", AnchorDID: "did:a"}, // cycle
	)
	res, _ := DiscoverAnchorChain(context.Background(), "did:a", h, nil, nil)
	if got := chainDIDs(res); !eqDIDs(got, []string{"did:a", "did:b"}) {
		t.Fatalf("chain = %v, want [did:a did:b]", got)
	}
	if res.Valid {
		t.Fatal("a cyclic anchor chain must NOT be Valid (no genuine root)")
	}
}

// Negative / regression: an anchor pointing outside the hierarchy stops the walk
// and is not a valid root (matches the prior !ok break).
func TestDiscoverAnchorChain_DanglingAnchorNotValid(t *testing.T) {
	h := hier(&JurisdictionNode{DID: "did:county", AnchorDID: "did:missing"})
	res, _ := DiscoverAnchorChain(context.Background(), "did:county", h, nil, nil)
	if len(res.Chain) != 1 || res.Chain[0].LogDID != "did:county" || res.Valid {
		t.Fatalf("res = %+v, want chain [did:county] not-valid", res)
	}
}

// Negative: an unknown starting court yields an empty chain, not valid.
func TestDiscoverAnchorChain_UnknownCourtEmpty(t *testing.T) {
	h := hier(&JurisdictionNode{DID: "did:state"})
	res, _ := DiscoverAnchorChain(context.Background(), "did:ghost", h, nil, nil)
	if len(res.Chain) != 0 || res.Valid {
		t.Fatalf("res = %+v, want empty not-valid", res)
	}
}

// Guard: a nil hierarchy is an error (unchanged from the prior implementation).
func TestDiscoverAnchorChain_NilHierarchy(t *testing.T) {
	if _, err := DiscoverAnchorChain(context.Background(), "did:x", nil, nil, nil); err == nil {
		t.Fatal("nil hierarchy must return an error")
	}
}
