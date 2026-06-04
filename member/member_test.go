package member

import (
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"

	"github.com/clearcompass-ai/judicial-network/topology"
)

// JurisdictionNode satisfies protocol.Node, and its domain fields ride along.
func TestJurisdictionNode_SatisfiesNode(t *testing.T) {
	root := topology.JurisdictionNode{DID: "did:web:tn", Level: topology.LevelState}
	county := topology.JurisdictionNode{
		DID: "did:web:tn:davidson", AnchorDID: "did:web:tn",
		Level: topology.LevelCounty, FIPSCode: "47037", Region: "Middle Tennessee",
	}

	if root.ID() != "did:web:tn" {
		t.Fatalf("ID = %q, want did:web:tn", root.ID())
	}
	if _, ok := root.Anchor(); ok {
		t.Fatal("state root must report no anchor (chain root)")
	}
	a, ok := county.Anchor()
	if !ok || a != "did:web:tn" {
		t.Fatalf("county Anchor = (%q,%v), want (did:web:tn,true)", a, ok)
	}
	// domain vocabulary preserved through the SDK-Node adoption
	if county.FIPSCode != "47037" || county.Level != topology.LevelCounty || county.Region != "Middle Tennessee" {
		t.Fatal("domain fields (FIPSCode/Level/Region) must be preserved")
	}
}

// TNCourtSystem is a usable, type-blind protocol.MemberNetwork handle.
func TestTNCourtSystem_MemberNetworkHandle(t *testing.T) {
	var id cosign.NetworkID
	id[0] = 0xAB
	s := New(id, "did:web:us:federal", nil, nil)

	if s.NetworkID() != id {
		t.Fatal("NetworkID must round-trip")
	}
	if s.Anchor() != "did:web:us:federal" {
		t.Fatalf("Anchor = %q, want did:web:us:federal", s.Anchor())
	}
	// Ledger is the injected Source (nil here until the live-ledger Source lands
	// in Slice 2 / baseproof#8); the handle stays valid regardless.
	if s.Ledger() != nil {
		t.Fatal("Ledger() must return exactly the injected Source")
	}
}
