// Package member provides judicial-network's concrete SDK protocol handles —
// the type-blind network handle the SDK federation recursion walks over, plus
// the compile-time proof that JN's domain types satisfy the agnostic interfaces.
//
// This is the consumer side of baseproof/baseproof#7 (Slice 1): JN stops owning
// the agnostic vocabulary and instead *implements* it. The domain data
// (topology.JurisdictionNode with Level/FIPSCode/Region) is untouched; it rides
// along while satisfying protocol.Node.
package member

import (
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/protocol"

	"github.com/clearcompass-ai/judicial-network/topology"
)

// JurisdictionNode satisfies the SDK's bounded pointer-follow handle. The
// assertion lives here so the topology package stays free of SDK imports.
var _ protocol.Node = topology.JurisdictionNode{}

// TNCourtSystem is the Tennessee court-system network expressed as an SDK
// protocol.MemberNetwork — a type-blind handle exposing only the protocol
// primitives (NetworkID, the Source-backed ledger, the anchor DID, the witness
// set). It never reveals that it is a *judicial* network, so the SDK federation
// recursion walks it identically to any other network type.
//
// Ledger() is injected as a protocol.Source: the live-ledger Source
// implementation lands with the walker family in Slice 2 (baseproof#8); a caller
// may inject the offline embedded-proof-chain Source instead, unchanged.
type TNCourtSystem struct {
	id        cosign.NetworkID
	anchorDID string
	witnesses *cosign.WitnessKeySet
	ledger    protocol.Source
}

// New builds the court-system handle. anchorDID is "" when this network is a
// federation root.
func New(id cosign.NetworkID, anchorDID string, witnesses *cosign.WitnessKeySet, ledger protocol.Source) *TNCourtSystem {
	return &TNCourtSystem{id: id, anchorDID: anchorDID, witnesses: witnesses, ledger: ledger}
}

// NetworkID is the network's 32-byte identifier (federation keys on it).
func (s *TNCourtSystem) NetworkID() cosign.NetworkID { return s.id }

// Ledger is the network's log, read through the agnostic Source seam.
func (s *TNCourtSystem) Ledger() protocol.Source { return s.ledger }

// Anchor is the DID this network anchors to (its federation parent), or "" at a
// federation root.
func (s *TNCourtSystem) Anchor() string { return s.anchorDID }

// Witnesses is the network's K-of-N witness set; cross-log verification of an
// element sourced from this network binds to it.
func (s *TNCourtSystem) Witnesses() *cosign.WitnessKeySet { return s.witnesses }

var _ protocol.MemberNetwork = (*TNCourtSystem)(nil)
