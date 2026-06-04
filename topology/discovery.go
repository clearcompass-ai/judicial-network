/*
FILE PATH: topology/discovery.go
DESCRIPTION: Court DID → anchor chain resolution. Walks the anchor hierarchy

	to verify a court is a legitimate participant.

KEY ARCHITECTURAL DECISIONS:
  - The bounded pointer-follow (depth cap + cycle-guard) is the SDK's agnostic
    walk.WalkAnchorChain over protocol.Node; topology.JurisdictionNode satisfies
    Node (member package / baseproof#7). This file keeps ONLY the domain
    enrichment — DIDResolver for court DID → ledger endpoint, TreeHeadClient for
    the per-node cached tree size.
  - Max chain depth 10 (state → county is typically depth 2).

OVERVIEW: DiscoverAnchorChain walks court → state root via the SDK walker.
KEY DEPENDENCIES: baseproof/{did,witness,walk,protocol}
*/
package topology

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/protocol"
	"github.com/baseproof/baseproof/walk"
	"github.com/baseproof/baseproof/witness"
)

const maxAnchorChainDepth = 10

// AnchorChainNode represents one step in the anchor chain.
type AnchorChainNode struct {
	LogDID    string
	LedgerURL string
	TreeSize  uint64
	Depth     int
}

// AnchorChainResult holds the discovered anchor chain.
type AnchorChainResult struct {
	Chain        []AnchorChainNode
	StateRootDID string
	Valid        bool
}

// DiscoverAnchorChain walks the anchor hierarchy from a court DID to the state
// root and enriches each step with its ledger endpoint + cached tree size. The
// walk itself is delegated to the SDK's agnostic walk.WalkAnchorChain (bounded
// at maxAnchorChainDepth, cycle-detected); ctx bounds the resolver RPCs.
func DiscoverAnchorChain(
	ctx context.Context,
	courtDID string,
	hierarchy *Hierarchy,
	resolver did.DIDResolver,
	client *witness.TreeHeadClient,
) (*AnchorChainResult, error) {
	if hierarchy == nil {
		return nil, fmt.Errorf("topology/discovery: nil hierarchy")
	}

	// Delegate the bounded pointer-follow to the SDK walker. JurisdictionNode
	// satisfies protocol.Node; the hierarchy is the domain's node lookup.
	lookup := func(logDID string) (protocol.Node, bool) {
		n, ok := hierarchy.ByDID[logDID]
		if !ok {
			return nil, false
		}
		return n, true
	}
	chain := walk.WalkAnchorChain(courtDID, lookup, maxAnchorChainDepth)

	result := &AnchorChainResult{}
	for depth, node := range chain {
		logDID := node.ID()
		chainNode := AnchorChainNode{LogDID: logDID, Depth: depth}

		// Resolve ledger URL from the DID Document (domain enrichment).
		if resolver != nil {
			if doc, err := resolver.Resolve(ctx, logDID); err == nil {
				if url, urlErr := doc.LedgerEndpointURL(); urlErr == nil {
					chainNode.LedgerURL = url
				}
			}
		}
		// Tree size from the cached head (domain enrichment).
		if client != nil {
			if head, _, found := client.CachedHead(logDID); found {
				chainNode.TreeSize = head.TreeSize
			}
		}
		result.Chain = append(result.Chain, chainNode)
	}

	// The walk reached a genuine state root iff its last node self-anchors or has
	// no parent (walk.AnchorChainRoot) — preserving the prior Valid semantics
	// (AnchorDID == "" || AnchorDID == self).
	if root, ok := walk.AnchorChainRoot(chain); ok {
		result.StateRootDID = root.ID()
		result.Valid = true
	}
	return result, nil
}
