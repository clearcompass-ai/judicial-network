/*
FILE PATH: topology/discovery.go
DESCRIPTION: Court DID → anchor chain resolution. Walks the anchor hierarchy

	to verify a court is a legitimate participant.

KEY ARCHITECTURAL DECISIONS:
  - Uses DIDResolver for court DID → DID Document → ledger endpoint.
  - Uses TreeHeadClient to fetch and cache tree heads along the chain.
  - Max chain depth 10 (state → county is typically depth 2).

OVERVIEW: DiscoverAnchorChain walks from court to state root.
KEY DEPENDENCIES: attesta/did, attesta/witness
*/
package topology

import (
	"context"
	"fmt"

	"github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/witness"
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

// DiscoverAnchorChain walks the anchor hierarchy from a court DID to
// the state root. Each step resolves the DID Document to find the
// ledger endpoint and parent anchor DID. ctx bounds the resolver RPCs.
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

	result := &AnchorChainResult{}
	current := courtDID
	visited := make(map[string]bool)

	for depth := 0; depth < maxAnchorChainDepth; depth++ {
		if visited[current] {
			break
		}
		visited[current] = true

		node, ok := hierarchy.ByDID[current]
		if !ok {
			break
		}

		chainNode := AnchorChainNode{
			LogDID: current,
			Depth:  depth,
		}

		// Resolve ledger URL from DID Document.
		if resolver != nil {
			doc, err := resolver.Resolve(ctx, current)
			if err == nil {
				url, urlErr := doc.LedgerEndpointURL()
				if urlErr == nil {
					chainNode.LedgerURL = url
				}
			}
		}

		// Fetch tree size from cached head.
		if client != nil {
			head, _, found := client.CachedHead(current)
			if found {
				chainNode.TreeSize = head.TreeSize
			}
		}

		result.Chain = append(result.Chain, chainNode)

		if node.AnchorDID == "" || node.AnchorDID == current {
			result.StateRootDID = current
			result.Valid = true
			break
		}
		current = node.AnchorDID
	}

	return result, nil
}
