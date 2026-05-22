/*
FILE PATH: topology/anchor_publisher.go
DESCRIPTION: Publishes periodic county→state anchors as self-contained

	cosigned_tree_head_v1 entries via the SDK's single anchor owner
	(attesta/anchor). The embedded head carries the source log's full
	K-of-N cosignatures, so a consumer verifies the quorum OFFLINE — no
	callback to the source log, which may by then be offline or equivocating.

KEY ARCHITECTURAL DECISIONS:
  - Uses anchor.BuildCosignedAnchorEntry (commentary entry, zero SMT impact) —
    the SAME format as cross-exchange peer anchors. There is exactly one
    anchor type across the network (constitution P1/P2: the SDK owns it).
  - Fetches the source log's cosigned tree head via witness.TreeHeadClient.
  - tree_head_ref (network-bound cosign.TreeHeadDigest) is retained as the
    provenance/audit value and surfaced in AnchorResult; it equals the digest
    the SDK embeds in the anchor.

OVERVIEW: PublishAnchor fetches latest tree head and builds a self-contained
anchor entry.
KEY DEPENDENCIES: attesta/anchor, attesta/witness, attesta/crypto/cosign
*/
package topology

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/clearcompass-ai/attesta/anchor"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/witness"
)

// AnchorConfig configures an anchor publishing operation.
type AnchorConfig struct {
	Destination  string // DID of target exchange. Required.
	SignerDID    string // Ledger DID signing the anchor entry
	SourceLogDID string // Log being anchored (e.g., county cases log)
	EventTime    int64
	NetworkID    cosign.NetworkID // network-binding for the tree-head digest
}

// AnchorResult holds the output of anchor publishing.
type AnchorResult struct {
	Entry       *envelope.Entry
	TreeHeadRef string
	TreeSize    uint64
}

// PublishAnchor fetches the latest cosigned tree head for the source log
// and builds a self-contained cosigned_tree_head_v1 anchor commentary entry
// suitable for submission to the parent (state) log. ctx bounds the
// FetchLatestTreeHead RPC.
func PublishAnchor(
	ctx context.Context,
	cfg AnchorConfig,
	client *witness.TreeHeadClient,
) (*AnchorResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("topology/anchor: empty signer DID")
	}
	if cfg.SourceLogDID == "" {
		return nil, fmt.Errorf("topology/anchor: empty source log DID")
	}
	if client == nil {
		return nil, fmt.Errorf("topology/anchor: nil tree head client")
	}

	head, _, err := client.FetchLatestTreeHead(ctx, cfg.SourceLogDID)
	if err != nil {
		return nil, fmt.Errorf("topology/anchor: fetch tree head: %w", err)
	}

	headHash, err := cosign.TreeHeadDigest(head.TreeHead, cfg.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("topology/anchor: tree head digest: %w", err)
	}
	headRef := hex.EncodeToString(headHash[:])

	entry, err := anchor.BuildCosignedAnchorEntry(anchor.CosignedAnchorParams{
		Destination:  cfg.Destination,
		SignerDID:    cfg.SignerDID,
		SourceLogDID: cfg.SourceLogDID,
		Head:         head,
		NetworkID:    cfg.NetworkID,
		EventTime:    cfg.EventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("topology/anchor: build entry: %w", err)
	}

	return &AnchorResult{
		Entry:       entry,
		TreeHeadRef: headRef,
		TreeSize:    head.TreeSize,
	}, nil
}
