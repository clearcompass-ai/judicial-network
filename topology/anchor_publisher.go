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
	sdklog "github.com/clearcompass-ai/attesta/log"
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

// PublishAnchor fetches the source log's PUBLISHED, witness-cosigned horizon and
// builds a self-contained cosigned_tree_head_v1 anchor commentary entry suitable
// for submission to the parent (state) log. ctx bounds the resolve+fetch.
//
// The horizon — not the live /v1/tree/head — is anchored: it is the durable
// checkpoint whose K-of-N quorum is finalized, so the embedded head a consumer
// verifies offline always carries a full quorum. The live head can be ahead of
// the published checkpoint and carry fewer than K cosignatures, which would make
// the offline quorum check on the anchor fail.
func PublishAnchor(
	ctx context.Context,
	cfg AnchorConfig,
	cp *sdklog.ResolvingCheckpointClient,
	set *cosign.WitnessKeySet,
) (*AnchorResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("topology/anchor: empty signer DID")
	}
	if cfg.SourceLogDID == "" {
		return nil, fmt.Errorf("topology/anchor: empty source log DID")
	}
	if cp == nil {
		return nil, fmt.Errorf("topology/anchor: nil checkpoint client")
	}
	if set == nil {
		return nil, fmt.Errorf("topology/anchor: nil witness key set for %s", cfg.SourceLogDID)
	}

	head, err := cp.FetchVerifiedHorizon(ctx, cfg.SourceLogDID, set)
	if err != nil {
		return nil, fmt.Errorf("topology/anchor: fetch verified horizon for %s: %w", cfg.SourceLogDID, err)
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
