/*
FILE PATH: topology/anchor_publisher.go
DESCRIPTION: Wraps SDK BuildAnchorEntry + TreeHeadClient. Publishes periodic
    anchors from county log to state log.
KEY ARCHITECTURAL DECISIONS:
    - Uses builder.BuildAnchorEntry (commentary entry, zero SMT impact).
    - Fetches tree head via witness.TreeHeadClient.
    - Anchor entry payload: source_log_did, tree_head_ref, tree_size.
OVERVIEW: PublishAnchor fetches latest tree head and builds anchor entry.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/witness, ortholog-sdk/types
*/
package topology

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/witness"
)

// AnchorConfig configures an anchor publishing operation.
type AnchorConfig struct {
	Destination string // DID of target exchange. Required.
	SignerDID    string // Operator DID signing the anchor entry
	SourceLogDID string // Log being anchored (e.g., county cases log)
	EventTime    int64
}

// AnchorResult holds the output of anchor publishing.
type AnchorResult struct {
	Entry        *envelope.Entry
	TreeHeadRef  string
	TreeSize     uint64
}

// PublishAnchor fetches the latest cosigned tree head for the source log
// and builds an anchor commentary entry suitable for submission to the
// parent (state) log.
func PublishAnchor(
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

	head, _, err := client.FetchLatestTreeHead(cfg.SourceLogDID)
	if err != nil {
		return nil, fmt.Errorf("topology/anchor: fetch tree head: %w", err)
	}

	msg := types.WitnessCosignMessage(head.TreeHead)
	headHash := sha256.Sum256(msg[:])
	headRef := hex.EncodeToString(headHash[:])

	entry, err := builder.BuildAnchorEntry(builder.AnchorParams{
		Destination: cfg.Destination,
		SignerDID:    cfg.SignerDID,
		SourceLogDID: cfg.SourceLogDID,
		TreeHeadRef:  headRef,
		TreeSize:     head.TreeSize,
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
