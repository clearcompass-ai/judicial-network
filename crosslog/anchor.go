/*
FILE PATH: crosslog/anchor.go

DESCRIPTION:

	Consumer for the ledger's self-contained cross-log anchor
	(anchor/publisher.go, anchor_type="cosigned_tree_head_v1"). The anchor
	embeds the FULL source-log cosigned tree head — all four roots + the
	K-of-N witness cosignatures — as a gossip.WireCosignedTreeHeadBody, so a
	consumer reconstructs it via findings.CosignedTreeHeadFromWire and
	verifies the quorum OFFLINE (no callback to the source log, which may by
	then be offline / equivocating).

	This is distinct from topology.ExtractAnchorPayload, which reads the SDK
	builder's "tree_head_ref" anchor (a precomputed TreeHeadDigest) for
	VerifyCrossLogProof. cosigned_tree_head_v1 is the LEDGER's peer-anchor
	format; this is where the JN cross-log reconciler ingests it.
*/
package crosslog

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
)

// CosignedAnchorType is the ledger anchor discriminator for the
// self-contained cosigned-tree-head anchor.
const CosignedAnchorType = "cosigned_tree_head_v1"

var (
	// ErrNotCosignedAnchor is returned when a payload does not declare the
	// cosigned_tree_head_v1 anchor kind.
	ErrNotCosignedAnchor = errors.New("crosslog: not a cosigned_tree_head_v1 anchor")

	// ErrAnchorQuorumFailed is returned when the embedded cosigned head's
	// K-of-N witness quorum does not verify against the source witness set.
	ErrAnchorQuorumFailed = errors.New("crosslog: anchor cosignature quorum not met")
)

// cosignedAnchorPayload mirrors the ledger publisher's payload shape:
// {anchor_type, source_log_did, head: WireCosignedTreeHeadBody, tree_head_ref}.
type cosignedAnchorPayload struct {
	AnchorType   string                          `json:"anchor_type"`
	SourceLogDID string                          `json:"source_log_did"`
	Head         gossip.WireCosignedTreeHeadBody `json:"head"`
	TreeHeadRef  string                          `json:"tree_head_ref"`
}

// VerifiedAnchor is the result of consuming + verifying a cosigned anchor.
type VerifiedAnchor struct {
	// SourceLogDID is the peer log the anchor commits to.
	SourceLogDID string
	// Head is the source log's tree head whose K-of-N quorum verified —
	// its RootHash / TreeSize are the trusted reference a foreign inclusion
	// proof is checked against.
	Head types.CosignedTreeHead
}

// IsCosignedAnchor reports whether payload declares the ledger's
// cosigned_tree_head_v1 anchor kind — a cheap probe so a reconciler can
// route mixed log entries without a full decode.
func IsCosignedAnchor(payload []byte) bool {
	var probe struct {
		AnchorType string `json:"anchor_type"`
	}
	return json.Unmarshal(payload, &probe) == nil && probe.AnchorType == CosignedAnchorType
}

// VerifyCosignedAnchor parses a ledger cosigned_tree_head_v1 anchor payload,
// reconstructs the embedded source-log cosigned head, and verifies its
// K-of-N witness quorum OFFLINE against sourceSet (the source log's witness
// keyset, from Dependencies.WitnessSets). On success it returns the verified
// head + source log DID; a quorum failure returns ErrAnchorQuorumFailed.
func VerifyCosignedAnchor(payload []byte, sourceSet *cosign.WitnessKeySet) (VerifiedAnchor, error) {
	if sourceSet == nil {
		return VerifiedAnchor{}, fmt.Errorf("crosslog: nil source witness set")
	}
	var p cosignedAnchorPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return VerifiedAnchor{}, fmt.Errorf("crosslog: unmarshal anchor: %w", err)
	}
	if p.AnchorType != CosignedAnchorType {
		return VerifiedAnchor{}, fmt.Errorf("%w: anchor_type=%q", ErrNotCosignedAnchor, p.AnchorType)
	}
	finding, err := findings.CosignedTreeHeadFromWire(p.Head)
	if err != nil {
		return VerifiedAnchor{}, fmt.Errorf("crosslog: reconstruct cosigned head: %w", err)
	}
	if err := finding.Verify(sourceSet); err != nil {
		return VerifiedAnchor{}, fmt.Errorf("%w: %v", ErrAnchorQuorumFailed, err)
	}
	return VerifiedAnchor{SourceLogDID: p.SourceLogDID, Head: finding.Head}, nil
}
