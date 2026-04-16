/*
FILE PATH: onboarding/anchor_registration.go
DESCRIPTION: Publishes the first anchor entry from a newly-provisioned county
    log to its parent (state) log. The state operator watches for this anchor
    to admit the county into the network.
KEY ARCHITECTURAL DECISIONS:
    - Uses builder.BuildAnchorEntry (commentary, zero SMT impact).
    - Fetches the county log's initial cosigned tree head via TreeHeadClient
      (the head that includes the provisioning entries — scope entity,
      delegations, schemas).
    - Returns the anchor entry for submission to the state log by the caller.
OVERVIEW: RegisterFirstAnchor wraps topology/anchor_publisher for onboarding.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/witness
*/
package onboarding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/witness"
)

// AnchorRegistrationConfig configures the initial anchor publication.
type AnchorRegistrationConfig struct {
	// CountyOperatorDID signs the anchor entry.
	CountyOperatorDID string

	// CountyLogDID is the newly-provisioned county log being anchored.
	CountyLogDID string

	// ParentLogDID is the state log receiving the anchor.
	ParentLogDID string

	// EventTime overrides the anchor timestamp. Zero → time.Now().
	EventTime int64
}

// AnchorRegistrationResult holds the anchor entry + metadata.
type AnchorRegistrationResult struct {
	AnchorEntry *envelope.Entry
	TreeHeadRef string
	TreeSize    uint64

	// TargetLogDID is where the caller must submit AnchorEntry.
	// Equals cfg.ParentLogDID for clarity.
	TargetLogDID string
}

// RegisterFirstAnchor fetches the county log's initial tree head and
// builds an anchor entry for submission to the state log.
//
// Preconditions: the county log must have processed its provisioning
// entries and produced a cosigned tree head (TreeHeadClient can fetch it).
// If the county's tree head isn't available yet, this returns an error —
// the caller retries after the county operator publishes its first head.
func RegisterFirstAnchor(
	cfg AnchorRegistrationConfig,
	treeHeadClient *witness.TreeHeadClient,
) (*AnchorRegistrationResult, error) {
	if cfg.CountyOperatorDID == "" {
		return nil, fmt.Errorf("onboarding/anchor_registration: empty county operator DID")
	}
	if cfg.CountyLogDID == "" || cfg.ParentLogDID == "" {
		return nil, fmt.Errorf("onboarding/anchor_registration: both log DIDs required")
	}
	if treeHeadClient == nil {
		return nil, fmt.Errorf("onboarding/anchor_registration: nil tree head client")
	}

	eventTime := cfg.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	// Fetch the county log's current tree head.
	head, _, err := treeHeadClient.FetchLatestTreeHead(cfg.CountyLogDID)
	if err != nil {
		return nil, fmt.Errorf(
			"onboarding/anchor_registration: county log %s has no available tree head yet: %w",
			cfg.CountyLogDID, err,
		)
	}
	if head.TreeSize == 0 {
		return nil, fmt.Errorf(
			"onboarding/anchor_registration: county log %s tree size is 0 (provisioning incomplete)",
			cfg.CountyLogDID,
		)
	}

	// Compute tree head reference hash.
	msg := types.WitnessCosignMessage(head.TreeHead)
	headHash := sha256.Sum256(msg[:])
	headRef := hex.EncodeToString(headHash[:])

	entry, err := builder.BuildAnchorEntry(builder.AnchorParams{
		SignerDID:    cfg.CountyOperatorDID,
		SourceLogDID: cfg.CountyLogDID,
		TreeHeadRef:  headRef,
		TreeSize:     head.TreeSize,
		EventTime:    eventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("onboarding/anchor_registration: build anchor: %w", err)
	}

	return &AnchorRegistrationResult{
		AnchorEntry:  entry,
		TreeHeadRef:  headRef,
		TreeSize:     head.TreeSize,
		TargetLogDID: cfg.ParentLogDID,
	}, nil
}
