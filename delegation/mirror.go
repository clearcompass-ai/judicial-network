/*
FILE PATH: delegation/mirror.go
DESCRIPTION: Cross-log delegation mirrors. When a delegation is created/revoked
    on the officers log, a mirror entry is published on the cases log.
KEY ARCHITECTURAL DECISIONS:
    - Uses builder.BuildMirrorEntry (commentary, zero SMT impact).
    - Mirror entries are informational — the cases log operator discovers
      delegations via mirrors rather than querying the officers log directly.
    - Bulk sync mode for bootstrap; reactive mode for ongoing operations.
OVERVIEW: MirrorDelegation → mirror entry for cases log.
    BulkMirrorSync → batch mirror entries for all live delegations.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/verifier
*/
package delegation

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// MirrorConfig configures a single delegation mirror operation.
type MirrorConfig struct {
	Destination string // DID of target exchange. Required.
	SignerDID        string            // Operator or court DID signing the mirror
	SourcePosition   types.LogPosition // Delegation entry position on officers log
	SourceLogDID     string            // Officers log DID
	EventTime        int64
}

// MirrorDelegation creates a mirror commentary entry for publication
// on the cases log. The mirror entry references the source delegation
// entry on the officers log.
func MirrorDelegation(cfg MirrorConfig) (*envelope.Entry, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("delegation/mirror: empty signer DID")
	}
	if cfg.SourceLogDID == "" {
		return nil, fmt.Errorf("delegation/mirror: empty source log DID")
	}

	return builder.BuildMirrorEntry(builder.MirrorParams{
		Destination: cfg.Destination,
		SignerDID:      cfg.SignerDID,
		SourcePosition: cfg.SourcePosition,
		SourceLogDID:   cfg.SourceLogDID,
		EventTime:      cfg.EventTime,
	})
}

// BulkMirrorSync discovers all live delegations on the officers log
// and creates mirror entries for each. Used during bootstrap when the
// cases log has no mirrors yet.
func BulkMirrorSync(
	rootEntityPos types.LogPosition,
	signerDID string,
	sourceLogDID string,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
	querier verifier.DelegationQuerier,
	eventTime int64,
) ([]*envelope.Entry, error) {
	tree, err := verifier.WalkDelegationTree(verifier.WalkDelegationTreeParams{
		RootEntityPos: rootEntityPos,
		Fetcher:       fetcher,
		LeafReader:    leafReader,
		Querier:       querier,
	})
	if err != nil {
		return nil, fmt.Errorf("delegation/mirror: walk tree: %w", err)
	}

	live := verifier.LiveDelegations(tree)
	entries := make([]*envelope.Entry, 0, len(live))
	for _, node := range live {
		entry, mErr := MirrorDelegation(MirrorConfig{
			SignerDID:      signerDID,
			SourcePosition: node.Position,
			SourceLogDID:   sourceLogDID,
			EventTime:      eventTime,
		})
		if mErr != nil {
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}
