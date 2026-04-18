/*
FILE PATH: delegation/roster_sync.go
DESCRIPTION: officers.yaml → delegation tree reconciliation. Queries operator
    via QueryBySignerDID, uses WalkDelegationTree, reconciles state.
KEY ARCHITECTURAL DECISIONS:
    - Uses verifier.WalkDelegationTree (SDK) for discovery.
    - Uses builder.BuildDelegation for missing delegations.
    - Uses builder.BuildRevocation for stale delegations.
    - Does NOT create entries directly — returns actions for the caller to submit.
OVERVIEW: ReconcileRoster compares YAML roster against live delegation tree.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/verifier, ortholog-sdk/core/smt
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

// RosterEntry describes one officer from the YAML roster.
type RosterEntry struct {
	DID       string
	Role      string
	Division  string
	ParentDID string // who delegates to this officer
}

// RosterAction describes a reconciliation action.
type RosterAction struct {
	Type    string // "create_delegation", "revoke_delegation"
	Entry   *envelope.Entry
	Officer RosterEntry
	Reason  string
}

// ReconcileRosterConfig configures roster reconciliation.
type ReconcileRosterConfig struct {
	Destination string // DID of target exchange. Required.
	RootEntityPos types.LogPosition
	Roster        []RosterEntry
	SchemaRef     *types.LogPosition
	EventTime     int64
}

// ReconcileRoster compares the YAML roster against the live delegation tree
// and produces actions to bring the on-log state into alignment.
func ReconcileRoster(
	cfg ReconcileRosterConfig,
	fetcher builder.EntryFetcher,
	leafReader smt.LeafReader,
	querier verifier.DelegationQuerier,
) ([]RosterAction, error) {
	// Walk the live delegation tree.
	tree, err := verifier.WalkDelegationTree(verifier.WalkDelegationTreeParams{
		RootEntityPos: cfg.RootEntityPos,
		Fetcher:       fetcher,
		LeafReader:    leafReader,
		Querier:       querier,
	})
	if err != nil {
		return nil, fmt.Errorf("delegation/roster_sync: walk tree: %w", err)
	}

	// Index live delegations by delegate DID.
	liveDelegations := verifier.LiveDelegations(tree)
	liveByDID := make(map[string]*verifier.DelegationNode, len(liveDelegations))
	for _, node := range liveDelegations {
		liveByDID[node.DelegateDID] = node
	}

	// Index roster by DID.
	rosterByDID := make(map[string]RosterEntry, len(cfg.Roster))
	for _, r := range cfg.Roster {
		rosterByDID[r.DID] = r
	}

	var actions []RosterAction

	// Officers in roster but not live → create delegation.
	for _, r := range cfg.Roster {
		if _, live := liveByDID[r.DID]; !live {
			payload := fmt.Sprintf(`{"role":"%s","division":"%s","delegated_by":"%s"}`,
				r.Role, r.Division, r.ParentDID)

			signerDID := r.ParentDID
			if signerDID == "" {
				continue // cannot create without parent
			}

			entry, bErr := builder.BuildDelegation(builder.DelegationParams{
				Destination: cfg.Destination,
				SignerDID:   signerDID,
				DelegateDID: r.DID,
				Payload:     []byte(payload),
				SchemaRef:   cfg.SchemaRef,
				EventTime:   cfg.EventTime,
			})
			if bErr != nil {
				continue
			}
			actions = append(actions, RosterAction{
				Type:    "create_delegation",
				Entry:   entry,
				Officer: r,
				Reason:  "officer in roster but no live delegation on log",
			})
		}
	}

	// Live delegations not in roster → revoke.
	for did, node := range liveByDID {
		if _, inRoster := rosterByDID[did]; !inRoster {
			entry, bErr := builder.BuildRevocation(builder.RevocationParams{
				Destination: cfg.Destination,
				SignerDID:  node.SignerDID,
				TargetRoot: node.Position,
				EventTime:  cfg.EventTime,
			})
			if bErr != nil {
				continue
			}
			actions = append(actions, RosterAction{
				Type:  "revoke_delegation",
				Entry: entry,
				Officer: RosterEntry{
					DID:       did,
					ParentDID: node.SignerDID,
				},
				Reason: "live delegation not in roster",
			})
		}
	}

	return actions, nil
}
