/*
FILE PATH: monitoring/mirror_consistency.go
DESCRIPTION: Detects mirror drift — cases where the delegation mirror entries
    on the cases log disagree with the live delegation state on the officers log.
KEY ARCHITECTURAL DECISIONS:
    - Compares smt.LeafReader state for delegation leaves on the officers log
      against mirror commentary payloads on the cases log.
    - A live delegation (OriginTip == position on officers log) should have
      at least one un-revoked mirror entry on the cases log.
    - A revoked delegation should either have no mirror or a revocation mirror.
OVERVIEW: CheckMirrorConsistency returns alerts for missing/stale mirrors.
KEY DEPENDENCIES: ortholog-sdk/core/smt, ortholog-sdk/log, ortholog-sdk/verifier
*/
package monitoring

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
	"github.com/clearcompass-ai/ortholog-sdk/monitoring"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

const MonitorMirrorConsistency monitoring.MonitorID = "judicial.mirror_consistency"

// MirrorConsistencyConfig configures the mirror consistency monitor.
type MirrorConsistencyConfig struct {
	// RootEntityPos is the court scope entity on the officers log.
	RootEntityPos types.LogPosition

	// OfficersLogDID is the officers log DID.
	OfficersLogDID string

	// CasesLogDID is the cases log DID (where mirrors should appear).
	CasesLogDID string

	// MirrorSignerDID is the operator DID that signs mirror entries on
	// the cases log.
	MirrorSignerDID string
}

// CheckMirrorConsistency walks the delegation tree and verifies each
// live delegation has a matching mirror on the cases log.
func CheckMirrorConsistency(
	cfg MirrorConsistencyConfig,
	officersQuerier sdklog.OperatorQueryAPI,
	casesQuerier sdklog.OperatorQueryAPI,
	officersFetcher builder.EntryFetcher,
	officersLeafReader smt.LeafReader,
	now time.Time,
) ([]monitoring.Alert, error) {
	if officersQuerier == nil || casesQuerier == nil {
		return nil, fmt.Errorf("monitoring/mirror: both queriers required")
	}

	// 1. Walk the officers log delegation tree.
	tree, err := verifier.WalkDelegationTree(verifier.WalkDelegationTreeParams{
		RootEntityPos: cfg.RootEntityPos,
		Fetcher:       officersFetcher,
		LeafReader:    officersLeafReader,
		Querier:       officersQuerier,
	})
	if err != nil {
		return nil, fmt.Errorf("monitoring/mirror: walk tree: %w", err)
	}

	liveDelegations := verifier.LiveDelegations(tree)
	liveByPos := make(map[types.LogPosition]*verifier.DelegationNode, len(liveDelegations))
	for _, node := range liveDelegations {
		liveByPos[node.Position] = node
	}

	// 2. Fetch mirror entries from the cases log signed by the operator.
	mirrorEntries, err := casesQuerier.QueryBySignerDID(cfg.MirrorSignerDID)
	if err != nil {
		return nil, fmt.Errorf("monitoring/mirror: query mirrors: %w", err)
	}

	mirroredPositions := make(map[types.LogPosition]bool)
	for _, meta := range mirrorEntries {
		entry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil || len(entry.DomainPayload) == 0 {
			continue
		}

		var payload struct {
			MirrorType     string `json:"mirror_type"`
			SourceLogDID   string `json:"source_log_did"`
			SourceSequence uint64 `json:"source_sequence"`
		}
		if json.Unmarshal(entry.DomainPayload, &payload) != nil {
			continue
		}
		if payload.MirrorType != "cross_log_relay" || payload.SourceLogDID != cfg.OfficersLogDID {
			continue
		}
		sourcePos := types.LogPosition{
			LogDID:   payload.SourceLogDID,
			Sequence: payload.SourceSequence,
		}
		mirroredPositions[sourcePos] = true
	}

	// 3. Compare.
	var alerts []monitoring.Alert
	for pos, node := range liveByPos {
		if !mirroredPositions[pos] {
			alerts = append(alerts, monitoring.Alert{
				Monitor:     MonitorMirrorConsistency,
				Severity:    monitoring.Warning,
				Destination: monitoring.Ops,
				Message: fmt.Sprintf(
					"live delegation lacks mirror on cases log: %s → %s",
					node.SignerDID, node.DelegateDID,
				),
				Details: map[string]any{
					"delegation_pos": pos.String(),
					"delegate":       node.DelegateDID,
					"signer":         node.SignerDID,
					"officers_log":   cfg.OfficersLogDID,
					"cases_log":      cfg.CasesLogDID,
				},
				EmittedAt: now,
			})
		}
	}

	// Reverse check: mirrors that point to non-live delegations are stale.
	for pos := range mirroredPositions {
		if _, live := liveByPos[pos]; !live {
			alerts = append(alerts, monitoring.Alert{
				Monitor:     MonitorMirrorConsistency,
				Severity:    monitoring.Info,
				Destination: monitoring.Ops,
				Message:     "mirror entry points to non-live delegation",
				Details: map[string]any{
					"delegation_pos": pos.String(),
					"officers_log":   cfg.OfficersLogDID,
					"cases_log":      cfg.CasesLogDID,
				},
				EmittedAt: now,
			})
		}
	}

	return alerts, nil
}
