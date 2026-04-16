/*
FILE PATH: enforcement/compliance.go
DESCRIPTION: Enforcement timeline verification. Walks the authority lane
    of a case entity and reports on active, pending, and overridden
    constraints plus per-constraint contest state.

KEY ARCHITECTURAL DECISIONS:
    - Correction #3: uses verifier.EvaluateAuthority (O(A) walker that
      handles snapshots and skip pointers) rather than manual scanning.
      This is the difference vs verification/sealing_check.go: compliance
      produces a rich timeline for court administration; sealing_check
      returns a compact status for API responses.
    - Correction #7: per active constraint, calls EvaluateContest to
      determine whether pending operations referencing it are blocked by
      unresolved contest. Reports surface this as RequiresAttention.
    - Pure read-only: no SMT mutation, no entry creation. Safe to run
      against live logs at arbitrary cadence.

OVERVIEW: RunComplianceCheck → ComplianceReport{Active, Pending, Overridden,
    PendingContests, Summary}.
KEY DEPENDENCIES: ortholog-sdk/verifier, ortholog-sdk/core/smt, ortholog-sdk/schema
*/
package enforcement

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// ComplianceConfig configures a compliance check.
type ComplianceConfig struct {
	CaseRootPos types.LogPosition
	// Now is the evaluation time. Zero value uses time.Now().UTC().
	Now time.Time
	// CheckContests enables per-constraint contest evaluation. Expensive
	// for long authority chains; recommended true for accuracy.
	CheckContests bool
}

// ConstraintReport describes one constraint in the authority chain.
type ConstraintReport struct {
	Position          types.LogPosition
	State             verifier.ConstraintState
	StateLabel        string
	SignerDID         string
	OrderType         string
	LogTime           time.Time
	ContestedBy       *types.LogPosition
	OverrideBy        *types.LogPosition
	RequiresAttention bool
}

// ComplianceReport is the output of RunComplianceCheck.
type ComplianceReport struct {
	CaseRootPos       types.LogPosition
	EvaluatedAt       time.Time
	ActiveCount       int
	PendingCount      int
	ChainLength       int
	UsedSnapshot      bool
	ActiveConstraints []ConstraintReport
	PendingContests   []ConstraintReport
	Summary           string
}

// RunComplianceCheck walks the authority lane for a case entity using
// verifier.EvaluateAuthority (correction #3) and produces a timeline
// for court compliance monitoring. Optionally evaluates per-constraint
// contest state (correction #7).
func RunComplianceCheck(
	cfg ComplianceConfig,
	fetcher builder.EntryFetcher,
	leafReader smt.LeafReader,
	extractor schema.SchemaParameterExtractor,
) (*ComplianceReport, error) {
	if cfg.CaseRootPos.IsNull() {
		return nil, fmt.Errorf("enforcement/compliance: null case root position")
	}

	now := cfg.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	leafKey := smt.DeriveKey(cfg.CaseRootPos)

	authEval, err := verifier.EvaluateAuthority(leafKey, leafReader, fetcher, extractor)
	if err != nil {
		return nil, fmt.Errorf("enforcement/compliance: evaluate authority: %w", err)
	}

	report := &ComplianceReport{
		CaseRootPos:  cfg.CaseRootPos,
		EvaluatedAt:  now,
		ActiveCount:  len(authEval.ActiveConstraints),
		PendingCount: authEval.PendingCount,
		ChainLength:  authEval.ChainLength,
		UsedSnapshot: authEval.UsedSnapshot,
	}

	for _, c := range authEval.ActiveConstraints {
		cr := ConstraintReport{
			Position:   c.Position,
			State:      c.State,
			StateLabel: constraintStateLabel(c.State),
			LogTime:    c.LogTime,
		}
		if c.Entry != nil {
			cr.SignerDID = c.Entry.Header.SignerDID
			cr.OrderType = readOrderType(c.Entry.DomainPayload)
		}

		if cfg.CheckContests {
			contestResult, cErr := verifier.EvaluateContest(
				c.Position, fetcher, leafReader, extractor,
			)
			if cErr == nil && contestResult != nil {
				if contestResult.OperationBlocked {
					cr.RequiresAttention = true
					if contestResult.ContestPos != nil {
						pos := *contestResult.ContestPos
						cr.ContestedBy = &pos
					}
				}
				if contestResult.OverridePos != nil {
					pos := *contestResult.OverridePos
					cr.OverrideBy = &pos
				}
			}
		}

		report.ActiveConstraints = append(report.ActiveConstraints, cr)
		if cr.RequiresAttention {
			report.PendingContests = append(report.PendingContests, cr)
		}
	}

	report.Summary = formatComplianceSummary(report)
	return report, nil
}

func constraintStateLabel(s verifier.ConstraintState) string {
	switch s {
	case verifier.ConstraintActive:
		return "active"
	case verifier.ConstraintPending:
		return "pending"
	case verifier.ConstraintOverridden:
		return "overridden"
	default:
		return "unknown"
	}
}

func readOrderType(domainPayload []byte) string {
	if len(domainPayload) == 0 {
		return ""
	}
	var p struct {
		OrderType string `json:"order_type"`
	}
	if err := json.Unmarshal(domainPayload, &p); err != nil {
		return ""
	}
	return p.OrderType
}

func formatComplianceSummary(r *ComplianceReport) string {
	attention := ""
	if len(r.PendingContests) > 0 {
		attention = fmt.Sprintf(" (%d require attention)", len(r.PendingContests))
	}
	snap := ""
	if r.UsedSnapshot {
		snap = " [snapshot]"
	}
	return fmt.Sprintf(
		"%d active, %d pending, chain %d%s%s",
		r.ActiveCount, r.PendingCount, r.ChainLength, snap, attention,
	)
}
