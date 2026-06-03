/*
FILE PATH: enforcement/compliance.go
DESCRIPTION: Enforcement timeline verification. Walks the authority lane

	of a case entity and reports on active, pending, and overridden
	constraints plus per-constraint contest state.

KEY ARCHITECTURAL DECISIONS:
  - Correction #3: uses verifier.EvaluateAuthorityWithTrust (O(A) walker
    that handles snapshots and skip pointers) rather than manual scanning.
    Fed by a LocalTrust adapter from verification/trust over the
    (fetcher, leafReader) pair the call site already holds.
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

KEY DEPENDENCIES: baseproof/verifier, baseproof/core/smt, baseproof/schema
*/
package enforcement

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/schema"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

// ComplianceConfig configures a compliance check.
type ComplianceConfig struct {
	CaseRootPos types.LogPosition
	// Now is the evaluation time. Zero value uses time.Now().UTC().
	Now time.Time
	// AsOf pins the cosigned head that the authority walker evaluates
	// against (C-4 of PR-C). Zero (AsOf{}) preserves the legacy
	// "latest known head" semantics — the walker resolves the
	// current trusted head and uses time.Now().UTC() internally for
	// activation timestamps. Non-zero AsOf binds the verdict to a
	// SPECIFIC head: every signer-membership / activation check is
	// then evaluated under THAT head's witness set, making the
	// verdict deterministic in the head (Goal 6 — court-admissible
	// reproducibility) and the witness set frozen across rotations
	// (Goal 13 — year-15 verification of year-1 bundles).
	AsOf verifier.AsOf
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
// verifier.EvaluateAuthorityWithTrust (correction #3) and produces a
// timeline for court compliance monitoring. Optionally evaluates
// per-constraint contest state (correction #7).
//
// trustProvider is the C-3 dispatch seam. Production callers thread
// deps.PickTrust() — a MultiJurisdictionTrust when cross-network
// PeerLogs are declared, else a LocalTrust over the same (fetcher,
// leafReader) pair the legacy path used. cfg.AsOf pins the head the
// walker evaluates against (Goal 6 reproducibility; Goal 13 year-15
// verification). fetcher + leafReader stay in the signature for
// EvaluateContest's per-constraint check (the SDK has not yet
// shipped EvaluateContestWithTrust).
func RunComplianceCheck(
	ctx context.Context,
	cfg ComplianceConfig,
	trustProvider verifier.LogTrustProvider,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
	extractor schema.SchemaParameterExtractor,
) (*ComplianceReport, error) {
	if cfg.CaseRootPos.IsNull() {
		return nil, fmt.Errorf("enforcement/compliance: null case root position")
	}
	if trustProvider == nil {
		return nil, fmt.Errorf("enforcement/compliance: nil trustProvider (use deps.PickTrust())")
	}

	now := cfg.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// ZT-IMM-01 (baseproof v1.43.0): cfg.AsOf{} ("latest") is no longer an
	// implicit wall-clock default inside the SDK — resolve it to a pinned
	// head deliberately so the verdict is reproducible.
	asOf := cfg.AsOf
	if asOf.IsNull() {
		latest, rerr := verifier.ResolveLatest(ctx, trustProvider, cfg.CaseRootPos.LogDID)
		if rerr != nil {
			return nil, fmt.Errorf("enforcement/compliance: resolve latest head: %w", rerr)
		}
		asOf = latest
	}

	authEval, err := verifier.EvaluateAuthorityWithTrust(
		ctx, cfg.CaseRootPos, trustProvider, extractor, asOf)
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
			contestResult, cErr := verifier.EvaluateContest(ctx,
				c.Position, fetcher, leafReader, extractor)

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
