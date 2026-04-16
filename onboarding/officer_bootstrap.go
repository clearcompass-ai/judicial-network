/*
FILE PATH: onboarding/officer_bootstrap.go
DESCRIPTION: Bulk delegation creation from an initial officer roster. For a
    freshly-provisioned court, creates the full depth-1 (judges), depth-2
    (clerks), and depth-3 (deputies) delegation tree in one pass.
KEY ARCHITECTURAL DECISIONS:
    - Thin wrapper over judicial-network/delegation builders.
    - Handles the depth ordering: judges must be created before clerks can
      be delegated to, clerks before deputies.
    - Returns per-log entry sets (typically all targeted at officers log).
OVERVIEW: BootstrapOfficers returns ordered entries for the caller to submit.
KEY DEPENDENCIES: judicial-network/delegation, judicial-network/schemas
*/
package onboarding

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/delegation"
)

// RosterEntry describes one officer to bootstrap.
type RosterEntry struct {
	DID           string // e.g., did:web:ed-smith.judges.davidson-county.court.gov
	Role          string // "judge" | "clerk" | "deputy"
	ParentDID     string // Who delegates to this officer
	Division      string // "criminal" | "civil" | "family" | "juvenile"
	Title         string
	AppointedDate string // ISO 8601
	BarNumber     string
	ScopeLimit    string
}

// OfficerBootstrapConfig configures the bulk bootstrap.
type OfficerBootstrapConfig struct {
	Roster    []RosterEntry
	SchemaRef *types.LogPosition // tn-court-officer-v1 schema on the cases log
	EventTime int64
}

// BootstrapResult holds the ordered entries for submission.
type BootstrapResult struct {
	// JudgeEntries are depth-1 delegations. Submit first.
	JudgeEntries []*envelope.Entry

	// ClerkEntries are depth-2 delegations. Submit after judges.
	ClerkEntries []*envelope.Entry

	// DeputyEntries are depth-3 delegations. Submit last.
	DeputyEntries []*envelope.Entry

	// Errors collects per-officer errors. Bootstrap continues on error.
	Errors map[string]string
}

// BootstrapOfficers builds delegation entries for every officer in the roster.
// The returned BootstrapResult groups entries by depth so the caller submits
// them in valid order (judges → clerks → deputies).
//
// Each officer's depth is inferred from their Role. Cross-depth submission
// ordering is enforced by grouping; within a group, order doesn't matter.
func BootstrapOfficers(cfg OfficerBootstrapConfig) (*BootstrapResult, error) {
	eventTime := cfg.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	result := &BootstrapResult{Errors: make(map[string]string)}

	for _, officer := range cfg.Roster {
		if err := validateRosterEntry(officer); err != nil {
			result.Errors[officer.DID] = err.Error()
			continue
		}

		var (
			entry *envelope.Entry
			err   error
		)

		switch officer.Role {
		case "judge":
			entry, err = delegation.DelegateJudge(delegation.JudgeDelegationConfig{
				DivisionDID:   officer.ParentDID,
				JudgeDID:      officer.DID,
				Division:      officer.Division,
				AppointedDate: officer.AppointedDate,
				BarNumber:     officer.BarNumber,
				Title:         officer.Title,
				SchemaRef:     cfg.SchemaRef,
				EventTime:     eventTime,
			})
			if err == nil {
				result.JudgeEntries = append(result.JudgeEntries, entry)
			}

		case "clerk":
			entry, err = delegation.DelegateClerk(delegation.ClerkDelegationConfig{
				JudgeDID:      officer.ParentDID,
				ClerkDID:      officer.DID,
				Division:      officer.Division,
				AppointedDate: officer.AppointedDate,
				ScopeLimit:    officer.ScopeLimit,
				Title:         officer.Title,
				SchemaRef:     cfg.SchemaRef,
				EventTime:     eventTime,
			})
			if err == nil {
				result.ClerkEntries = append(result.ClerkEntries, entry)
			}

		case "deputy":
			entry, err = delegation.DelegateDeputy(delegation.DeputyDelegationConfig{
				ClerkDID:      officer.ParentDID,
				DeputyDID:     officer.DID,
				Division:      officer.Division,
				AppointedDate: officer.AppointedDate,
				ScopeLimit:    officer.ScopeLimit,
				SchemaRef:     cfg.SchemaRef,
				EventTime:     eventTime,
			})
			if err == nil {
				result.DeputyEntries = append(result.DeputyEntries, entry)
			}

		default:
			err = fmt.Errorf("unknown role %q", officer.Role)
		}

		if err != nil {
			result.Errors[officer.DID] = err.Error()
		}
	}

	return result, nil
}

// OrderedEntries returns the bootstrap entries in submission order:
// judges first, then clerks, then deputies. Safe for a single batch
// submission or multiple batches respecting the slice boundaries.
func (r *BootstrapResult) OrderedEntries() []*envelope.Entry {
	out := make([]*envelope.Entry, 0, len(r.JudgeEntries)+len(r.ClerkEntries)+len(r.DeputyEntries))
	out = append(out, r.JudgeEntries...)
	out = append(out, r.ClerkEntries...)
	out = append(out, r.DeputyEntries...)
	return out
}

func validateRosterEntry(e RosterEntry) error {
	if e.DID == "" {
		return fmt.Errorf("empty officer DID")
	}
	if e.ParentDID == "" {
		return fmt.Errorf("empty parent DID")
	}
	if e.Role == "" {
		return fmt.Errorf("empty role")
	}
	return nil
}
