/*
FILE PATH: deployments/davidson_county/daily_docket.go

DESCRIPTION:
    Generates daily docket assignment commentary entries for Davidson
    County. Assignments are soft constraints (Layer 3 in the lone-actor
    defense design): the delegation is permanent (who CAN act), the
    assignment is daily (who SHOULD act today).

    Published as commentary entries on the cases log via
    BuildCommentary (guide §11.3). No SMT impact.

    The CMS bridge or presiding judge's clerk runs this daily.

KEY DEPENDENCIES:
    - ortholog-sdk/builder: BuildCommentary (guide §11.3)
*/
package davidson_county

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// DailyDocketConfig configures the daily docket generation.
type DailyDocketConfig struct {
	// SignerDID is the presiding judge or clerk who publishes assignments.
	SignerDID string

	// Date is the assignment date. Zero → today.
	Date time.Time

	// Assignments maps division → list of judge assignments.
	Assignments []DivisionAssignment
}

// DivisionAssignment describes assignments for one division on one day.
type DivisionAssignment struct {
	Division    string            `json:"division"`
	Assignments []JudgeAssignment `json:"assignments"`
}

// JudgeAssignment maps a judge to courtrooms and case types for the day.
type JudgeAssignment struct {
	JudgeDID   string   `json:"judge_did"`
	JudgeName  string   `json:"judge_name"`
	Courtrooms []string `json:"courtrooms"`
	CaseTypes  []string `json:"case_types"`
}

// GenerateDailyDocket creates a commentary entry carrying the day's
// assignments. This is a domain-level convention — the builder
// processes it as a standard commentary entry (no SMT update).
//
// If a non-assigned judge signs an order on an assigned case, the
// domain application flags it for review. The entry is still on the
// log (the builder accepted it — delegation was live), but monitoring
// detects the assignment violation.
func GenerateDailyDocket(cfg DailyDocketConfig) (*envelope.Entry, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("davidson/daily_docket: empty signer DID")
	}

	date := cfg.Date
	if date.IsZero() {
		date = time.Now().UTC().Truncate(24 * time.Hour)
	}

	payload, err := json.Marshal(map[string]any{
		"schema_ref":      "tn-daily-assignment-v1",
		"assignment_date": date.Format("2006-01-02"),
		"court_did":       "did:web:courts.nashville.gov",
		"divisions":       cfg.Assignments,
	})
	if err != nil {
		return nil, fmt.Errorf("davidson/daily_docket: marshal: %w", err)
	}

	return builder.BuildCommentary(builder.CommentaryParams{
		SignerDID: cfg.SignerDID,
		Payload:   payload,
	})
}

// DefaultDavidsonDivisions returns the standard Davidson County
// division list for docket generation.
func DefaultDavidsonDivisions() []string {
	return []string{
		"criminal",
		"civil",
		"chancery",
		"circuit",
		"general-sessions",
		"juvenile",
	}
}
