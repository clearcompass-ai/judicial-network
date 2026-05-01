/*
FILE PATH: tools/aggregator/parties_filings.go

DESCRIPTION:
    parties_filings indexer extension (3E.5). Walks every entry's
    payload for filed_by_capacity (single block) and
    signed_by_capacities (list) blocks and produces one row per
    capacity for the parties_filings table.

    The row-builder is a PURE FUNCTION over ClassifiedEntry —
    testable without Postgres. The SQL writer is a thin wrapper
    that takes the rows and INSERTs them, with ON CONFLICT
    DO NOTHING for rescan idempotency.

OVERVIEW:
    PartiesFilingRow            row shape produced by extraction.
    BuildPartiesFilingRows      pure extractor.
    Indexer.indexPartiesFilings SQL writer (calls extractor + db).
*/
package aggregator

import (
	"context"
	"encoding/json"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// PartiesFilingRow is the in-memory shape one row produces. The
// SQL writer maps this directly to the parties_filings table.
type PartiesFilingRow struct {
	LogPosition uint64
	LogDID      string

	// CapacityKind is "filed_by" or "signed_by". Closed-set
	// invariant; the table CHECK constraint enforces this.
	CapacityKind string

	// CapacityDID is the actor's network DID. Empty for Pro Se /
	// Party-side rows (those carry CapacityBindingID instead).
	CapacityDID string

	// CapacityRole is the closed-set role string from
	// schemas.FilerRole / role_catalog.
	CapacityRole string

	// CapacityBindingID is set ONLY when CapacityDID is empty
	// (Pro Se / Party-side reference). Otherwise empty.
	CapacityBindingID string

	// Credentials is the marshaled JSON of the capacity's
	// credentials map. Empty string when no credentials block.
	CredentialsJSON string

	EventType string
	CaseRef   string
	SwornAt   string
}

// BuildPartiesFilingRows extracts every parties_filings row this
// entry produces. Pure function — no I/O, no panics, returns
// the empty slice when the payload has no capacity blocks.
func BuildPartiesFilingRows(c *ClassifiedEntry) []PartiesFilingRow {
	if c == nil || c.Payload == nil {
		return nil
	}
	eventType, _ := c.Payload["event_type"].(string)
	caseRef, _ := c.Payload["case_ref"].(string)

	var rows []PartiesFilingRow

	// filed_by_capacity is a single map[string]any.
	if fbc, ok := c.Payload["filed_by_capacity"].(map[string]any); ok {
		rows = append(rows, capacityRow(c, "filed_by", fbc, eventType, caseRef))
	}

	// signed_by_capacities is a list of map[string]any.
	if sbcs, ok := c.Payload["signed_by_capacities"].([]any); ok {
		for _, item := range sbcs {
			sbc, ok := item.(map[string]any)
			if !ok {
				continue
			}
			rows = append(rows, capacityRow(c, "signed_by", sbc, eventType, caseRef))
		}
	}

	return rows
}

// capacityRow builds one row from a single capacity block.
func capacityRow(c *ClassifiedEntry, kind string, cap map[string]any,
	eventType, caseRef string) PartiesFilingRow {
	row := PartiesFilingRow{
		LogPosition:  c.Sequence,
		LogDID:       c.LogDID,
		CapacityKind: kind,
		EventType:    eventType,
		CaseRef:      caseRef,
	}
	if v, ok := cap["did"].(string); ok {
		row.CapacityDID = v
	}
	if v, ok := cap["role"].(string); ok {
		row.CapacityRole = v
	}
	if v, ok := cap["binding_id"].(string); ok {
		row.CapacityBindingID = v
	}
	if v, ok := cap["sworn_at"].(string); ok {
		row.SwornAt = v
	}
	if creds, ok := cap["credentials"].(map[string]any); ok && len(creds) > 0 {
		if b, err := json.Marshal(creds); err == nil {
			row.CredentialsJSON = string(b)
		}
	}
	return row
}

// indexPartiesFilings writes every capacity row this entry
// produces to the parties_filings table. ON CONFLICT DO NOTHING
// makes the call idempotent on rescan — the UNIQUE constraint
// (log_did, log_position, capacity_did, capacity_binding_id,
// capacity_kind) prevents duplicates.
func (idx *Indexer) indexPartiesFilings(ctx context.Context, c *ClassifiedEntry) error {
	rows := BuildPartiesFilingRows(c)
	if len(rows) == 0 {
		return nil
	}

	// Resolve case_id once (shared by every row of this entry).
	caseID := idx.lookupCaseID(ctx, c)

	for _, r := range rows {
		var bindingPtr any
		if r.CapacityBindingID != "" {
			bindingPtr = r.CapacityBindingID
		}
		var credsPtr any
		if r.CredentialsJSON != "" {
			credsPtr = r.CredentialsJSON
		}
		_, err := idx.db.ExecContext(ctx, `
			INSERT INTO parties_filings (
				case_id, log_position, log_did, capacity_kind,
				capacity_did, capacity_role, capacity_binding_id,
				credentials, event_type, case_ref, sworn_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11::timestamptz)
			ON CONFLICT DO NOTHING
		`, caseID, r.LogPosition, r.LogDID, r.CapacityKind,
			r.CapacityDID, r.CapacityRole, bindingPtr,
			credsPtr, r.EventType, nullIfEmpty(r.CaseRef),
			nullIfEmpty(r.SwornAt))
		if err != nil {
			return err
		}
	}
	return nil
}

// lookupCaseID joins back to cases by (log_did, log_position) of
// the case_root. Returns nil when no match (lifecycle events
// emitted before the case row exists; Indexer rescans pick them
// up later).
func (idx *Indexer) lookupCaseID(ctx context.Context, c *ClassifiedEntry) *int64 {
	if c.TargetRootSeq == nil {
		return nil
	}
	var id int64
	err := idx.db.QueryRowContext(ctx,
		`SELECT id FROM cases WHERE log_position = $1 AND log_did = $2`,
		*c.TargetRootSeq, c.LogDID).Scan(&id)
	if err != nil {
		return nil
	}
	return &id
}

// _ = common.DB silences the unused import in the v0.5.0 stub
// when the Indexer is built without a live database (tests).
var _ = (*common.DB)(nil)
