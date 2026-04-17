package aggregator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// Indexer writes classified entries into Postgres tables.
type Indexer struct {
	db *common.DB
}

// NewIndexer creates an indexer backed by the given database.
func NewIndexer(db *common.DB) *Indexer {
	return &Indexer{db: db}
}

// Index dispatches a classified entry to the appropriate table writer.
func (idx *Indexer) Index(ctx context.Context, c *ClassifiedEntry) error {
	switch c.EntryType {
	case "new_case":
		return idx.indexNewCase(ctx, c)
	case "amendment":
		return idx.indexAmendment(ctx, c)
	case "delegation":
		return idx.indexDelegation(ctx, c)
	case "revocation":
		return idx.indexRevocation(ctx, c)
	case "enforcement":
		return idx.indexEnforcement(ctx, c)
	case "path_b_order":
		return idx.indexPathBOrder(ctx, c)
	case "cosignature":
		return idx.indexCosignature(ctx, c)
	case "commentary":
		return idx.indexCommentary(ctx, c)
	case "scope_creation", "schema":
		// Indexed only as case_events for audit trail.
		return idx.indexGenericEvent(ctx, c)
	default:
		return nil
	}
}

func (idx *Indexer) indexNewCase(ctx context.Context, c *ClassifiedEntry) error {
	docket, _ := c.Payload["docket_number"].(string)
	caseType, _ := c.Payload["case_type"].(string)
	division, _ := c.Payload["division"].(string)
	filedDate, _ := c.Payload["filed_date"].(string)
	status := "active"
	if s, ok := c.Payload["status"].(string); ok && s != "" {
		status = s
	}

	_, err := idx.db.ExecContext(ctx, `
		INSERT INTO cases (docket_number, case_type, division, status, filed_date,
		                   court_did, log_did, log_position, signer_did)
		VALUES ($1, $2, $3, $4, $5::date, $6, $7, $8, $9)
		ON CONFLICT (docket_number) DO NOTHING
	`, docket, caseType, division, status, nullIfEmpty(filedDate),
		c.SignerDID, c.LogDID, c.Sequence, c.SignerDID)
	return err
}

func (idx *Indexer) indexAmendment(ctx context.Context, c *ClassifiedEntry) error {
	if c.TargetRootSeq == nil {
		return nil
	}

	// Update case status if payload includes it.
	if newStatus, ok := c.Payload["status"].(string); ok && newStatus != "" {
		_, _ = idx.db.ExecContext(ctx, `
			UPDATE cases SET status = $1, updated_at = NOW()
			WHERE log_position = $2 AND log_did = $3
		`, newStatus, *c.TargetRootSeq, c.LogDID)
	}

	// Insert event.
	return idx.insertEvent(ctx, c, "amendment")
}

func (idx *Indexer) indexDelegation(ctx context.Context, c *ClassifiedEntry) error {
	delegateDID := ""
	if c.DelegateDID != nil {
		delegateDID = *c.DelegateDID
	}

	role, _ := c.Payload["role"].(string)
	division, _ := c.Payload["division"].(string)

	var scopeLimit []string
	if sl, ok := c.Payload["scope_limit"].([]any); ok {
		for _, s := range sl {
			if str, ok := s.(string); ok {
				scopeLimit = append(scopeLimit, str)
			}
		}
	}

	_, err := idx.db.ExecContext(ctx, `
		INSERT INTO officers (delegate_did, signer_did, role, division, scope_limit,
		                      log_position, depth, court_did)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, delegateDID, c.SignerDID, role, division, scopeLimit,
		c.Sequence, 1, c.SignerDID)
	return err
}

func (idx *Indexer) indexRevocation(ctx context.Context, c *ClassifiedEntry) error {
	if c.TargetRootSeq == nil {
		return nil
	}

	_, err := idx.db.ExecContext(ctx, `
		UPDATE officers SET is_live = FALSE, revoked_at_pos = $1
		WHERE log_position = $2
	`, c.Sequence, *c.TargetRootSeq)
	if err != nil {
		return err
	}

	return idx.insertEvent(ctx, c, "revocation")
}

func (idx *Indexer) indexEnforcement(ctx context.Context, c *ClassifiedEntry) error {
	orderType, _ := c.Payload["order_type"].(string)
	authority, _ := c.Payload["authority"].(string)

	var affectedCIDs []string
	if cids, ok := c.Payload["affected_artifacts"].([]any); ok {
		for _, cid := range cids {
			if s, ok := cid.(string); ok {
				affectedCIDs = append(affectedCIDs, s)
			}
		}
	}

	// Find case by target root position.
	var caseID *int64
	if c.TargetRootSeq != nil {
		var id int64
		err := idx.db.QueryRowContext(ctx, `
			SELECT id FROM cases WHERE log_position = $1 AND log_did = $2
		`, *c.TargetRootSeq, c.LogDID).Scan(&id)
		if err == nil {
			caseID = &id
		}
	}

	_, err := idx.db.ExecContext(ctx, `
		INSERT INTO sealing_orders (case_id, order_type, log_position, signer_did,
		                            authority, affected_cids)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, caseID, orderType, c.Sequence, c.SignerDID, authority, affectedCIDs)
	if err != nil {
		return err
	}

	// Update case sealed/expunged status.
	if caseID != nil {
		switch orderType {
		case "sealing_order":
			_, _ = idx.db.ExecContext(ctx,
				`UPDATE cases SET sealed = TRUE, updated_at = NOW() WHERE id = $1`, *caseID)
		case "unsealing_order":
			_, _ = idx.db.ExecContext(ctx,
				`UPDATE cases SET sealed = FALSE, updated_at = NOW() WHERE id = $1`, *caseID)
		case "expungement":
			_, _ = idx.db.ExecContext(ctx,
				`UPDATE cases SET expunged = TRUE, sealed = TRUE, updated_at = NOW() WHERE id = $1`, *caseID)
		}
	}

	return idx.insertEvent(ctx, c, "enforcement")
}

func (idx *Indexer) indexPathBOrder(ctx context.Context, c *ClassifiedEntry) error {
	return idx.insertEvent(ctx, c, "path_b_order")
}

func (idx *Indexer) indexCosignature(ctx context.Context, c *ClassifiedEntry) error {
	return idx.insertEvent(ctx, c, "cosignature")
}

func (idx *Indexer) indexCommentary(ctx context.Context, c *ClassifiedEntry) error {
	// Check for assignment entries.
	if date, ok := c.Payload["assignment_date"].(string); ok {
		return idx.indexAssignment(ctx, c, date)
	}
	return idx.insertEvent(ctx, c, "commentary")
}

func (idx *Indexer) indexAssignment(ctx context.Context, c *ClassifiedEntry, date string) error {
	division, _ := c.Payload["division"].(string)

	assignments, ok := c.Payload["assignments"].([]any)
	if !ok {
		return nil
	}

	for _, a := range assignments {
		assignment, ok := a.(map[string]any)
		if !ok {
			continue
		}

		judgeDID, _ := assignment["judge_did"].(string)
		var courtrooms, caseTypes []string

		if cr, ok := assignment["courtrooms"].([]any); ok {
			for _, r := range cr {
				if s, ok := r.(string); ok {
					courtrooms = append(courtrooms, s)
				}
			}
		}
		if ct, ok := assignment["case_types"].([]any); ok {
			for _, t := range ct {
				if s, ok := t.(string); ok {
					caseTypes = append(caseTypes, s)
				}
			}
		}

		_, err := idx.db.ExecContext(ctx, `
			INSERT INTO assignments (assignment_date, division, judge_did, courtrooms,
			                         case_types, log_position)
			VALUES ($1::date, $2, $3, $4, $5, $6)
		`, date, division, judgeDID, courtrooms, caseTypes, c.Sequence)
		if err != nil {
			return err
		}
	}

	return nil
}

func (idx *Indexer) indexGenericEvent(ctx context.Context, c *ClassifiedEntry) error {
	return idx.insertEvent(ctx, c, c.EntryType)
}

func (idx *Indexer) insertEvent(ctx context.Context, c *ClassifiedEntry, eventType string) error {
	// Find case by target root.
	var caseID *int64
	if c.TargetRootSeq != nil {
		var id int64
		err := idx.db.QueryRowContext(ctx,
			`SELECT id FROM cases WHERE log_position = $1 AND log_did = $2`,
			*c.TargetRootSeq, c.LogDID).Scan(&id)
		if err == nil {
			caseID = &id
		}
	}

	summaryJSON, _ := json.Marshal(c.Payload)

	var logTime *string
	if !c.LogTime.IsZero() {
		t := c.LogTime.Format("2006-01-02T15:04:05Z07:00")
		logTime = &t
	}

	_, err := idx.db.ExecContext(ctx, `
		INSERT INTO case_events (case_id, event_type, log_position, signer_did,
		                         authority_path, payload_summary, log_time)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::timestamptz)
	`, caseID, eventType, c.Sequence, c.SignerDID,
		nullIfEmpty(c.AuthorityPath), string(summaryJSON), logTime)
	return err
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// RunMigrations applies the schema.sql to the database.
func RunMigrations(db *common.DB, schemaSQL string) error {
	_, err := db.Pool.Exec(schemaSQL)
	if err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	return nil
}
