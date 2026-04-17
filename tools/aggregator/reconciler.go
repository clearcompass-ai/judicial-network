package aggregator

import (
	"context"
	"fmt"
	"log"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// Reconciler periodically verifies that Postgres matches the log.
// If Postgres is wrong, it can be rebuilt from scratch by scanning from 0.
type Reconciler struct {
	operator     *common.OperatorClient
	db           *common.DB
	deserializer *Deserializer
	logDIDs      []string
}

// NewReconciler creates a reconciler.
func NewReconciler(cfg common.Config, operator *common.OperatorClient, db *common.DB) *Reconciler {
	return &Reconciler{
		operator:     operator,
		db:           db,
		deserializer: NewDeserializer(),
		logDIDs:      cfg.LogDIDs(),
	}
}

// ReconcileResult holds the outcome of a reconciliation run.
type ReconcileResult struct {
	LogDID       string
	EntriesCheck int
	Mismatches   int
	Details      []string
}

// Reconcile checks the last N entries on each log against Postgres.
func (r *Reconciler) Reconcile(ctx context.Context, checkCount int) ([]ReconcileResult, error) {
	var results []ReconcileResult

	for _, logDID := range r.logDIDs {
		result, err := r.reconcileLog(ctx, logDID, checkCount)
		if err != nil {
			return nil, fmt.Errorf("reconcile %s: %w", logDID, err)
		}
		results = append(results, *result)
	}

	return results, nil
}

func (r *Reconciler) reconcileLog(ctx context.Context, logDID string, checkCount int) (*ReconcileResult, error) {
	result := &ReconcileResult{LogDID: logDID}

	watermark, err := r.db.GetWatermark(logDID)
	if err != nil {
		return nil, err
	}

	if watermark == 0 {
		result.Details = append(result.Details, "no entries indexed yet")
		return result, nil
	}

	// Check from max(0, watermark-checkCount) to watermark.
	startPos := uint64(0)
	if watermark > uint64(checkCount) {
		startPos = watermark - uint64(checkCount)
	}

	entries, err := r.operator.ScanFrom(startPos, checkCount)
	if err != nil {
		return nil, err
	}

	for _, raw := range entries {
		result.EntriesCheck++

		classified, err := r.deserializer.Classify(logDID, raw)
		if err != nil {
			result.Mismatches++
			result.Details = append(result.Details,
				fmt.Sprintf("seq=%d: deserialize error: %v", raw.Sequence, err))
			continue
		}

		// Check case_events table for this entry.
		var exists bool
		err = r.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM case_events WHERE log_position = $1)`,
			raw.Sequence).Scan(&exists)

		if err != nil {
			result.Mismatches++
			result.Details = append(result.Details,
				fmt.Sprintf("seq=%d: db query error: %v", raw.Sequence, err))
			continue
		}

		// Commentary and certain types may not have case_events entries.
		// Check type-specific tables.
		switch classified.EntryType {
		case "new_case":
			var caseExists bool
			r.db.QueryRowContext(ctx,
				`SELECT EXISTS(SELECT 1 FROM cases WHERE log_position = $1 AND log_did = $2)`,
				raw.Sequence, logDID).Scan(&caseExists)
			if !caseExists {
				result.Mismatches++
				result.Details = append(result.Details,
					fmt.Sprintf("seq=%d: case not in Postgres", raw.Sequence))
			}
		case "delegation":
			var officerExists bool
			r.db.QueryRowContext(ctx,
				`SELECT EXISTS(SELECT 1 FROM officers WHERE log_position = $1)`,
				raw.Sequence).Scan(&officerExists)
			if !officerExists {
				result.Mismatches++
				result.Details = append(result.Details,
					fmt.Sprintf("seq=%d: officer not in Postgres", raw.Sequence))
			}
		}
	}

	if result.Mismatches > 0 {
		log.Printf("reconciler: %s — %d mismatches in %d entries",
			logDID, result.Mismatches, result.EntriesCheck)
	}

	return result, nil
}

// RebuildFromScratch drops all data and re-scans from position 0.
// Use when reconciliation finds too many mismatches.
func (r *Reconciler) RebuildFromScratch(ctx context.Context) error {
	log.Println("reconciler: rebuilding from scratch — truncating all tables")

	tables := []string{
		"assignments", "sealing_orders", "artifacts",
		"case_events", "officers", "cases", "scan_watermarks",
	}
	for _, table := range tables {
		if _, err := r.db.ExecContext(ctx, "TRUNCATE "+table+" CASCADE"); err != nil {
			return fmt.Errorf("truncate %s: %w", table, err)
		}
	}

	// Reset watermarks so the scanner starts from 0.
	for _, logDID := range r.logDIDs {
		if err := r.db.UpdateWatermark(logDID, 0); err != nil {
			return fmt.Errorf("reset watermark %s: %w", logDID, err)
		}
	}

	log.Println("reconciler: rebuild complete — scanner will re-index on next poll")
	return nil
}
