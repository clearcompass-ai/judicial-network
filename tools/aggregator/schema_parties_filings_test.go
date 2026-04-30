/*
FILE PATH: tools/aggregator/schema_parties_filings_test.go

DESCRIPTION:
    Tests the parties_filings DDL added in 3E.5. Loads schema.sql
    from disk and pins the columns + invariants the Indexer (next
    commit) will rely on. No live Postgres required — text-level
    DDL invariants are sufficient to catch silent drift.
*/
package aggregator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// schemaSQL reads the DDL once per test invocation.
func schemaSQL(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(wd, "schema.sql"))
	if err != nil {
		t.Fatalf("read schema.sql: %v", err)
	}
	return string(data)
}

func TestSchemaSQL_DefinesPartiesFilingsTable(t *testing.T) {
	sql := schemaSQL(t)
	if !strings.Contains(sql, "CREATE TABLE IF NOT EXISTS parties_filings") {
		t.Error("schema.sql must define the parties_filings table")
	}
}

// TestSchemaSQL_PartiesFilings_RequiredColumns pins every column
// the Indexer will write to. Drift here means a follow-on commit
// can silently break the rebuilt cache.
func TestSchemaSQL_PartiesFilings_RequiredColumns(t *testing.T) {
	sql := schemaSQL(t)
	want := []string{
		"case_id",
		"log_position",
		"log_did",
		"capacity_kind",
		"capacity_did",
		"capacity_role",
		"capacity_binding_id",
		"credentials",
		"event_type",
		"case_ref",
		"sworn_at",
	}
	for _, col := range want {
		if !strings.Contains(sql, col) {
			t.Errorf("schema.sql parties_filings missing column %q", col)
		}
	}
}

// TestSchemaSQL_PartiesFilings_KindClosedSet pins the CHECK
// constraint so the kind column stays a closed set: filed_by,
// signed_by.
func TestSchemaSQL_PartiesFilings_KindClosedSet(t *testing.T) {
	sql := schemaSQL(t)
	want := []string{
		"capacity_kind",
		"'filed_by'",
		"'signed_by'",
		"CHECK",
	}
	for _, frag := range want {
		if !strings.Contains(sql, frag) {
			t.Errorf("schema.sql parties_filings missing CHECK fragment %q", frag)
		}
	}
}

// TestSchemaSQL_PartiesFilings_UniqueOnRescanIdempotent pins
// the UNIQUE constraint that makes Indexer rescans idempotent.
func TestSchemaSQL_PartiesFilings_UniqueOnRescanIdempotent(t *testing.T) {
	sql := schemaSQL(t)
	want := []string{
		"UNIQUE",
		"log_did",
		"log_position",
		"capacity_did",
		"capacity_binding_id",
		"capacity_kind",
	}
	for _, frag := range want {
		if !strings.Contains(sql, frag) {
			t.Errorf("schema.sql parties_filings UNIQUE constraint missing %q", frag)
		}
	}
}

// TestSchemaSQL_PartiesFilings_Indexes pins the read-side
// indexes the Indexer / API queries will rely on.
func TestSchemaSQL_PartiesFilings_Indexes(t *testing.T) {
	sql := schemaSQL(t)
	want := []string{
		"idx_parties_filings_case",
		"idx_parties_filings_did",
		"idx_parties_filings_role",
		"idx_parties_filings_event",
		"idx_parties_filings_binding",
	}
	for _, idx := range want {
		if !strings.Contains(sql, idx) {
			t.Errorf("schema.sql missing parties_filings index %q", idx)
		}
	}
}

// TestSchemaSQL_PreservesExistingTables guards against accidental
// removal of pre-3E.5 tables when adding parties_filings.
func TestSchemaSQL_PreservesExistingTables(t *testing.T) {
	sql := schemaSQL(t)
	for _, tbl := range []string{
		"cases", "case_events", "officers", "artifacts",
		"sealing_orders", "assignments", "scan_watermarks",
	} {
		if !strings.Contains(sql, "CREATE TABLE IF NOT EXISTS "+tbl) {
			t.Errorf("schema.sql missing pre-3E.5 table %q", tbl)
		}
	}
}
