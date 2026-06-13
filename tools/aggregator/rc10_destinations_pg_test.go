/*
tools/aggregator/rc10_destinations_pg_test.go — the rebuild law at its
real tier (JN#176 DoD): the SQL store's lifecycle taxonomy against live
Postgres, and drop-table → replay → IDENTICAL rows. DSN-gated
(AGGREGATOR_TEST_PG_DSN); skips cleanly without it — CI's DB matrix runs
it for real.
*/
package aggregator

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/baseproof/baseproof/exchange"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

func pgStore(t *testing.T) (*Indexer, *common.DB) {
	t.Helper()
	dsn := os.Getenv("AGGREGATOR_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AGGREGATOR_TEST_PG_DSN unset — the rebuild-law tier runs in the DB matrix")
	}
	db, err := common.NewDB(dsn)
	if err != nil {
		t.Fatalf("pg connect: %v", err)
	}
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS destinations`,
		`CREATE TABLE destinations (
			destination_ref TEXT PRIMARY KEY, exchange_did TEXT NOT NULL,
			endpoints TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
			log_did TEXT NOT NULL, provisioned_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)`,
	} {
		if _, err := db.ExecContext(context.Background(), stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	return NewIndexer(db), db
}

func snapshotRows(t *testing.T, db *common.DB) string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(),
		`SELECT destination_ref, exchange_did, endpoints, status, provisioned_at, updated_at
		   FROM destinations ORDER BY destination_ref`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := ""
	for rows.Next() {
		var ref, ex, eps, st string
		var p, u int64
		if err := rows.Scan(&ref, &ex, &eps, &st, &p, &u); err != nil {
			t.Fatal(err)
		}
		out += fmt.Sprintf("%s|%s|%s|%s|%d|%d\n", ref, ex, eps, st, p, u)
	}
	return out
}

// replayLifecycle applies the canonical sequence (provision, amend,
// foreign-amend, retire, post-retire-amend, duplicate-provision) and
// returns the refusal codes seen, in order.
func replayLifecycle(t *testing.T, idx *Indexer) []string {
	t.Helper()
	ctx := context.Background()
	const ex = "did:web:state:tn:davidson"
	var refusals []string
	rec := func(code string, err error) {
		if err != nil {
			t.Fatalf("infrastructure error mid-replay: %v", err)
		}
		if code != "" {
			refusals = append(refusals, code)
		}
	}
	rec(idx.ApplyProvision(ctx, exchange.DestinationProvision{
		DestinationRef: "tn/davidson/circuit-1", ExchangeDID: ex,
		Endpoints: map[string]string{"filing": "https://a.example", "api": "https://b.example"}}, "log", 10))
	rec(idx.ApplyAmend(ctx, exchange.DestinationAmend{
		DestinationRef: "tn/davidson/circuit-1", ExchangeDID: ex,
		Endpoints: map[string]string{"filing": "https://c.example"}}, "log", 20))
	rec(idx.ApplyAmend(ctx, exchange.DestinationAmend{
		DestinationRef: "tn/davidson/circuit-1", ExchangeDID: "did:web:foreign",
		Endpoints: map[string]string{"x": "https://x.example"}}, "log", 30))
	rec(idx.ApplyRetire(ctx, exchange.DestinationRetire{
		DestinationRef: "tn/davidson/circuit-1", ExchangeDID: ex}, "log", 40))
	rec(idx.ApplyAmend(ctx, exchange.DestinationAmend{
		DestinationRef: "tn/davidson/circuit-1", ExchangeDID: ex,
		Endpoints: map[string]string{"y": "https://y.example"}}, "log", 50))
	rec(idx.ApplyProvision(ctx, exchange.DestinationProvision{
		DestinationRef: "tn/davidson/circuit-1", ExchangeDID: ex,
		Endpoints: map[string]string{"z": "https://z.example"}}, "log", 60))
	return refusals
}

func TestRC10_PG_TaxonomyAndRebuildLaw(t *testing.T) {
	idx, db := pgStore(t)

	wantRefusals := []string{RefusalForeignExchange, RefusalAmendAfterRetire, RefusalDuplicateProvision}
	got := replayLifecycle(t, idx)
	if fmt.Sprint(got) != fmt.Sprint(wantRefusals) {
		t.Fatalf("SQL taxonomy drift: want %v got %v", wantRefusals, got)
	}
	first := snapshotRows(t, db)
	if first == "" {
		t.Fatal("lifecycle must have produced rows")
	}

	// THE REBUILD LAW: drop, replay the same sequence, byte-identical.
	if _, err := db.ExecContext(context.Background(), `DELETE FROM destinations`); err != nil {
		t.Fatal(err)
	}
	got2 := replayLifecycle(t, idx)
	if fmt.Sprint(got2) != fmt.Sprint(wantRefusals) {
		t.Fatalf("rebuild taxonomy drift: %v", got2)
	}
	second := snapshotRows(t, db)
	if first != second {
		t.Fatalf("REBUILD LAW BROKEN:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}
