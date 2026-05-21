package gossipfeed

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip"
)

// openTestStore connects to JN_TEST_DATABASE_URL, migrates, and truncates
// peer_gossip for isolation. Skips when no DB is configured so the suite
// stays green on hosts without Postgres.
func openTestStore(t *testing.T) *PostgresStore {
	t.Helper()
	dsn := os.Getenv("JN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("JN_TEST_DATABASE_URL not set; skipping Postgres integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	s, err := NewPostgresStore(db)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := db.Exec(`TRUNCATE peer_gossip`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return s
}

// signedChain produces n properly-chained signed events for one
// originator (real prev/lamport linkage via EventSigner).
func signedChain(t *testing.T, n int) (string, []gossip.SignedEvent) {
	t.Helper()
	key := mustGenKey(t)
	originator, err := DIDKeyForSigningKey(key)
	if err != nil {
		t.Fatalf("DIDKeyForSigningKey: %v", err)
	}
	es, err := NewEventSigner(cosign.NewECDSAWitnessSigner(key), cosign.NetworkID{1}, originator)
	if err != nil {
		t.Fatalf("NewEventSigner: %v", err)
	}
	ctx := context.Background()
	out := make([]gossip.SignedEvent, 0, n)
	for i := 0; i < n; i++ {
		ev, err := es.Sign(ctx, mustCTHFinding(t))
		if err != nil {
			t.Fatalf("sign #%d: %v", i, err)
		}
		out = append(out, ev)
	}
	return originator, out
}

func TestPostgresStore_AppendGet_EventIDStable(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, chain := signedChain(t, 1)
	ev := chain[0]

	if err := s.Append(ctx, ev); err != nil {
		t.Fatalf("Append: %v", err)
	}
	id, err := gossip.EventIDOf(ev)
	if err != nil {
		t.Fatalf("EventIDOf: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// The whole point of BYTEA-not-JSONB: the round-tripped event must
	// recompute the SAME EventID (signed Body bytes preserved exactly).
	gotID, err := gossip.EventIDOf(got)
	if err != nil {
		t.Fatalf("EventIDOf(got): %v", err)
	}
	if gotID != id {
		t.Fatalf("EventID drift after round-trip: stored %x got %x", id, gotID)
	}
}

func TestPostgresStore_AppendIdempotent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, chain := signedChain(t, 1)

	if err := s.Append(ctx, chain[0]); err != nil {
		t.Fatalf("first Append: %v", err)
	}
	if err := s.Append(ctx, chain[0]); err != nil {
		t.Fatalf("re-Append must be idempotent, got: %v", err)
	}
	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.EventCount != 1 {
		t.Fatalf("EventCount = %d, want 1 (idempotent)", st.EventCount)
	}
}

func TestPostgresStore_ChainBreak(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, chain := signedChain(t, 3)

	if err := s.Append(ctx, chain[0]); err != nil {
		t.Fatalf("Append e0: %v", err)
	}
	// chain[2].PrevHash points at chain[1], but the head is chain[0].
	err := s.Append(ctx, chain[2])
	if !errors.Is(err, gossip.ErrChainBreak) {
		t.Fatalf("want ErrChainBreak, got %v", err)
	}
}

func TestPostgresStore_LamportRegression(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, chain := signedChain(t, 2)

	if err := s.Append(ctx, chain[0]); err != nil {
		t.Fatalf("Append e0: %v", err)
	}
	// Forge an event that links correctly (prev = head) but does not
	// advance the Lamport clock. The store is dumb on signatures but
	// strict on chain order.
	regress := chain[1]
	regress.LamportTime = chain[0].LamportTime // <= head
	err := s.Append(ctx, regress)
	if !errors.Is(err, gossip.ErrLamportRegression) {
		t.Fatalf("want ErrLamportRegression, got %v", err)
	}
}

func TestPostgresStore_HeadAndGetNotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	originator, chain := signedChain(t, 2)
	for i, ev := range chain {
		if err := s.Append(ctx, ev); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}
	prev, lamport, err := s.Head(ctx, originator)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	wantID, _ := gossip.EventIDOf(chain[1])
	if prev != wantID {
		t.Fatalf("Head prev = %x, want %x (latest event)", prev, wantID)
	}
	if lamport != chain[1].LamportTime {
		t.Fatalf("Head lamport = %d, want %d", lamport, chain[1].LamportTime)
	}
	if _, err := s.Get(ctx, [32]byte{0xde, 0xad}); !errors.Is(err, gossip.ErrEventNotFound) {
		t.Fatalf("want ErrEventNotFound, got %v", err)
	}
}

func TestPostgresStore_IterSincePagination(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	originator, chain := signedChain(t, 3)
	for _, ev := range chain {
		if err := s.Append(ctx, ev); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	page1, next, err := s.IterSince(ctx, gossip.IterCursor{Originator: originator}, 2)
	if err != nil {
		t.Fatalf("IterSince p1: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("page1 len = %d, want 2", len(page1))
	}
	page2, _, err := s.IterSince(ctx, next, 2)
	if err != nil {
		t.Fatalf("IterSince p2: %v", err)
	}
	if len(page2) != 1 {
		t.Fatalf("page2 len = %d, want 1 (remaining)", len(page2))
	}
	if page2[0].LamportTime != chain[2].LamportTime {
		t.Fatalf("page2 event = lamport %d, want %d", page2[0].LamportTime, chain[2].LamportTime)
	}
}

func TestPostgresStore_LatestSTHAndStats(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	originator, chain := signedChain(t, 3)
	for _, ev := range chain {
		if err := s.Append(ctx, ev); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	sth, ok, err := s.LatestSTH(ctx, originator)
	if err != nil || !ok {
		t.Fatalf("LatestSTH: ok=%v err=%v", ok, err)
	}
	if sth.LamportTime != chain[2].LamportTime {
		t.Fatalf("LatestSTH lamport = %d, want %d (newest)", sth.LamportTime, chain[2].LamportTime)
	}
	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.EventCount != 3 || st.OriginatorCount != 1 {
		t.Fatalf("Stats = {events:%d origins:%d}, want {3,1}", st.EventCount, st.OriginatorCount)
	}
	if st.Heads[originator] != chain[2].LamportTime {
		t.Fatalf("Heads[%s] = %d, want %d", originator, st.Heads[originator], chain[2].LamportTime)
	}
}

func TestPostgresStore_Prune(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, chain := signedChain(t, 1)
	if err := s.Append(ctx, chain[0]); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// Disabled / nothing-old-enough are no-ops.
	if n, err := s.Prune(ctx, 0); err != nil || n != 0 {
		t.Fatalf("Prune(0) = (%d,%v), want (0,nil)", n, err)
	}
	if n, err := s.Prune(ctx, 36500); err != nil || n != 0 {
		t.Fatalf("Prune(36500) = (%d,%v), want (0,nil)", n, err)
	}
	// Backdate the row, then a 30-day retention must reap it.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE peer_gossip SET inserted_at = now() - interval '60 days'`); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	n, err := s.Prune(ctx, 30)
	if err != nil || n != 1 {
		t.Fatalf("Prune(30) = (%d,%v), want (1,nil)", n, err)
	}
}
