package runner

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "verify.walgc", Tags: []string{"verify", "walgc", "slow"}, Run: verifyWALGC})
}

const gcReclaimLog = "wal retention GC reclaimed"

// verify.walgc (SLOW): validate WAL retention GC end-to-end against a ledger
// brought up with retention on (E2E_WAL_RETENTION_BUFFER=N). It loads TWO batches
// and pins the bounded-footprint contract:
//   - GC actually runs and DELETES shipped WAL entries — the ledger logs
//     "wal retention GC reclaimed" only when it removes entries;
//   - the WAL on-disk footprint stays BOUNDED as entries accumulate: doubling the
//     entry count does NOT ~double baseproof_wal_disk_bytes (the work-driven GC
//     holds it near the retention margin); without GC the second batch would
//     roughly double it;
//   - a below-cutoff entry GC'd from the WAL STILL resolves from the object store
//     (the cold-read safety contract — GC bounds the footprint, loses nothing).
//
// A stack brought up without a retention buffer SKIPS (no-op, not a failure).
func verifyWALGC(s *Session) error {
	buffer := s.Manifest.WALRetentionBuffer
	if buffer == 0 {
		fmt.Println("== verify.walgc SKIPPED: bring the stack up with E2E_WAL_RETENTION_BUFFER=N to enable WAL GC ==")
		return nil
	}
	t, ok := s.Target("")
	if !ok {
		return fmt.Errorf("no network in the persisted manifest")
	}

	// Load >> the buffer so most entries age past the margin and GC has repeated work.
	m := intEnv("E2E_WALGC_ENTRIES", 800)
	if uint64(m) < buffer*4 {
		m = int(buffer * 4)
	}
	gcTimeout := time.Duration(intEnv("E2E_WALGC_TIMEOUT_MIN", 4)) * time.Minute

	// ── Phase 1: load, fully ship, observe a GC reclaim, measure the footprint.
	reclaims0 := stack.LedgerLogCount(t.LedgerName, gcReclaimLog)
	if err := walgcLoad(t, s.Images.Ledger, m); err != nil {
		return fmt.Errorf("phase 1: %w", err)
	}
	if err := waitWALBacklogDrained(t, gcTimeout); err != nil {
		return fmt.Errorf("phase 1: %w", err)
	}
	if err := waitGCReclaim(t, reclaims0, gcTimeout); err != nil {
		return fmt.Errorf("phase 1: %w", err)
	}
	d1, ok := stack.WALDiskBytes(t.CertsDir, t.LedgerPort)
	if !ok || d1 <= 0 {
		return fmt.Errorf("phase 1: baseproof_wal_disk_bytes gauge absent or non-positive (%d)", d1)
	}
	reclaims1 := stack.LedgerLogCount(t.LedgerName, gcReclaimLog)

	// ── Phase 2: load AS MANY MORE, fully ship, observe another reclaim, re-measure.
	if err := walgcLoad(t, s.Images.Ledger, m); err != nil {
		return fmt.Errorf("phase 2: %w", err)
	}
	if err := waitWALBacklogDrained(t, gcTimeout); err != nil {
		return fmt.Errorf("phase 2: %w", err)
	}
	if err := waitGCReclaim(t, reclaims1, gcTimeout); err != nil {
		return fmt.Errorf("phase 2: %w", err)
	}
	d2, ok := stack.WALDiskBytes(t.CertsDir, t.LedgerPort)
	if !ok {
		return fmt.Errorf("phase 2: baseproof_wal_disk_bytes gauge absent")
	}

	// 1) Footprint BOUNDED: 2× the entries must NOT ~2× the WAL — GC holds it near
	//    the margin (both readings taken with the backlog drained, so they reflect
	//    only retained bytes). Without GC the second batch roughly doubles d1.
	const boundFactor = 1.5
	if float64(d2) > float64(d1)*boundFactor {
		return fmt.Errorf("WAL footprint NOT bounded: %d → %d bytes after a 2nd batch of %d entries (>%.2gx) — GC is not holding the footprint", d1, d2, m, boundFactor)
	}
	// 2) A below-cutoff entry (far past HWM-buffer) was GC'd from the WAL but still
	//    resolves from the object store. seq 2 is the first backfilled entry.
	const survivor = 2
	if !stack.RawEntryResolves(t.CertsDir, t.LedgerPort, survivor) {
		return fmt.Errorf("a below-cutoff entry (seq %d) no longer resolves via /raw after GC — cold-read safety broken", survivor)
	}

	fmt.Printf("  [PASS] WAL GC bounded the footprint (%d → %d bytes over 2×%d entries, buffer=%d) + a GC'd entry still resolves\n", d1, d2, m, buffer)
	return nil
}

// walgcLoad backfills n root entries on the writer and waits for the committed
// head to include them (absolute target — robust on a reused stack).
func walgcLoad(t stack.Target, image string, n int) error {
	before, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
	st, err := stack.Backfill(t, image, n, 8, 0.0, 1)
	if err != nil {
		return fmt.Errorf("backfill: %w", err)
	}
	if !stack.WaitDrained(t.CertsDir, t.LedgerPort, before+st.Roots,
		time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 15))*time.Minute) {
		return fmt.Errorf("backfill did not drain (raise E2E_DRAIN_TIMEOUT_MIN)")
	}
	return nil
}

// waitWALBacklogDrained waits until everything sequenced is shipped (backlog 0),
// so the next disk reading reflects only the retained margin, not in-flight bytes.
func waitWALBacklogDrained(t stack.Target, timeout time.Duration) error {
	if pollFor(timeout, func() bool {
		b, ok := stack.WALBacklog(t.CertsDir, t.LedgerPort)
		return ok && b == 0
	}) {
		return nil
	}
	return fmt.Errorf("WAL backlog never drained to 0 within %s", timeout)
}

// waitGCReclaim waits until the ledger logs a NEW "wal retention GC reclaimed"
// (count rises above `from`) — the deterministic proof GC ran AND deleted entries.
func waitGCReclaim(t stack.Target, from int, timeout time.Duration) error {
	if pollFor(timeout, func() bool {
		return stack.LedgerLogCount(t.LedgerName, gcReclaimLog) > from
	}) {
		return nil
	}
	return fmt.Errorf("WAL GC never reclaimed entries within %s (no new %q past count %d) — is shipping advancing the HWM past the buffer?", timeout, gcReclaimLog, from)
}

// pollFor calls fn every 2s until it returns true or timeout elapses.
func pollFor(timeout time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if fn() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Second)
	}
}
