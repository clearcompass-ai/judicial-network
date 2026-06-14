package verification

import (
	"sync"
	"testing"
)

// TestSeqRevalidatingCache_NeverStale pins the core contract: a value is a HIT
// only while its per-key watermark is unchanged, and a MISS the instant the
// watermark advances — the cache is invalidated by the log advancing, never by
// a clock.
func TestSeqRevalidatingCache_NeverStale(t *testing.T) {
	c := NewSeqRevalidatingCache[string]()

	// Absent → miss.
	if _, ok := c.Get("did:a", 10); ok {
		t.Fatal("absent key must miss")
	}

	// Computed at watermark 10.
	c.Set("did:a", "chain-v1", 10)

	// Same watermark → hit.
	if v, ok := c.Get("did:a", 10); !ok || v != "chain-v1" {
		t.Fatalf("unchanged watermark must hit with the stored value, got (%q,%v)", v, ok)
	}

	// Watermark advanced (a delegation/revocation landed for this DID) → miss.
	if _, ok := c.Get("did:a", 11); ok {
		t.Fatal("advanced watermark must miss (never serve a value computed against a stale head)")
	}

	// Recompute + Set at the new watermark → hit again at that watermark.
	c.Set("did:a", "chain-v2", 11)
	if v, ok := c.Get("did:a", 11); !ok || v != "chain-v2" {
		t.Fatalf("recompute at fresh watermark must hit, got (%q,%v)", v, ok)
	}
}

// TestSeqRevalidatingCache_PerKeyIndependence proves the per-DID watermark
// property: advancing one key's watermark does NOT invalidate another key —
// an unrelated append elsewhere in the log leaves untouched chains cached.
// This is what keeps the hit rate up versus a global-head watermark.
func TestSeqRevalidatingCache_PerKeyIndependence(t *testing.T) {
	c := NewSeqRevalidatingCache[int]()
	c.Set("did:a", 1, 100)
	c.Set("did:b", 2, 100)

	// did:a's watermark advances (its delegation changed); did:b's did not.
	if _, ok := c.Get("did:a", 101); ok {
		t.Fatal("did:a must miss after its own watermark advanced")
	}
	if v, ok := c.Get("did:b", 100); !ok || v != 2 {
		t.Fatal("did:b must still hit — an unrelated key's advance is not its own")
	}
}

// TestSeqRevalidatingCache_SetRefreshesBasis confirms a re-Set moves the basis
// forward, so a value cached at an older watermark cannot linger.
func TestSeqRevalidatingCache_SetRefreshesBasis(t *testing.T) {
	c := NewSeqRevalidatingCache[string]()
	c.Set("k", "old", 5)
	c.Set("k", "new", 9)
	if _, ok := c.Get("k", 6); !ok {
		t.Fatal("watermark 6 <= basis 9 must hit after the refresh")
	}
	if v, _ := c.Get("k", 9); v != "new" {
		t.Fatalf("re-Set must overwrite the value, got %q", v)
	}
	if _, ok := c.Get("k", 10); ok {
		t.Fatal("watermark past the refreshed basis must miss")
	}
}

// TestSeqRevalidatingCache_Invalidate covers the explicit eviction path.
func TestSeqRevalidatingCache_Invalidate(t *testing.T) {
	c := NewSeqRevalidatingCache[int]()
	c.Set("k", 7, 3)
	c.Invalidate("k")
	if _, ok := c.Get("k", 3); ok {
		t.Fatal("Invalidate must force a miss even at the original watermark")
	}
	if c.Len() != 0 {
		t.Fatalf("Len after Invalidate = %d, want 0", c.Len())
	}
}

// TestSeqRevalidatingCache_Concurrent is the -race guard: concurrent readers
// and writers across keys must not corrupt the map or the basis bookkeeping.
func TestSeqRevalidatingCache_Concurrent(t *testing.T) {
	c := NewSeqRevalidatingCache[int]()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := "did:" + string(rune('a'+id))
			for seq := uint64(0); seq < 500; seq++ {
				c.Set(key, int(seq), seq)
				_, _ = c.Get(key, seq)
				_, _ = c.Get(key, seq+1) // forces the advanced-watermark path
			}
		}(i)
	}
	wg.Wait()
}
