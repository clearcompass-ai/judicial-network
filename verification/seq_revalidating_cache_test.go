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

	// Fingerprint moved UP (a new grant landed for this DID) → miss.
	if _, ok := c.Get("did:a", 11); ok {
		t.Fatal("a raised fingerprint must miss (a new grant — never serve the prior chain)")
	}

	// Fingerprint moved DOWN (the newest-live delegation was REVOKED, so an
	// older entry is now newest) → miss. This is the non-monotonic case that
	// a "has-not-advanced" (<=) test would WRONGLY serve stale.
	if _, ok := c.Get("did:a", 9); ok {
		t.Fatal("a lowered fingerprint (revocation dropped the newest grant) must miss — exact match, not <=")
	}

	// Recompute + Set at the new fingerprint → hit again at that fingerprint.
	c.Set("did:a", "chain-v2", 11)
	if v, ok := c.Get("did:a", 11); !ok || v != "chain-v2" {
		t.Fatalf("recompute at the fresh fingerprint must hit, got (%q,%v)", v, ok)
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

// TestSeqRevalidatingCache_SetRefreshesBasis confirms a re-Set rebinds both the
// value and the fingerprint, so a hit requires the NEW fingerprint and the old
// one no longer matches.
func TestSeqRevalidatingCache_SetRefreshesBasis(t *testing.T) {
	c := NewSeqRevalidatingCache[string]()
	c.Set("k", "old", 5)
	if v, ok := c.Get("k", 5); !ok || v != "old" {
		t.Fatalf("original fingerprint must hit with the original value, got (%q,%v)", v, ok)
	}
	c.Set("k", "new", 9)
	if v, ok := c.Get("k", 9); !ok || v != "new" {
		t.Fatalf("re-Set must rebind value+fingerprint; want new@9, got (%q,%v)", v, ok)
	}
	if _, ok := c.Get("k", 5); ok {
		t.Fatal("the old fingerprint must no longer hit after the refresh")
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
