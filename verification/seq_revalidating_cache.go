/*
FILE PATH: verification/seq_revalidating_cache.go

PRE-13b #181 — the adaptive log-sequence-revalidating cache that replaces the
delegation resolver's wall-clock TTL.

A TTL cache's defect is that it is keyed to a CLOCK: a revocation that lands
mid-window goes unseen until the timer expires. This cache is keyed to LOG
SEQUENCE instead. Each entry is tagged with the watermark (a log-sequence
position) it was computed at; a Get supplies the CURRENT watermark for that
key, and the entry is fresh only while the watermark has not advanced past it.

A revocation IS a log entry, so it advances the watermark at the position the
cached value depends on — which makes the entry a MISS and forces a recompute
from the log. The cache is invalidated by the TRUTH advancing, never by a
clock. This is "projections are caches of the log, keyed to log position" made
literal (Verify-Live-State / never-cache-truth), with no staleness window.

PER-KEY, NOT GLOBAL-HEAD: the watermark is supplied per key. With a per-DID
watermark (idx_delegate_did_latest's last-modified sequence for a delegate
DID), an unrelated append elsewhere in the log does NOT advance THIS key's
watermark, so the hit rate is preserved (O(1) on a truly-unchanged key) while
staying never-stale — a revocation cannot land at this key's position without
advancing its watermark and forcing the recompute. A global-head watermark
would instead revalidate on every unrelated entry and degrade the cache toward
a no-op; callers MUST pass the narrowest correct watermark.
*/
package verification

import "sync"

// SeqRevalidatingCache is a concurrency-safe cache whose entries are
// revalidated against a LOG-SEQUENCE watermark rather than a wall-clock timer.
// V is the cached value type; keys are strings (e.g. a delegate DID).
type SeqRevalidatingCache[V any] struct {
	mu      sync.Mutex
	entries map[string]revEntry[V]
}

// revEntry pairs a cached value with the watermark it was computed at.
type revEntry[V any] struct {
	val   V
	basis uint64 // the log-sequence watermark val is consistent with
}

// NewSeqRevalidatingCache builds an empty cache.
func NewSeqRevalidatingCache[V any]() *SeqRevalidatingCache[V] {
	return &SeqRevalidatingCache[V]{entries: make(map[string]revEntry[V])}
}

// Get returns the cached value for key iff it is still fresh at currentSeq —
// the watermark has not advanced past the basis the value was computed at
// (currentSeq <= basis). Because the watermark is monotonic and basis was a
// past reading, this is in practice "the key's watermark is unchanged." A
// miss (absent key, or watermark advanced) returns ok=false; the caller
// recomputes from the log and Sets with the fresh watermark.
func (c *SeqRevalidatingCache[V]) Get(key string, currentSeq uint64) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || currentSeq > e.basis {
		var zero V
		return zero, false
	}
	return e.val, true
}

// Set stores val for key, tagged with basis — the watermark the value is
// consistent with. Callers MUST read basis BEFORE computing val: if the
// watermark advances during the compute, the next Get sees currentSeq > basis
// and treats the entry as a miss, so a value computed against state that a
// concurrent revocation has already superseded is never served stale.
func (c *SeqRevalidatingCache[V]) Set(key string, val V, basis uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = revEntry[V]{val: val, basis: basis}
}

// Invalidate drops key. The watermark path makes this rarely necessary, but a
// caller with out-of-band knowledge of a change may force a miss.
func (c *SeqRevalidatingCache[V]) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Len reports the number of cached entries (introspection / tests).
func (c *SeqRevalidatingCache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
