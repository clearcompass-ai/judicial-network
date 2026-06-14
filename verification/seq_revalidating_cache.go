/*
FILE PATH: verification/seq_revalidating_cache.go

PRE-13b #181 — the adaptive log-sequence-revalidating cache that replaces the
delegation resolver's wall-clock TTL.

A TTL cache's defect is that it is keyed to a CLOCK: a revocation that lands
mid-window goes unseen until the timer expires. This cache is keyed to LOG
SEQUENCE instead. Each entry is tagged with the revalidation FINGERPRINT — a
log-sequence position the value derives from — at compute time; a Get supplies
the CURRENT fingerprint for that key, and the entry is fresh only while that
fingerprint is UNCHANGED.

A delegation change IS a log entry, so it moves the fingerprint at the position
the cached value depends on — a new grant raises it, a revocation that drops
the delegate's newest-live delegation lowers it — and EITHER move makes the
entry a MISS that forces a recompute from the log. The match is therefore EXACT
(unchanged), not "has-not-advanced": the per-key fingerprint is non-monotonic
under revocation. The cache is invalidated by the TRUTH moving, never by a clock
— "projections are caches of the log, keyed to log position" made literal
(Verify-Live-State / never-cache-truth), with no staleness window.

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

// Get returns the cached value for key iff its revalidation fingerprint is
// UNCHANGED at currentSeq (currentSeq == basis). The match is EXACT, not
// "has-not-advanced": a per-key fingerprint such as a delegate DID's
// newest-live delegation sequence is non-monotonic — a revocation that drops
// that delegation lowers it — so any move (up from a new grant, or down from a
// revocation) is a miss. The caller recomputes from the log and Sets with the
// fresh fingerprint.
func (c *SeqRevalidatingCache[V]) Get(key string, currentSeq uint64) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || currentSeq != e.basis {
		var zero V
		return zero, false
	}
	return e.val, true
}

// Set stores val for key, tagged with basis — the revalidation fingerprint the
// value derives from (e.g. the delegate DID's newest-live delegation sequence).
// Callers MUST read basis BEFORE computing val: if the fingerprint moves during
// the compute, the next Get sees currentSeq != basis and treats the entry as a
// miss, so a value computed against state that a concurrent grant or revocation
// has already changed is never served stale.
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
