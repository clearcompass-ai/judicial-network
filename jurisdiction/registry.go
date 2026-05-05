/*
FILE PATH: jurisdiction/registry.go

DESCRIPTION:

	Registry — the per-process map from ExchangeDID to Bundle.
	Multi-exchange networks register one Bundle per court system at
	boot; the verifier and aggregator resolve the right Bundle from
	the entry's destination DID before evaluating any rules.

	Why a registry, not a single global Bundle: per the v1.6
	invariant a network may host multiple exchanges (Davidson,
	Shelby, etc.). Each ships its own catalog + policies. The
	registry is the single seam at which a request "this entry
	targets exchange X" turns into "use Bundle X's vocabulary."

	The registry is NOT thread-mutable after Freeze. Production
	callers register Bundles at startup, call Freeze, and then
	handle requests concurrently. Tests can omit Freeze.

OVERVIEW:

	Registry      — mutex-protected map[ExchangeDID]Bundle.
	NewRegistry   — empty registry.
	Register      — add Bundle (validates first).
	Bundle        — lookup by ExchangeDID.
	ExchangeDIDs  — sorted list of registered DIDs.
	Freeze        — disables further mutation; subsequent Register
	                calls return ErrRegistryFrozen.
	Sentinels.

KEY DEPENDENCIES:
  - jurisdiction/bundle.go (Bundle, Validate).
*/
package jurisdiction

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ─── Sentinels ──────────────────────────────────────────────────────

var (
	// ErrUnknownExchange signals a Bundle lookup miss.
	ErrUnknownExchange = errors.New("jurisdiction: unknown exchange")

	// ErrDuplicateExchange signals a second Register call with the
	// same ExchangeDID. Re-registration is forbidden — replacing a
	// jurisdiction's policy at runtime would defeat the closed-set
	// guarantee. Use a fresh process for policy updates.
	ErrDuplicateExchange = errors.New("jurisdiction: exchange already registered")

	// ErrRegistryFrozen signals a mutation attempt after Freeze.
	ErrRegistryFrozen = errors.New("jurisdiction: registry is frozen")
)

// ─── Registry ──────────────────────────────────────────────────────

// Registry maps ExchangeDID → Bundle. Safe for concurrent reads
// after Freeze; the mutex covers the Register/Freeze transition
// for tests that build the registry from multiple goroutines.
type Registry struct {
	mu     sync.RWMutex
	m      map[string]Bundle
	frozen bool
}

// NewRegistry returns an empty mutable registry.
func NewRegistry() *Registry {
	return &Registry{m: make(map[string]Bundle)}
}

// Register validates b, then inserts it under b.ExchangeDID().
// Returns:
//   - ErrInvalidBundle  when Validate fails.
//   - ErrDuplicateExchange  when ExchangeDID is already registered.
//   - ErrRegistryFrozen  when Freeze has been called.
func (r *Registry) Register(b Bundle) error {
	if err := Validate(b); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return fmt.Errorf("%w: cannot register %s",
			ErrRegistryFrozen, b.ExchangeDID())
	}
	did := b.ExchangeDID()
	if _, exists := r.m[did]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateExchange, did)
	}
	r.m[did] = b
	return nil
}

// Bundle returns the registered Bundle for exchangeDID. Returns
// ErrUnknownExchange when not registered.
func (r *Registry) Bundle(exchangeDID string) (Bundle, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.m[exchangeDID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownExchange, exchangeDID)
	}
	return b, nil
}

// ExchangeDIDs returns a sorted snapshot of registered DIDs.
// Used by health-check / audit paths.
func (r *Registry) ExchangeDIDs() []string {
	r.mu.RLock()
	out := make([]string, 0, len(r.m))
	for did := range r.m {
		out = append(out, did)
	}
	r.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Freeze disables further Register calls. Idempotent.
func (r *Registry) Freeze() {
	r.mu.Lock()
	r.frozen = true
	r.mu.Unlock()
}

// IsFrozen reports the registry's mutation state. Mostly useful
// for diagnostics; Register's error already surfaces the state.
func (r *Registry) IsFrozen() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.frozen
}

// Len reports the number of registered Bundles.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.m)
}
