/*
FILE PATH: directory/officer_registry_inmemory.go

DESCRIPTION:
    InMemoryRegistry method implementations. Split out of
    officer_registry.go to keep that file focused on the type
    surface.

OVERVIEW:
    Lookup / LookupByAlias / Add / Update / MarkRevoked /
    MarkSucceeded / List / ListByRole — Registry interface methods.

KEY DEPENDENCIES:
    - directory/officer_registry.go (Officer, Registry, errors).
*/
package directory

import (
	"fmt"
	"sort"
)

// Lookup returns the Officer record for did.
func (r *InMemoryRegistry) Lookup(did string) (*Officer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	o, ok := r.byDID[did]
	if !ok {
		return nil, fmt.Errorf("%w: did=%s", ErrOfficerNotFound, did)
	}
	cp := *o
	return &cp, nil
}

// LookupByAlias returns the Officer record by alias.
func (r *InMemoryRegistry) LookupByAlias(alias string) (*Officer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	did, ok := r.byAlias[alias]
	if !ok {
		return nil, fmt.Errorf("%w: alias=%s", ErrOfficerNotFound, alias)
	}
	o := r.byDID[did]
	cp := *o
	return &cp, nil
}

// Add inserts a new record. Returns ErrOfficerExists on duplicate
// DID, ErrAliasTaken on duplicate alias.
func (r *InMemoryRegistry) Add(o Officer) error {
	if err := validateOfficer(o); err != nil {
		return err
	}
	if o.Status == "" {
		o.Status = StatusActive
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, dup := r.byDID[o.DID]; dup {
		return fmt.Errorf("%w: did=%s", ErrOfficerExists, o.DID)
	}
	if existingDID, taken := r.byAlias[o.Alias]; taken {
		return fmt.Errorf("%w: alias=%s already maps to did=%s",
			ErrAliasTaken, o.Alias, existingDID)
	}

	now := r.nowFn()
	if o.CreatedAt.IsZero() {
		o.CreatedAt = now
	}
	o.UpdatedAt = now

	stored := o
	r.byDID[o.DID] = &stored
	r.byAlias[o.Alias] = o.DID
	return nil
}

// Update replaces a record by DID. Status is preserved unless the
// caller sets it explicitly. The registry refuses to rewind a
// terminal status.
func (r *InMemoryRegistry) Update(o Officer) error {
	if err := validateOfficer(o); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	existing, ok := r.byDID[o.DID]
	if !ok {
		return fmt.Errorf("%w: did=%s", ErrOfficerNotFound, o.DID)
	}

	// Status: caller's value takes precedence when set; otherwise
	// preserve existing. Refuse to rewind from terminal.
	desired := o.Status
	if desired == "" {
		desired = existing.Status
	}
	if isTerminal(existing.Status) && desired == StatusActive {
		return fmt.Errorf("%w: cannot un-revoke / un-succeed did=%s",
			ErrIllegalTransition, o.DID)
	}

	// Alias change: confirm not in use by another DID.
	if o.Alias != existing.Alias {
		if otherDID, taken := r.byAlias[o.Alias]; taken && otherDID != o.DID {
			return fmt.Errorf("%w: alias=%s already maps to did=%s",
				ErrAliasTaken, o.Alias, otherDID)
		}
		delete(r.byAlias, existing.Alias)
		r.byAlias[o.Alias] = o.DID
	}

	stored := o
	stored.Status = desired
	stored.CreatedAt = existing.CreatedAt
	stored.UpdatedAt = r.nowFn()
	r.byDID[o.DID] = &stored
	return nil
}

// MarkRevoked transitions did's status to StatusRevoked.
func (r *InMemoryRegistry) MarkRevoked(did string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.byDID[did]
	if !ok {
		return fmt.Errorf("%w: did=%s", ErrOfficerNotFound, did)
	}
	if o.Status == StatusSucceeded {
		return fmt.Errorf("%w: did=%s already succeeded; cannot revoke",
			ErrIllegalTransition, did)
	}
	cp := *o
	cp.Status = StatusRevoked
	cp.UpdatedAt = r.nowFn()
	r.byDID[did] = &cp
	return nil
}

// MarkSucceeded transitions did's status to StatusSucceeded with
// the given successor DID.
func (r *InMemoryRegistry) MarkSucceeded(did string, successorDID string) error {
	if successorDID == "" {
		return fmt.Errorf("%w: successor_did required", ErrInvalidOfficer)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.byDID[did]
	if !ok {
		return fmt.Errorf("%w: did=%s", ErrOfficerNotFound, did)
	}
	if o.Status == StatusRevoked {
		return fmt.Errorf("%w: did=%s already revoked; cannot succeed",
			ErrIllegalTransition, did)
	}
	cp := *o
	cp.Status = StatusSucceeded
	cp.SuccessorDID = successorDID
	cp.UpdatedAt = r.nowFn()
	r.byDID[did] = &cp
	return nil
}

// List returns all records sorted by DID.
func (r *InMemoryRegistry) List() []*Officer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Officer, 0, len(r.byDID))
	for _, o := range r.byDID {
		cp := *o
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DID < out[j].DID })
	return out
}

// ListByRole returns all records whose Role equals role, sorted by DID.
func (r *InMemoryRegistry) ListByRole(role string) []*Officer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Officer, 0)
	for _, o := range r.byDID {
		if o.Role != role {
			continue
		}
		cp := *o
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DID < out[j].DID })
	return out
}

// Static check that InMemoryRegistry satisfies Registry.
var _ Registry = (*InMemoryRegistry)(nil)
