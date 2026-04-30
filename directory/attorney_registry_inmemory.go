/*
FILE PATH: directory/attorney_registry_inmemory.go

DESCRIPTION:
    InMemoryAttorneys method implementations. Split out of
    attorney_registry.go to keep that file focused on the type
    surface.

OVERVIEW:
    Lookup / LookupByAlias / LookupByBarNumber / Register / Update /
    Suspend / Restore / Retire / Revoke / List / ListByType.

KEY DEPENDENCIES:
    - directory/attorney_registry.go (Attorney, AttorneyRegistry,
      sentinels).
*/
package directory

import (
	"fmt"
	"sort"
)

// ─── lookups ────────────────────────────────────────────────────────

func (r *InMemoryAttorneys) Lookup(id string) (*Attorney, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w: id=%s", ErrAttorneyNotFound, id)
	}
	cp := *a
	return &cp, nil
}

func (r *InMemoryAttorneys) LookupByAlias(alias string) (*Attorney, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byAlias[alias]
	if !ok {
		return nil, fmt.Errorf("%w: alias=%s", ErrAttorneyNotFound, alias)
	}
	cp := *r.byID[id]
	return &cp, nil
}

func (r *InMemoryAttorneys) LookupByBarNumber(barNumber string) (*Attorney, error) {
	if barNumber == "" {
		return nil, fmt.Errorf("%w: empty bar_number", ErrAttorneyNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byBarNumber[barNumber]
	if !ok {
		return nil, fmt.Errorf("%w: bar_number=%s", ErrAttorneyNotFound, barNumber)
	}
	cp := *r.byID[id]
	return &cp, nil
}

// ─── Register / Update ──────────────────────────────────────────────

func (r *InMemoryAttorneys) Register(a Attorney) error {
	if err := validateAttorney(a); err != nil {
		return err
	}
	if a.Status == "" {
		a.Status = AttorneyActive
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, dup := r.byID[a.ID]; dup {
		return fmt.Errorf("%w: id=%s", ErrAttorneyExists, a.ID)
	}
	if existingID, taken := r.byAlias[a.Alias]; taken {
		return fmt.Errorf("%w: alias=%s already maps to id=%s",
			ErrAliasTaken, a.Alias, existingID)
	}
	if a.BarNumber != "" {
		if existingID, taken := r.byBarNumber[a.BarNumber]; taken {
			return fmt.Errorf("%w: bar_number=%s already maps to id=%s",
				ErrBarNumberTaken, a.BarNumber, existingID)
		}
	}

	now := r.nowFn()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	a.UpdatedAt = now

	stored := a
	r.byID[a.ID] = &stored
	r.byAlias[a.Alias] = a.ID
	if a.BarNumber != "" {
		r.byBarNumber[a.BarNumber] = a.ID
	}
	return nil
}

func (r *InMemoryAttorneys) Update(a Attorney) error {
	if err := validateAttorney(a); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	existing, ok := r.byID[a.ID]
	if !ok {
		return fmt.Errorf("%w: id=%s", ErrAttorneyNotFound, a.ID)
	}

	desired := a.Status
	if desired == "" {
		desired = existing.Status
	}
	if existing.Status.IsTerminal() && desired == AttorneyActive {
		return fmt.Errorf("%w: id=%s already %s; cannot reactivate",
			ErrIllegalAttorneyTransition, a.ID, existing.Status)
	}

	if a.Alias != existing.Alias {
		if otherID, taken := r.byAlias[a.Alias]; taken && otherID != a.ID {
			return fmt.Errorf("%w: alias=%s already maps to id=%s",
				ErrAliasTaken, a.Alias, otherID)
		}
		delete(r.byAlias, existing.Alias)
		r.byAlias[a.Alias] = a.ID
	}
	if a.BarNumber != existing.BarNumber {
		if a.BarNumber != "" {
			if otherID, taken := r.byBarNumber[a.BarNumber]; taken && otherID != a.ID {
				return fmt.Errorf("%w: bar_number=%s already maps to id=%s",
					ErrBarNumberTaken, a.BarNumber, otherID)
			}
			r.byBarNumber[a.BarNumber] = a.ID
		}
		if existing.BarNumber != "" {
			delete(r.byBarNumber, existing.BarNumber)
		}
	}

	stored := a
	stored.Status = desired
	stored.CreatedAt = existing.CreatedAt
	stored.UpdatedAt = r.nowFn()
	r.byID[a.ID] = &stored
	return nil
}

// ─── status transitions ─────────────────────────────────────────────

func (r *InMemoryAttorneys) Suspend(id string, reason string) error {
	if reason == "" {
		return fmt.Errorf("%w: suspension reason required", ErrInvalidAttorney)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.byID[id]
	if !ok {
		return fmt.Errorf("%w: id=%s", ErrAttorneyNotFound, id)
	}
	if a.Status.IsTerminal() {
		return fmt.Errorf("%w: id=%s already %s; cannot suspend",
			ErrIllegalAttorneyTransition, id, a.Status)
	}
	cp := *a
	cp.Status = AttorneySuspended
	cp.SuspensionReason = reason
	cp.UpdatedAt = r.nowFn()
	r.byID[id] = &cp
	return nil
}

func (r *InMemoryAttorneys) Restore(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.byID[id]
	if !ok {
		return fmt.Errorf("%w: id=%s", ErrAttorneyNotFound, id)
	}
	if a.Status != AttorneySuspended {
		return fmt.Errorf("%w: id=%s status %s (Restore requires suspended)",
			ErrIllegalAttorneyTransition, id, a.Status)
	}
	cp := *a
	cp.Status = AttorneyActive
	cp.SuspensionReason = ""
	cp.UpdatedAt = r.nowFn()
	r.byID[id] = &cp
	return nil
}

func (r *InMemoryAttorneys) Retire(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.byID[id]
	if !ok {
		return fmt.Errorf("%w: id=%s", ErrAttorneyNotFound, id)
	}
	if a.Status == AttorneyRevoked {
		return fmt.Errorf("%w: id=%s already revoked; cannot retire",
			ErrIllegalAttorneyTransition, id)
	}
	cp := *a
	cp.Status = AttorneyRetired
	cp.UpdatedAt = r.nowFn()
	r.byID[id] = &cp
	return nil
}

func (r *InMemoryAttorneys) Revoke(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.byID[id]
	if !ok {
		return fmt.Errorf("%w: id=%s", ErrAttorneyNotFound, id)
	}
	if a.Status == AttorneyRetired {
		return fmt.Errorf("%w: id=%s already retired; cannot revoke",
			ErrIllegalAttorneyTransition, id)
	}
	cp := *a
	cp.Status = AttorneyRevoked
	cp.UpdatedAt = r.nowFn()
	r.byID[id] = &cp
	return nil
}

// ─── listing ────────────────────────────────────────────────────────

func (r *InMemoryAttorneys) List() []*Attorney {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Attorney, 0, len(r.byID))
	for _, a := range r.byID {
		cp := *a
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r *InMemoryAttorneys) ListByType(t AttorneyType) []*Attorney {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Attorney, 0)
	for _, a := range r.byID {
		if a.Type != t {
			continue
		}
		cp := *a
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
