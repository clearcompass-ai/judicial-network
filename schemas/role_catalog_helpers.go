/*
FILE PATH: schemas/role_catalog_helpers.go

DESCRIPTION:

	Pure helpers used by the catalog: per-role structural validator
	and two set-arithmetic primitives. Split out of role_catalog.go
	so that file can stay focused on the public interface and
	InMemoryCatalog implementation.

OVERVIEW:

	validateRole          — structural sanity for a single Role.
	roleAllowedToDelegate — wildcard-aware membership test.
	subset                — ordered-list ⊆ ordered-list.
*/
package schemas

import "fmt"

// validateRole runs structural sanity on a single Role definition.
// Used by NewInMemoryCatalog and Replace before installing.
func validateRole(r Role) error {
	if r.Name == "" {
		return fmt.Errorf("schemas/role_catalog: role name required")
	}
	if err := validateActor(r.Actor); err != nil {
		return fmt.Errorf("schemas/role_catalog: role %q: %w", r.Name, err)
	}
	if r.Actor != ActorSigner {
		return fmt.Errorf("schemas/role_catalog: role %q actor=%s; the catalog only lists ActorSigner (key-holding) roles — ActorFiler attestations live in the payload's filed_by_capacity block",
			r.Name, r.Actor.String())
	}
	if r.MaxDuration <= 0 {
		return fmt.Errorf("schemas/role_catalog: role %q max_duration must be > 0", r.Name)
	}
	if r.DefaultDuration <= 0 {
		return fmt.Errorf("schemas/role_catalog: role %q default_duration must be > 0", r.Name)
	}
	if r.DefaultDuration > r.MaxDuration {
		return fmt.Errorf("schemas/role_catalog: role %q default_duration %s exceeds max_duration %s",
			r.Name, r.DefaultDuration, r.MaxDuration)
	}
	if len(r.AllowedScope) == 0 {
		return fmt.Errorf("schemas/role_catalog: role %q allowed_scope required", r.Name)
	}
	if len(r.DefaultScope) == 0 {
		return fmt.Errorf("schemas/role_catalog: role %q default_scope required", r.Name)
	}
	if !subset(r.DefaultScope, r.AllowedScope) {
		return fmt.Errorf("schemas/role_catalog: role %q default_scope %v not subset of allowed_scope %v",
			r.Name, r.DefaultScope, r.AllowedScope)
	}
	if len(r.DelegableScope) > 0 && !subset(r.DelegableScope, r.AllowedScope) {
		return fmt.Errorf("schemas/role_catalog: role %q delegable_scope %v not subset of allowed_scope %v",
			r.Name, r.DelegableScope, r.AllowedScope)
	}
	return nil
}

// roleAllowedToDelegate returns true iff granter is in delegableBy or
// delegableBy contains the wildcard "*".
func roleAllowedToDelegate(granter string, delegableBy []string) bool {
	for _, d := range delegableBy {
		if d == "*" || d == granter {
			return true
		}
	}
	return false
}

// subset reports whether every token in a is in b.
func subset(a, b []string) bool {
	if len(a) == 0 {
		return true
	}
	idx := make(map[string]struct{}, len(b))
	for _, t := range b {
		idx[t] = struct{}{}
	}
	for _, t := range a {
		if _, ok := idx[t]; !ok {
			return false
		}
	}
	return true
}
