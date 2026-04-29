/*
FILE PATH: schemas/role_catalog.go

DESCRIPTION:
    Programmatic role catalog. Roles are *not* hard-coded constants;
    they are entries in a court-controlled config that the catalog
    loads at startup (and reloads on signal). Adding a role is a
    config change, not a JN code change, not a schema migration.

    A Role describes:
        - what scope tokens a holder *may* be granted (AllowedScope)
        - what scope tokens are granted by default (DefaultScope)
        - the maximum duration of a delegation in this role (MaxDuration)
        - which roles are permitted to *grant* this role (DelegableBy)
        - which scope tokens may be passed downstream (DelegableScope,
          i.e. what slice of AllowedScope a holder of this role may
          re-delegate to a deputy/subordinate)

    The on-log JudicialDelegationPayload references a Role by name.
    AuthorityResolver and IssueDelegation consult the catalog to
    decide whether the proposed (granter_role, grantee_role,
    requested_scope, requested_duration) tuple is permissible.

KEY ARCHITECTURAL DECISIONS:
    - Catalog is read-mostly. Implementations are RWMutex-protected.
    - The on-log truth never mentions catalog internals; only role
      name + concrete scope tokens. If the catalog is reloaded the
      *log* is unchanged. AuthorityResolver evaluates a delegation
      against whatever catalog the verifying node currently runs;
      a node out of date may produce a different verdict than a
      node up-to-date — this is intentional. Catalog drift is
      auditable: every node logs (catalog_version_hash, decision)
      pairs, and a periodic reconciliation run flags any
      disagreement.
    - "DelegableBy" supports a single special token "*" meaning
      "any role with the appropriate invite:* scope." This avoids
      a maintenance trap where every role must enumerate every
      delegable parent. The chain-walking enforcer (scope_enforcement)
      still intersects scope tokens, so "*" alone is not a back door.
    - The default fixture (DavidsonRoles) bakes in the reference
      Davidson County hierarchy. Tests use it; production loads from
      file (see role_catalog_yaml.go).

OVERVIEW:
    Role          — typed description of one role.
    RoleCatalog   — interface (Lookup, List, ValidateGrant).
    InMemoryCatalog — RWMutex-protected map[string]Role implementation.
    DavidsonRoles — reference fixture for the Davidson County deployment.

KEY DEPENDENCIES:
    - schemas/judicial_delegation.go (Role names referenced in
      JudicialDelegationPayload.Role).
*/
package schemas

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Role is the typed description of one role in the catalog. Field
// JSON tags allow a single struct to be loaded from either a JSON
// catalog file or a YAML loader (mapped through json tags).
type Role struct {
	// Name is the catalog key. Required, must equal map key.
	Name string `json:"name"`

	// Description is human-readable; recorded only in the catalog,
	// not on-log.
	Description string `json:"description,omitempty"`

	// MaxDuration is the upper bound on (ExpiresAt - IssuedAt) for
	// any delegation in this role. Required (>0).
	MaxDuration time.Duration `json:"max_duration"`

	// DefaultDuration is what IssueDelegation uses when the caller
	// does not specify ExpiresAt. Must be <= MaxDuration. Required.
	DefaultDuration time.Duration `json:"default_duration"`

	// AllowedScope is the universe of scope tokens a holder of this
	// role *may* be granted. Issued delegations' Scope must be a
	// subset. Required (non-empty).
	AllowedScope []string `json:"allowed_scope"`

	// DefaultScope is the scope tokens granted when the caller
	// passes no Scope. Must be a subset of AllowedScope. Required
	// (non-empty).
	DefaultScope []string `json:"default_scope"`

	// DelegableBy lists the role names that may *grant* this role.
	// "*" means any role whose own scope includes the matching
	// invite:* token. Empty means no role may grant — the role is
	// instituted directly by the institutional DID at depth 0
	// (typical for chief_justice).
	DelegableBy []string `json:"delegable_by,omitempty"`

	// DelegableScope is the slice of AllowedScope a holder of this
	// role may pass downstream when granting another role. If empty
	// and DelegableBy is non-empty, holders may pass through any
	// subset of their own current scope. The SDK
	// scope_enforcement.go intersection rule narrower-cannot-be-widened
	// always applies on top of this.
	DelegableScope []string `json:"delegable_scope,omitempty"`
}

// RoleCatalog is the read-side interface used by AuthorityResolver,
// IssueDelegation, and the validator. Implementations are expected to
// be safe for concurrent use.
type RoleCatalog interface {
	// Lookup returns the role with the given name. Returns
	// ErrRoleNotFound if absent.
	Lookup(name string) (Role, error)

	// List returns the catalog's role names in deterministic order.
	List() []string

	// ValidateGrant checks that a granter holding granterRole may
	// grant granteeRole with requestedScope for requestedDuration.
	// Returns nil iff:
	//   - granteeRole exists in the catalog
	//   - granterRole is in granteeRole.DelegableBy (or "*" present)
	//   - requestedScope ⊆ granteeRole.AllowedScope
	//   - requestedScope ⊆ granterRole.DelegableScope (when set)
	//   - requestedDuration <= granteeRole.MaxDuration
	ValidateGrant(granterRole, granteeRole string, requestedScope []string, requestedDuration time.Duration) error
}

// ErrRoleNotFound is returned by Lookup for unknown role names.
var ErrRoleNotFound = fmt.Errorf("schemas/role_catalog: role not found")

// InMemoryCatalog is the default RoleCatalog implementation. Safe for
// concurrent use. Tests construct one directly via
// NewInMemoryCatalog(...); production loads from a file (see
// role_catalog_yaml.go).
type InMemoryCatalog struct {
	mu    sync.RWMutex
	roles map[string]Role
}

// NewInMemoryCatalog constructs a catalog from a slice of roles.
// Each role's Name must be non-empty; duplicate names error.
func NewInMemoryCatalog(roles []Role) (*InMemoryCatalog, error) {
	c := &InMemoryCatalog{roles: make(map[string]Role, len(roles))}
	for _, r := range roles {
		if err := validateRole(r); err != nil {
			return nil, err
		}
		if _, dup := c.roles[r.Name]; dup {
			return nil, fmt.Errorf("schemas/role_catalog: duplicate role %q", r.Name)
		}
		c.roles[r.Name] = r
	}
	return c, nil
}

// Replace atomically swaps the catalog's contents. Used by the
// hot-reload path. Returns the same error set as NewInMemoryCatalog.
func (c *InMemoryCatalog) Replace(roles []Role) error {
	next := make(map[string]Role, len(roles))
	for _, r := range roles {
		if err := validateRole(r); err != nil {
			return err
		}
		if _, dup := next[r.Name]; dup {
			return fmt.Errorf("schemas/role_catalog: duplicate role %q", r.Name)
		}
		next[r.Name] = r
	}
	c.mu.Lock()
	c.roles = next
	c.mu.Unlock()
	return nil
}

// Lookup returns the named role.
func (c *InMemoryCatalog) Lookup(name string) (Role, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.roles[name]
	if !ok {
		return Role{}, fmt.Errorf("%w: %q", ErrRoleNotFound, name)
	}
	return r, nil
}

// List returns the catalog's role names in lexicographic order.
func (c *InMemoryCatalog) List() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	names := make([]string, 0, len(c.roles))
	for n := range c.roles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ValidateGrant enforces the catalog's grant rules. See the interface
// doc for the exact predicate.
func (c *InMemoryCatalog) ValidateGrant(granterRole, granteeRole string, requestedScope []string, requestedDuration time.Duration) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	gee, ok := c.roles[granteeRole]
	if !ok {
		return fmt.Errorf("%w: grantee role %q", ErrRoleNotFound, granteeRole)
	}

	// Skip granter-role check when granterRole is empty: the
	// institutional DID at depth 0 grants the top-of-chain role
	// (typically chief_justice). The caller passes "" for that path.
	if granterRole != "" {
		if _, gerOK := c.roles[granterRole]; !gerOK {
			return fmt.Errorf("%w: granter role %q", ErrRoleNotFound, granterRole)
		}
		if !roleAllowedToDelegate(granterRole, gee.DelegableBy) {
			return fmt.Errorf("schemas/role_catalog: granter role %q not permitted to delegate %q (DelegableBy=%v)",
				granterRole, granteeRole, gee.DelegableBy)
		}
	}

	if !subset(requestedScope, gee.AllowedScope) {
		return fmt.Errorf("schemas/role_catalog: requested scope %v not subset of role %q AllowedScope %v",
			requestedScope, granteeRole, gee.AllowedScope)
	}

	if granterRole != "" {
		ger := c.roles[granterRole]
		if len(ger.DelegableScope) > 0 && !subset(requestedScope, ger.DelegableScope) {
			return fmt.Errorf("schemas/role_catalog: requested scope %v not subset of granter role %q DelegableScope %v",
				requestedScope, granterRole, ger.DelegableScope)
		}
	}

	if requestedDuration > gee.MaxDuration {
		return fmt.Errorf("schemas/role_catalog: requested duration %s exceeds role %q MaxDuration %s",
			requestedDuration, granteeRole, gee.MaxDuration)
	}
	if requestedDuration <= 0 {
		return fmt.Errorf("schemas/role_catalog: requested duration must be positive, got %s", requestedDuration)
	}
	return nil
}

// ─── helpers ────────────────────────────────────────────────────────

func validateRole(r Role) error {
	if r.Name == "" {
		return fmt.Errorf("schemas/role_catalog: role name required")
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

// ─── reference fixture: Davidson County ─────────────────────────────

// DavidsonRoles is the reference role catalog for the Davidson County
// deployment. Tests use this. Production deployments load their own
// catalog file but typically start from this template.
//
// The hierarchy:
//
//   institutional_did ── grants ──> chief_justice (depth 0→1)
//   chief_justice     ── grants ──> judge (depth 1→2)
//   judge             ── grants ──> court_clerk (depth 2→3)
//   judge             ── grants ──> deputy_judge (depth 2→3)
//   court_clerk       ── grants ──> court_staff (depth 3→4) [if max_depth allows]
//
// Scope tokens follow the convention "verb:object", e.g.
// "case_filing", "invite:judge", "revoke:any".
func DavidsonRoles() []Role {
	day := 24 * time.Hour
	year := 365 * day
	return []Role{
		{
			Name:        "chief_justice",
			Description: "Top-of-chain authority for the court. Granted only by the institutional DID's Authority_Set.",
			MaxDuration: 8 * year,
			DefaultDuration: 4 * year,
			AllowedScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:judge",
				"invite:court_clerk",
				"invite:deputy_judge",
				"revoke:any",
				"administrative",
			},
			DefaultScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:judge",
				"invite:court_clerk",
				"invite:deputy_judge",
				"revoke:any",
				"administrative",
			},
			DelegableBy: nil, // institutional DID only
			DelegableScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:judge",
				"invite:court_clerk",
				"invite:deputy_judge",
				"revoke:any",
				"administrative",
			},
		},
		{
			Name:        "judge",
			Description: "Sitting judge. Issues case decisions and may delegate to a clerk or deputy.",
			MaxDuration: 8 * year,
			DefaultDuration: 4 * year,
			AllowedScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
				"invite:court_clerk",
				"invite:deputy_judge",
				"revoke:downstream",
			},
			DefaultScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
			},
			DelegableBy: []string{"chief_justice"},
			DelegableScope: []string{
				"case_filing",
				"docket_management",
				"invite:court_clerk",
				"invite:deputy_judge",
				"revoke:downstream",
			},
		},
		{
			Name:        "deputy_judge",
			Description: "Deputy judge sitting for the granter. Decisions are valid for the granter's term.",
			MaxDuration: 2 * year,
			DefaultDuration: year,
			AllowedScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
			},
			DefaultScope: []string{
				"case_filing",
				"case_decision",
				"docket_management",
			},
			DelegableBy:    []string{"judge"},
			DelegableScope: nil, // deputies cannot re-delegate
		},
		{
			Name:        "court_clerk",
			Description: "Court clerk. Files cases and manages the docket but does not issue decisions.",
			MaxDuration: 4 * year,
			DefaultDuration: 2 * year,
			AllowedScope: []string{
				"case_filing",
				"docket_management",
				"invite:court_staff",
			},
			DefaultScope: []string{
				"case_filing",
				"docket_management",
			},
			DelegableBy: []string{"chief_justice", "judge"},
			DelegableScope: []string{
				"case_filing",
				"docket_management",
				"invite:court_staff",
			},
		},
		{
			Name:        "court_staff",
			Description: "Court staff. Limited filing access. Cannot delegate.",
			MaxDuration: 2 * year,
			DefaultDuration: year,
			AllowedScope: []string{
				"case_filing",
			},
			DefaultScope: []string{
				"case_filing",
			},
			DelegableBy:    []string{"court_clerk"},
			DelegableScope: nil,
		},
	}
}

// MustDavidsonCatalog returns a catalog populated with DavidsonRoles
// or panics. Convenience for tests and the default boot path.
func MustDavidsonCatalog() *InMemoryCatalog {
	c, err := NewInMemoryCatalog(DavidsonRoles())
	if err != nil {
		panic(fmt.Sprintf("schemas/role_catalog: Davidson fixture invalid: %v", err))
	}
	return c
}
