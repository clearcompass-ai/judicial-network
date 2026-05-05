/*
FILE PATH: schemas/role_catalog_grant_test.go

DESCRIPTION:

	ValidateGrant tests — the bulk of the catalog's enforcement
	surface. Uses an inline 4-role fixture (chief, mid, leaf,
	delegating_leaf) to exercise hierarchy, scope-narrowing,
	duration caps, and wildcard delegable_by.

	Jurisdiction-specific assertions (Davidson hierarchy, every
	role tagged ActorSigner, etc.) live under
	deployments/<county>/rules/role_catalog_test.go. The schemas
	package stays jurisdiction-agnostic.
*/
package schemas

import (
	"strings"
	"testing"
	"time"
)

// hierarchicalCatalog builds a 4-role chain:
//
//	institutional → chief → mid → leaf
//	chief         → delegating_leaf
//
// Roles narrow as you descend: AllowedScope shrinks; the chief's
// DelegableScope omits "decision" so even though "mid" allows it,
// the chief cannot pass it down.
func hierarchicalCatalog(t *testing.T) *InMemoryCatalog {
	t.Helper()
	roles := []Role{
		{
			Name:            "chief",
			Actor:           ActorSigner,
			MaxDuration:     4 * 365 * 24 * time.Hour,
			DefaultDuration: time.Hour,
			AllowedScope:    []string{"file", "decision", "invite:mid", "invite:leaf", "invite:delegating_leaf"},
			DefaultScope:    []string{"file"},
			DelegableBy:     nil, // institutional only
			DelegableScope:  []string{"file", "invite:mid", "invite:leaf", "invite:delegating_leaf"},
		},
		{
			Name:            "mid",
			Actor:           ActorSigner,
			MaxDuration:     4 * 365 * 24 * time.Hour,
			DefaultDuration: time.Hour,
			AllowedScope:    []string{"file", "decision", "invite:leaf"},
			DefaultScope:    []string{"file"},
			DelegableBy:     []string{"chief"},
			DelegableScope:  []string{"file", "invite:leaf"},
		},
		{
			Name:            "leaf",
			Actor:           ActorSigner,
			MaxDuration:     2 * 365 * 24 * time.Hour,
			DefaultDuration: time.Hour,
			AllowedScope:    []string{"file"},
			DefaultScope:    []string{"file"},
			DelegableBy:     []string{"mid"},
			DelegableScope:  nil,
		},
		{
			Name:            "delegating_leaf",
			Actor:           ActorSigner,
			MaxDuration:     time.Hour,
			DefaultDuration: time.Hour,
			AllowedScope:    []string{"file"},
			DefaultScope:    []string{"file"},
			DelegableBy:     []string{"chief"},
			DelegableScope:  nil,
		},
	}
	c, err := NewInMemoryCatalog(roles)
	if err != nil {
		t.Fatalf("hierarchicalCatalog: %v", err)
	}
	return c
}

// ─── Hierarchy walk ─────────────────────────────────────────────────

func TestValidateGrant_HierarchyWalk(t *testing.T) {
	c := hierarchicalCatalog(t)

	if err := c.ValidateGrant("", "chief",
		[]string{"file", "invite:mid"}, time.Hour); err != nil {
		t.Errorf("institutional → chief: %v", err)
	}
	if err := c.ValidateGrant("chief", "mid",
		[]string{"file", "invite:leaf"}, time.Hour); err != nil {
		t.Errorf("chief → mid: %v", err)
	}
	if err := c.ValidateGrant("mid", "leaf",
		[]string{"file"}, time.Hour); err != nil {
		t.Errorf("mid → leaf: %v", err)
	}
}

// ─── Rejection paths ────────────────────────────────────────────────

func TestValidateGrant_RejectsUnauthorizedDelegator(t *testing.T) {
	c := hierarchicalCatalog(t)

	err := c.ValidateGrant("leaf", "mid", []string{"file"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("expected unauthorized delegator, got: %v", err)
	}
}

func TestValidateGrant_RejectsScopeOutsideAllowed(t *testing.T) {
	c := hierarchicalCatalog(t)

	// "decision" is not in leaf.AllowedScope; even though mid is a
	// permitted granter, the grantee's scope envelope rejects.
	err := c.ValidateGrant("mid", "leaf", []string{"decision"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "AllowedScope") {
		t.Errorf("expected scope-outside-allowed, got: %v", err)
	}
}

func TestValidateGrant_RejectsScopeOutsideGranterDelegable(t *testing.T) {
	c := hierarchicalCatalog(t)

	// chief.DelegableScope omits "decision" — chief itself can use
	// decision but cannot pass it down to mid even though
	// mid.AllowedScope includes it.
	err := c.ValidateGrant("chief", "mid", []string{"decision"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "DelegableScope") {
		t.Errorf("expected DelegableScope rejection, got: %v", err)
	}
}

func TestValidateGrant_RejectsExcessiveDuration(t *testing.T) {
	c := hierarchicalCatalog(t)

	err := c.ValidateGrant("", "chief", []string{"file"}, 100*365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "MaxDuration") {
		t.Errorf("expected MaxDuration rejection, got: %v", err)
	}
}

func TestValidateGrant_RejectsZeroDuration(t *testing.T) {
	c := hierarchicalCatalog(t)

	err := c.ValidateGrant("", "chief", []string{"file"}, 0)
	if err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("expected positive-duration rejection, got: %v", err)
	}
}

func TestValidateGrant_UnknownGranteeRole(t *testing.T) {
	c := hierarchicalCatalog(t)
	err := c.ValidateGrant("chief", "wizard", []string{"file"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "wizard") {
		t.Errorf("expected unknown grantee role, got: %v", err)
	}
}

func TestValidateGrant_UnknownGranterRole(t *testing.T) {
	c := hierarchicalCatalog(t)
	err := c.ValidateGrant("wizard", "chief", []string{"file"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "wizard") {
		t.Errorf("expected unknown granter role, got: %v", err)
	}
}

// ─── Wildcard DelegableBy ───────────────────────────────────────────

func TestValidateGrant_WildcardDelegableBy(t *testing.T) {
	roles := []Role{
		{
			Name:            "anyone_can_grant_me",
			Actor:           ActorSigner,
			MaxDuration:     time.Hour,
			DefaultDuration: time.Hour,
			AllowedScope:    []string{"a"},
			DefaultScope:    []string{"a"},
			DelegableBy:     []string{"*"},
		},
		{
			Name:            "any_role",
			Actor:           ActorSigner,
			MaxDuration:     time.Hour,
			DefaultDuration: time.Hour,
			AllowedScope:    []string{"a"},
			DefaultScope:    []string{"a"},
			DelegableScope:  []string{"a"},
		},
	}
	c, err := NewInMemoryCatalog(roles)
	if err != nil {
		t.Fatalf("NewInMemoryCatalog: %v", err)
	}

	if err := c.ValidateGrant("any_role", "anyone_can_grant_me",
		[]string{"a"}, time.Hour); err != nil {
		t.Errorf("wildcard delegable_by must allow any role: %v", err)
	}
}
