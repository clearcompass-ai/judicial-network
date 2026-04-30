/*
FILE PATH: schemas/role_catalog_grant_test.go

DESCRIPTION:
    ValidateGrant tests (the bulk of the catalog's enforcement
    surface) plus the Davidson-fixture sanity tests. Split out of
    role_catalog_test.go to keep both files under the source-file
    line cap.
*/
package schemas

import (
	"strings"
	"testing"
	"time"
)

// ─── ValidateGrant ──────────────────────────────────────────────────

func TestValidateGrant_DavidsonHierarchy(t *testing.T) {
	c := MustDavidsonCatalog()

	// Institutional DID grants chief_justice (granterRole="").
	if err := c.ValidateGrant("", "chief_justice", []string{"case_filing", "invite:judge", "revoke:any"}, 4*365*24*time.Hour); err != nil {
		t.Errorf("institutional → chief_justice: %v", err)
	}

	// CJ grants judge.
	if err := c.ValidateGrant("chief_justice", "judge", []string{"case_filing", "case_decision", "docket_management"}, 4*365*24*time.Hour); err != nil {
		t.Errorf("CJ → judge: %v", err)
	}

	// Judge grants court_clerk.
	if err := c.ValidateGrant("judge", "court_clerk", []string{"case_filing", "docket_management"}, 2*365*24*time.Hour); err != nil {
		t.Errorf("judge → court_clerk: %v", err)
	}

	// court_clerk grants court_staff.
	if err := c.ValidateGrant("court_clerk", "court_staff", []string{"case_filing"}, 365*24*time.Hour); err != nil {
		t.Errorf("court_clerk → court_staff: %v", err)
	}
}

func TestValidateGrant_RejectsUnauthorizedDelegator(t *testing.T) {
	c := MustDavidsonCatalog()

	// court_clerk cannot grant judge.
	err := c.ValidateGrant("court_clerk", "judge", []string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("expected unauthorized delegator error, got: %v", err)
	}

	// court_staff (not in any DelegableBy) cannot grant anything.
	err = c.ValidateGrant("court_staff", "court_clerk", []string{"case_filing"}, 365*24*time.Hour)
	if err == nil {
		t.Errorf("court_staff cannot grant")
	}
}

func TestValidateGrant_RejectsScopeOutsideAllowed(t *testing.T) {
	c := MustDavidsonCatalog()

	// court_clerk is permitted to grant court_staff. court_staff's
	// AllowedScope is just ["case_filing"]; "case_decision" is not
	// in it. The check that fails is grantee.AllowedScope, not
	// granter.DelegableScope.
	err := c.ValidateGrant("court_clerk", "court_staff", []string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "AllowedScope") {
		t.Errorf("expected scope-outside-allowed error, got: %v", err)
	}
}

func TestValidateGrant_RejectsScopeOutsideGranterDelegable(t *testing.T) {
	c := MustDavidsonCatalog()

	// judge.DelegableScope explicitly omits "case_decision" — judges
	// can act with case_decision themselves but cannot pass it down.
	// Even though deputy_judge.AllowedScope includes case_decision,
	// the granter (judge) lacks DelegableScope for it.
	err := c.ValidateGrant("judge", "deputy_judge", []string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "DelegableScope") {
		t.Errorf("expected DelegableScope rejection, got: %v", err)
	}
}

func TestValidateGrant_RejectsExcessiveDuration(t *testing.T) {
	c := MustDavidsonCatalog()

	err := c.ValidateGrant("chief_justice", "judge", []string{"case_filing"}, 100*365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "MaxDuration") {
		t.Errorf("expected MaxDuration rejection, got: %v", err)
	}
}

func TestValidateGrant_RejectsZeroDuration(t *testing.T) {
	c := MustDavidsonCatalog()

	err := c.ValidateGrant("chief_justice", "judge", []string{"case_filing"}, 0)
	if err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("expected positive-duration rejection, got: %v", err)
	}
}

func TestValidateGrant_UnknownGranteeRole(t *testing.T) {
	c := MustDavidsonCatalog()
	err := c.ValidateGrant("chief_justice", "wizard", []string{"case_filing"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "wizard") {
		t.Errorf("expected unknown grantee role, got: %v", err)
	}
}

func TestValidateGrant_UnknownGranterRole(t *testing.T) {
	c := MustDavidsonCatalog()
	err := c.ValidateGrant("wizard", "judge", []string{"case_filing"}, time.Hour)
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

	if err := c.ValidateGrant("any_role", "anyone_can_grant_me", []string{"a"}, time.Hour); err != nil {
		t.Errorf("wildcard delegable_by must allow any role: %v", err)
	}
}

// ─── DavidsonRoles fixture sanity ───────────────────────────────────

func TestDavidsonRoles_AllValid(t *testing.T) {
	for _, r := range DavidsonRoles() {
		if err := validateRole(r); err != nil {
			t.Errorf("davidson role %q invalid: %v", r.Name, err)
		}
	}
}

// TestDavidsonRoles_AllSigners pins that every role in the Davidson
// fixture is a key-holding ActorSigner per the v1.4 dictionary.
// If a future maintainer adds an ActorFiler entry to the catalog,
// this test fails and the validateRole gate also fires — defense
// in depth.
func TestDavidsonRoles_AllSigners(t *testing.T) {
	for _, r := range DavidsonRoles() {
		if r.Actor != ActorSigner {
			t.Errorf("davidson role %q has actor %s; catalog must contain only ActorSigner roles",
				r.Name, r.Actor)
		}
		if !r.Actor.HoldsKeys() {
			t.Errorf("davidson role %q actor %s claims HoldsKeys=false", r.Name, r.Actor)
		}
	}
}

// TestDavidsonRoles_CourtReporterPresent pins that the Davidson
// fixture covers the dictionary's Tier 1 categories — Adjudicators,
// Clerks, Court Reporters. Adding court_reporter as part of Phase 3A.
func TestDavidsonRoles_CourtReporterPresent(t *testing.T) {
	c := MustDavidsonCatalog()
	r, err := c.Lookup("court_reporter")
	if err != nil {
		t.Fatalf("court_reporter missing from Davidson fixture: %v", err)
	}
	want := []string{"transcript_publication"}
	if len(r.AllowedScope) != 1 || r.AllowedScope[0] != want[0] {
		t.Errorf("court_reporter AllowedScope drift: got %v want %v",
			r.AllowedScope, want)
	}
	if len(r.DelegableBy) != 1 || r.DelegableBy[0] != "chief_justice" {
		t.Errorf("court_reporter must be granted only by chief_justice, got DelegableBy=%v",
			r.DelegableBy)
	}
}

// TestDavidsonRoles_CJCanGrantCourtReporter pins the CJ → court_reporter
// path through the catalog: CJ.DelegableScope must contain
// transcript_publication so ValidateGrant accepts the issuance.
func TestDavidsonRoles_CJCanGrantCourtReporter(t *testing.T) {
	c := MustDavidsonCatalog()
	err := c.ValidateGrant("chief_justice", "court_reporter",
		[]string{"transcript_publication"}, 2*365*24*time.Hour)
	if err != nil {
		t.Errorf("CJ → court_reporter should be permitted: %v", err)
	}
}

func TestDavidsonRoles_HierarchyChainable(t *testing.T) {
	c := MustDavidsonCatalog()

	// Walk a 4-hop chain: institutional → chief_justice → judge → court_clerk → court_staff
	steps := []struct {
		granter, grantee string
		scope            []string
		duration         time.Duration
	}{
		{"", "chief_justice", []string{"case_filing", "invite:judge", "revoke:any"}, 4 * 365 * 24 * time.Hour},
		{"chief_justice", "judge", []string{"case_filing", "case_decision", "docket_management"}, 4 * 365 * 24 * time.Hour},
		{"judge", "court_clerk", []string{"case_filing", "docket_management"}, 2 * 365 * 24 * time.Hour},
		{"court_clerk", "court_staff", []string{"case_filing"}, 365 * 24 * time.Hour},
	}
	for _, s := range steps {
		if err := c.ValidateGrant(s.granter, s.grantee, s.scope, s.duration); err != nil {
			t.Errorf("chain step %s→%s failed: %v", s.granter, s.grantee, err)
		}
	}
}
