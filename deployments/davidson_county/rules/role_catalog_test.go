/*
FILE PATH: deployments/davidson_county/rules/role_catalog_test.go

DESCRIPTION:
    Tests pinning the Davidson role catalog. Lifted (3E.7) from
    schemas/role_catalog_grant_test.go's Davidson-specific tests.
    Validates the hierarchy:

      institutional → chief_justice → judge → court_clerk → court_staff
      chief_justice → court_reporter

    Plus structural pins: every role is ActorSigner, every role
    validates, court_reporter is reachable from chief_justice with
    transcript_publication scope.
*/
package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── Role validation ────────────────────────────────────────────────

// TestRoles_AllValid runs every Davidson role through
// NewInMemoryCatalog, which validates each role on insertion.
func TestRoles_AllValid(t *testing.T) {
	if _, err := schemas.NewInMemoryCatalog(Roles()); err != nil {
		t.Errorf("Davidson roles failed to construct: %v", err)
	}
}

// TestRoles_AllSigners pins that every Davidson role is a
// key-holding ActorSigner per the v1.6 dictionary. The catalog
// only lists Tier 1 (Signer) roles; Filers and Parties never
// appear here.
func TestRoles_AllSigners(t *testing.T) {
	for _, r := range Roles() {
		if r.Actor != schemas.ActorSigner {
			t.Errorf("davidson role %q has actor %s; catalog must contain only ActorSigner roles",
				r.Name, r.Actor)
		}
		if !r.Actor.HoldsKeys() {
			t.Errorf("davidson role %q actor %s claims HoldsKeys=false", r.Name, r.Actor)
		}
	}
}

// ─── Court reporter coverage ────────────────────────────────────────

// TestRoles_CourtReporterPresent pins that the Davidson fixture
// covers the dictionary's Tier 1 categories — Adjudicators, Clerks,
// Court Reporters.
func TestRoles_CourtReporterPresent(t *testing.T) {
	c := MustRoleCatalog()
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

// TestRoles_CJCanGrantCourtReporter pins the CJ → court_reporter
// path through the catalog: CJ.DelegableScope must contain
// transcript_publication so ValidateGrant accepts the issuance.
func TestRoles_CJCanGrantCourtReporter(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("chief_justice", "court_reporter",
		[]string{"transcript_publication"}, 2*365*24*time.Hour)
	if err != nil {
		t.Errorf("CJ → court_reporter should be permitted: %v", err)
	}
}

// ─── Hierarchy chain ────────────────────────────────────────────────

// TestRoles_HierarchyChainable walks the full Davidson chain:
//
//   institutional → chief_justice → judge → court_clerk → court_staff
//
// Every step must pass ValidateGrant.
func TestRoles_HierarchyChainable(t *testing.T) {
	c := MustRoleCatalog()

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

// ─── ValidateGrant rejection paths ──────────────────────────────────

func TestValidateGrant_DavidsonRejectsUnauthorizedDelegator(t *testing.T) {
	c := MustRoleCatalog()

	err := c.ValidateGrant("court_clerk", "judge", []string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("expected unauthorized delegator error, got: %v", err)
	}

	err = c.ValidateGrant("court_staff", "court_clerk", []string{"case_filing"}, 365*24*time.Hour)
	if err == nil {
		t.Errorf("court_staff cannot grant")
	}
}

func TestValidateGrant_DavidsonRejectsScopeOutsideAllowed(t *testing.T) {
	c := MustRoleCatalog()

	err := c.ValidateGrant("court_clerk", "court_staff", []string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "AllowedScope") {
		t.Errorf("expected scope-outside-allowed error, got: %v", err)
	}
}

func TestValidateGrant_DavidsonRejectsScopeOutsideGranterDelegable(t *testing.T) {
	c := MustRoleCatalog()

	err := c.ValidateGrant("judge", "deputy_judge", []string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "DelegableScope") {
		t.Errorf("expected DelegableScope rejection, got: %v", err)
	}
}

func TestValidateGrant_DavidsonRejectsExcessiveDuration(t *testing.T) {
	c := MustRoleCatalog()

	err := c.ValidateGrant("chief_justice", "judge", []string{"case_filing"}, 100*365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "MaxDuration") {
		t.Errorf("expected MaxDuration rejection, got: %v", err)
	}
}

func TestValidateGrant_DavidsonUnknownGranteeRole(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("chief_justice", "wizard", []string{"case_filing"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "wizard") {
		t.Errorf("expected unknown grantee role, got: %v", err)
	}
}
