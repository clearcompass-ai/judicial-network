/*
FILE PATH: deployments/tn/coa/role_catalog_test.go

DESCRIPTION:
    Tests pinning the TN Court of Appeals role catalog. Pins
    the v1.8 Authority Summary's appellate-Signer surface:
    Adjudicator (chief_judge / judge), Clerk (court_clerk),
    Deputy Clerk. NO chancellor / magistrate / court_staff —
    those are trial-court constructs.
*/
package coa

import (
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── Role validation ────────────────────────────────────────────────

func TestRoles_AllValid(t *testing.T) {
	if _, err := schemas.NewInMemoryCatalog(Roles()); err != nil {
		t.Errorf("TN COA roles failed to construct: %v", err)
	}
}

func TestRoles_AllSigners(t *testing.T) {
	for _, r := range Roles() {
		if r.Actor != schemas.ActorSigner {
			t.Errorf("tn/coa role %q has actor %s; catalog must contain only ActorSigner roles",
				r.Name, r.Actor)
		}
		if !r.Actor.HoldsKeys() {
			t.Errorf("tn/coa role %q actor %s claims HoldsKeys=false",
				r.Name, r.Actor)
		}
	}
}

// ─── v1.8 actor alignment ──────────────────────────────────────────

func TestRoles_v18ActorAlignment(t *testing.T) {
	want := map[string]bool{
		"chief_judge":  true,
		"judge":        true,
		"court_clerk":  true,
		"deputy_clerk": true,
	}
	got := map[string]bool{}
	for _, r := range Roles() {
		got[r.Name] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("v1.8 COA role %q missing", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("non-v1.8 COA role %q present (should not be)", name)
		}
	}
}

// TestRoles_NoTrialOnlyActors pins the absence of trial-court
// roles (chancellor, magistrate, court_staff, court_reporter).
// COA is appellate; those have no place here.
func TestRoles_NoTrialOnlyActors(t *testing.T) {
	c := MustRoleCatalog()
	for _, name := range []string{
		"chancellor", "magistrate", "court_staff", "court_reporter",
		"chief_justice", "deputy_judge",
	} {
		if _, err := c.Lookup(name); err == nil {
			t.Errorf("trial-only role %q must not appear in COA catalog", name)
		}
	}
}

// ─── Hierarchy chain ────────────────────────────────────────────────

func TestRoles_HierarchyChainable(t *testing.T) {
	c := MustRoleCatalog()
	year := 365 * 24 * time.Hour
	steps := []struct {
		granter, grantee string
		scope            []string
		duration         time.Duration
	}{
		{"", "chief_judge",
			[]string{"opinion_publication", "opinion_participation",
				"disposition_issuance", "invite:judge"},
			4 * year},
		{"chief_judge", "judge",
			[]string{"opinion_publication", "opinion_participation",
				"disposition_issuance"},
			4 * year},
		{"chief_judge", "court_clerk",
			[]string{"case_filing", "docket_management"},
			2 * year},
		{"court_clerk", "deputy_clerk",
			[]string{"case_filing", "docket_management"},
			year},
	}
	for _, s := range steps {
		if err := c.ValidateGrant(s.granter, s.grantee, s.scope, s.duration); err != nil {
			t.Errorf("chain step %s→%s failed: %v", s.granter, s.grantee, err)
		}
	}
}

// ─── ValidateGrant rejection paths ──────────────────────────────────

func TestValidateGrant_COARejectsUnauthorizedDelegator(t *testing.T) {
	c := MustRoleCatalog()
	// court_clerk cannot grant judge.
	err := c.ValidateGrant("court_clerk", "judge",
		[]string{"opinion_publication"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("expected unauthorized delegator error, got: %v", err)
	}
}

func TestValidateGrant_COARejectsScopeOutsideAllowed(t *testing.T) {
	c := MustRoleCatalog()
	// judge cannot exercise case_filing scope.
	err := c.ValidateGrant("chief_judge", "judge",
		[]string{"case_filing"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "AllowedScope") {
		t.Errorf("expected scope-outside-allowed error, got: %v", err)
	}
}

func TestValidateGrant_COARejectsExcessiveDuration(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("chief_judge", "judge",
		[]string{"opinion_publication"}, 100*365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "MaxDuration") {
		t.Errorf("expected MaxDuration rejection, got: %v", err)
	}
}

func TestValidateGrant_COAUnknownGranteeRole(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("chief_judge", "wizard",
		[]string{"opinion_publication"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "wizard") {
		t.Errorf("expected unknown grantee role, got: %v", err)
	}
}

// ─── MustRoleCatalog ────────────────────────────────────────────────

func TestMustRoleCatalog_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustRoleCatalog panicked: %v", r)
		}
	}()
	_ = MustRoleCatalog()
}

func TestMustRoleCatalog_IndependentCalls(t *testing.T) {
	a := MustRoleCatalog()
	b := MustRoleCatalog()
	if a == b {
		t.Error("MustRoleCatalog should return a fresh catalog per call")
	}
}

func TestRoles_ExpectedCount(t *testing.T) {
	const want = 4 // chief_judge, judge, court_clerk, deputy_clerk
	if got := len(Roles()); got != want {
		t.Errorf("TN COA role count: want %d, got %d", want, got)
	}
}
