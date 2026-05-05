/*
FILE PATH: deployments/tn/trial/role_catalog_test.go

DESCRIPTION:

	Tests pinning the TN trial role catalog after v1.8 actor
	simplification. The catalog has exactly 3 roles:
	judge, court_clerk, court_reporter. Tests verify:
	  - the closed set (count + names),
	  - non-v1.8 actor names are absent,
	  - the hierarchy chain is composable end-to-end,
	  - ValidateGrant rejects non-permitted granter/grantee
	    combinations, scope leaks, and excessive durations.
*/
package trial

import (
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── Role validation ────────────────────────────────────────────────

func TestRoles_AllValid(t *testing.T) {
	if _, err := schemas.NewInMemoryCatalog(Roles()); err != nil {
		t.Errorf("TN trial roles failed to construct: %v", err)
	}
}

func TestRoles_AllSigners(t *testing.T) {
	for _, r := range Roles() {
		if r.Actor != schemas.ActorSigner {
			t.Errorf("tn/trial role %q has actor %s; catalog must contain only ActorSigner roles",
				r.Name, r.Actor)
		}
		if !r.Actor.HoldsKeys() {
			t.Errorf("tn/trial role %q actor %s claims HoldsKeys=false",
				r.Name, r.Actor)
		}
	}
}

// ─── v1.8 closed-set surface ───────────────────────────────────────

func TestRoles_v18ClosedSet(t *testing.T) {
	want := map[string]bool{
		"judge":          true,
		"court_clerk":    true,
		"court_reporter": true,
	}
	got := map[string]bool{}
	for _, r := range Roles() {
		got[r.Name] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("v1.8 trial role %q missing", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("non-v1.8 trial role %q present (must drop)", name)
		}
	}
}

// TestRoles_NoNonV18Actors pins the absence of every actor name
// dropped during the simplification: chief_justice (Sup. Court
// terminology, not trial), deputy_judge (subsumed into judge),
// court_staff (not a Signer in v1.8), deputy_clerk (subsumed into
// court_clerk).
func TestRoles_NoNonV18Actors(t *testing.T) {
	c := MustRoleCatalog()
	for _, name := range []string{
		"chief_justice", "deputy_judge", "court_staff", "deputy_clerk",
		"chief_judge", "magistrate", "chancellor", "justice",
	} {
		if _, err := c.Lookup(name); err == nil {
			t.Errorf("non-v1.8 role %q must not appear in TN trial catalog", name)
		}
	}
}

func TestRoles_ExpectedCount(t *testing.T) {
	const want = 3
	if got := len(Roles()); got != want {
		t.Errorf("TN trial role count: want %d, got %d", want, got)
	}
}

// ─── Court reporter coverage ────────────────────────────────────────

func TestRoles_CourtReporterPresent(t *testing.T) {
	c := MustRoleCatalog()
	r, err := c.Lookup("court_reporter")
	if err != nil {
		t.Fatalf("court_reporter missing from TN trial fixture: %v", err)
	}
	want := []string{"transcript_publication"}
	if len(r.AllowedScope) != 1 || r.AllowedScope[0] != want[0] {
		t.Errorf("court_reporter AllowedScope drift: got %v want %v",
			r.AllowedScope, want)
	}
	if len(r.DelegableBy) != 1 || r.DelegableBy[0] != "judge" {
		t.Errorf("court_reporter must be granted only by judge, got DelegableBy=%v",
			r.DelegableBy)
	}
}

func TestRoles_JudgeCanGrantCourtReporter(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("judge", "court_reporter",
		[]string{"transcript_publication"}, 2*365*24*time.Hour)
	if err != nil {
		t.Errorf("judge → court_reporter should be permitted: %v", err)
	}
}

// ─── Hierarchy chain ────────────────────────────────────────────────

// TestRoles_HierarchyChainable walks the simplified TN trial
// chain:
//
//	institutional → judge → court_clerk
//	institutional → judge → court_reporter
//
// Every step must pass ValidateGrant.
func TestRoles_HierarchyChainable(t *testing.T) {
	c := MustRoleCatalog()
	year := 365 * 24 * time.Hour
	steps := []struct {
		granter, grantee string
		scope            []string
		duration         time.Duration
	}{
		{"", "judge",
			[]string{"case_filing", "case_decision",
				"invite:court_clerk", "invite:court_reporter"},
			4 * year},
		{"judge", "court_clerk",
			[]string{"case_filing", "docket_management"},
			2 * year},
		{"judge", "court_reporter",
			[]string{"transcript_publication"},
			2 * year},
	}
	for _, s := range steps {
		if err := c.ValidateGrant(s.granter, s.grantee, s.scope, s.duration); err != nil {
			t.Errorf("chain step %s→%s failed: %v", s.granter, s.grantee, err)
		}
	}
}

// ─── ValidateGrant rejection paths ──────────────────────────────────

func TestValidateGrant_TNTrialRejectsUnauthorizedDelegator(t *testing.T) {
	c := MustRoleCatalog()
	// court_clerk cannot grant judge.
	err := c.ValidateGrant("court_clerk", "judge",
		[]string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("expected unauthorized delegator error, got: %v", err)
	}
}

func TestValidateGrant_TNTrialRejectsScopeOutsideAllowed(t *testing.T) {
	c := MustRoleCatalog()
	// court_clerk cannot exercise case_decision.
	err := c.ValidateGrant("judge", "court_clerk",
		[]string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "AllowedScope") {
		t.Errorf("expected scope-outside-allowed error, got: %v", err)
	}
}

func TestValidateGrant_TNTrialRejectsExcessiveDuration(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("judge", "court_clerk",
		[]string{"case_filing"}, 100*365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "MaxDuration") {
		t.Errorf("expected MaxDuration rejection, got: %v", err)
	}
}

func TestValidateGrant_TNTrialUnknownGranteeRole(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("judge", "wizard",
		[]string{"case_filing"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "wizard") {
		t.Errorf("expected unknown grantee role, got: %v", err)
	}
}

// ─── MustRoleCatalog construction ───────────────────────────────────

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
