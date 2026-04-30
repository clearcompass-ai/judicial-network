/*
FILE PATH: deployments/tn/trial/role_catalog_test.go

DESCRIPTION:
    Tests pinning the TN trial role catalog. Lifted from
    deployments/davidson_county/rules/role_catalog_test.go and
    re-scoped to the shared TN trial framework: every TN county
    that imports this package gets the same hierarchy:

      institutional → chief_justice → judge → court_clerk → court_staff
      chief_justice → court_reporter
      judge         → deputy_judge

    Plus structural pins: every role is ActorSigner, every role
    validates, court_reporter is reachable from chief_justice
    with transcript_publication scope.

    NOTE: v1.8 actor alignment (drop court_staff, rename
    deputy_judge → magistrate, drop chief_justice from trial,
    add deputy_clerk) lands in a follow-on commit. Until then,
    these tests pin the current shape.
*/
package trial

import (
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── Role validation ────────────────────────────────────────────────

// TestRoles_AllValid runs every TN trial role through
// NewInMemoryCatalog, which validates each role on insertion.
func TestRoles_AllValid(t *testing.T) {
	if _, err := schemas.NewInMemoryCatalog(Roles()); err != nil {
		t.Errorf("TN trial roles failed to construct: %v", err)
	}
}

// TestRoles_AllSigners pins that every TN trial role is a
// key-holding ActorSigner per the v1.8 dictionary. The catalog
// only lists Signer roles; Filers and Parties never appear here.
func TestRoles_AllSigners(t *testing.T) {
	for _, r := range Roles() {
		if r.Actor != schemas.ActorSigner {
			t.Errorf("tn/trial role %q has actor %s; catalog must contain only ActorSigner roles",
				r.Name, r.Actor)
		}
		if !r.Actor.HoldsKeys() {
			t.Errorf("tn/trial role %q actor %s claims HoldsKeys=false", r.Name, r.Actor)
		}
	}
}

// ─── Court reporter coverage ────────────────────────────────────────

// TestRoles_CourtReporterPresent pins that the TN trial fixture
// covers the dictionary's Signer categories — Adjudicators, Clerks,
// Court Reporters.
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
	if len(r.DelegableBy) != 1 || r.DelegableBy[0] != "chief_justice" {
		t.Errorf("court_reporter must be granted only by chief_justice, got DelegableBy=%v",
			r.DelegableBy)
	}
}

// TestRoles_CJCanGrantCourtReporter pins the chief_justice →
// court_reporter path through the catalog: CJ.DelegableScope must
// contain transcript_publication so ValidateGrant accepts the
// issuance.
func TestRoles_CJCanGrantCourtReporter(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("chief_justice", "court_reporter",
		[]string{"transcript_publication"}, 2*365*24*time.Hour)
	if err != nil {
		t.Errorf("CJ → court_reporter should be permitted: %v", err)
	}
}

// ─── Hierarchy chain ────────────────────────────────────────────────

// TestRoles_HierarchyChainable walks the full TN trial chain:
//
//	institutional → chief_justice → judge → court_clerk → court_staff
//
// Every step must pass ValidateGrant.
func TestRoles_HierarchyChainable(t *testing.T) {
	c := MustRoleCatalog()

	steps := []struct {
		granter, grantee string
		scope            []string
		duration         time.Duration
	}{
		{"", "chief_justice",
			[]string{"case_filing", "invite:judge", "revoke:any"},
			4 * 365 * 24 * time.Hour},
		{"chief_justice", "judge",
			[]string{"case_filing", "case_decision", "docket_management"},
			4 * 365 * 24 * time.Hour},
		{"judge", "court_clerk",
			[]string{"case_filing", "docket_management"},
			2 * 365 * 24 * time.Hour},
		{"court_clerk", "court_staff",
			[]string{"case_filing"},
			365 * 24 * time.Hour},
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

	err := c.ValidateGrant("court_clerk", "judge",
		[]string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("expected unauthorized delegator error, got: %v", err)
	}

	err = c.ValidateGrant("court_staff", "court_clerk",
		[]string{"case_filing"}, 365*24*time.Hour)
	if err == nil {
		t.Errorf("court_staff cannot grant")
	}
}

func TestValidateGrant_TNTrialRejectsScopeOutsideAllowed(t *testing.T) {
	c := MustRoleCatalog()

	err := c.ValidateGrant("court_clerk", "court_staff",
		[]string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "AllowedScope") {
		t.Errorf("expected scope-outside-allowed error, got: %v", err)
	}
}

func TestValidateGrant_TNTrialRejectsScopeOutsideGranterDelegable(t *testing.T) {
	c := MustRoleCatalog()

	err := c.ValidateGrant("judge", "deputy_judge",
		[]string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "DelegableScope") {
		t.Errorf("expected DelegableScope rejection, got: %v", err)
	}
}

func TestValidateGrant_TNTrialRejectsExcessiveDuration(t *testing.T) {
	c := MustRoleCatalog()

	err := c.ValidateGrant("chief_justice", "judge",
		[]string{"case_filing"}, 100*365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "MaxDuration") {
		t.Errorf("expected MaxDuration rejection, got: %v", err)
	}
}

func TestValidateGrant_TNTrialUnknownGranteeRole(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("chief_justice", "wizard",
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
	// Each call returns a fresh InMemoryCatalog — callers must
	// not assume identity between calls. This pin guards against
	// future "memoize for performance" regressions that would
	// share state across deployments.
	a := MustRoleCatalog()
	b := MustRoleCatalog()
	if a == b {
		t.Error("MustRoleCatalog should return a new catalog per call")
	}
}

// TestRoles_ExpectedCount pins the role count so an accidental
// addition / deletion shows up in CI. Update when intentional.
func TestRoles_ExpectedCount(t *testing.T) {
	const want = 6 // chief_justice, judge, deputy_judge,
	//                court_clerk, court_staff, court_reporter
	if got := len(Roles()); got != want {
		t.Errorf("TN trial role count: want %d, got %d", want, got)
	}
}
