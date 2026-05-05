/*
FILE PATH: internal/testfixtures/davidsonlegacy/role_catalog_test.go

DESCRIPTION:

	Tests pinning the legacy 6-role Davidson hierarchy fixture.
	Mirrors the original deployments/davidson_county/rules/
	role_catalog_test.go invariants — every role is a Signer,
	the chain composes end-to-end (institutional → CJ → judge →
	court_clerk → court_staff), and every ValidateGrant
	rejection path is covered.
*/
package davidsonlegacy

import (
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── Role validation ────────────────────────────────────────────────

func TestRoles_AllValid(t *testing.T) {
	if _, err := schemas.NewInMemoryCatalog(Roles()); err != nil {
		t.Errorf("legacy davidson roles failed to construct: %v", err)
	}
}

func TestRoles_AllSigners(t *testing.T) {
	for _, r := range Roles() {
		if r.Actor != schemas.ActorSigner {
			t.Errorf("legacy davidson role %q has actor %s; must be ActorSigner",
				r.Name, r.Actor)
		}
	}
}

// ─── Court reporter coverage ────────────────────────────────────────

func TestRoles_CourtReporterPresent(t *testing.T) {
	c := MustRoleCatalog()
	r, err := c.Lookup("court_reporter")
	if err != nil {
		t.Fatalf("court_reporter missing: %v", err)
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

func TestRoles_CJCanGrantCourtReporter(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("chief_justice", "court_reporter",
		[]string{"transcript_publication"}, 2*365*24*time.Hour)
	if err != nil {
		t.Errorf("CJ → court_reporter should be permitted: %v", err)
	}
}

// ─── Hierarchy chain (the legacy multi-hop fixture) ─────────────────

func TestRoles_HierarchyChainable(t *testing.T) {
	c := MustRoleCatalog()
	year := 365 * 24 * time.Hour
	steps := []struct {
		granter, grantee string
		scope            []string
		duration         time.Duration
	}{
		{"", "chief_justice",
			[]string{"case_filing", "invite:judge", "revoke:any"},
			4 * year},
		{"chief_justice", "judge",
			[]string{"case_filing", "case_decision", "docket_management"},
			4 * year},
		{"judge", "court_clerk",
			[]string{"case_filing", "docket_management"},
			2 * year},
		{"court_clerk", "court_staff",
			[]string{"case_filing"},
			year},
	}
	for _, s := range steps {
		if err := c.ValidateGrant(s.granter, s.grantee, s.scope, s.duration); err != nil {
			t.Errorf("chain step %s→%s failed: %v", s.granter, s.grantee, err)
		}
	}
}

// ─── ValidateGrant rejection paths ──────────────────────────────────

func TestValidateGrant_RejectsUnauthorizedDelegator(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("court_clerk", "judge",
		[]string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("expected unauthorized delegator, got: %v", err)
	}

	err = c.ValidateGrant("court_staff", "court_clerk",
		[]string{"case_filing"}, 365*24*time.Hour)
	if err == nil {
		t.Error("court_staff cannot grant")
	}
}

func TestValidateGrant_RejectsScopeOutsideAllowed(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("court_clerk", "court_staff",
		[]string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "AllowedScope") {
		t.Errorf("expected scope-outside-allowed, got: %v", err)
	}
}

func TestValidateGrant_RejectsScopeOutsideGranterDelegable(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("judge", "deputy_judge",
		[]string{"case_decision"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "DelegableScope") {
		t.Errorf("expected DelegableScope rejection, got: %v", err)
	}
}

func TestValidateGrant_RejectsExcessiveDuration(t *testing.T) {
	c := MustRoleCatalog()
	err := c.ValidateGrant("chief_justice", "judge",
		[]string{"case_filing"}, 100*365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "MaxDuration") {
		t.Errorf("expected MaxDuration, got: %v", err)
	}
}

func TestValidateGrant_UnknownGranteeRole(t *testing.T) {
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

func TestRoles_ExpectedCount(t *testing.T) {
	const want = 6 // chief_justice, judge, deputy_judge,
	//                court_clerk, court_staff, court_reporter
	if got := len(Roles()); got != want {
		t.Errorf("legacy davidson role count: want %d, got %d",
			want, got)
	}
}
