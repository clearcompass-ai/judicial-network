/*
FILE PATH: deployments/tn/sup_ct/role_catalog_test.go

DESCRIPTION:
    Tests for the TN Supreme Court role catalog. Pins the
    chief_justice / justice / court_clerk surface and rejects
    every non-Sup-Ct role name.
*/
package sup_ct

import (
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

func TestRoles_AllValid(t *testing.T) {
	if _, err := schemas.NewInMemoryCatalog(Roles()); err != nil {
		t.Errorf("TN Sup Ct roles failed to construct: %v", err)
	}
}

func TestRoles_AllSigners(t *testing.T) {
	for _, r := range Roles() {
		if r.Actor != schemas.ActorSigner {
			t.Errorf("tn/sup_ct role %q has actor %s; must be ActorSigner",
				r.Name, r.Actor)
		}
	}
}

func TestRoles_v18ActorAlignment(t *testing.T) {
	want := map[string]bool{
		"chief_justice": true,
		"justice":       true,
		"court_clerk":   true,
	}
	got := map[string]bool{}
	for _, r := range Roles() {
		got[r.Name] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("Sup Ct role %q missing", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("non-Sup-Ct role %q present", name)
		}
	}
}

// TN COA uses chief_judge / judge; TN Sup Ct uses chief_justice /
// justice. Pin the distinction.
func TestRoles_NoCOARoles(t *testing.T) {
	c := MustRoleCatalog()
	for _, name := range []string{
		"chief_judge", "judge", "magistrate", "court_reporter",
		"court_staff", "deputy_clerk", "deputy_judge",
	} {
		if _, err := c.Lookup(name); err == nil {
			t.Errorf("non-Sup-Ct role %q must not appear in catalog", name)
		}
	}
}

func TestRoles_HierarchyChainable(t *testing.T) {
	c := MustRoleCatalog()
	year := 365 * 24 * time.Hour
	steps := []struct {
		granter, grantee string
		scope            []string
		duration         time.Duration
	}{
		{"", "chief_justice",
			[]string{"opinion_publication", "opinion_participation",
				"disposition_issuance", "invite:justice"},
			4 * year},
		{"chief_justice", "justice",
			[]string{"opinion_publication", "opinion_participation",
				"disposition_issuance"},
			4 * year},
		{"chief_justice", "court_clerk",
			[]string{"case_filing", "docket_management"},
			2 * year},
	}
	for _, s := range steps {
		if err := c.ValidateGrant(s.granter, s.grantee, s.scope, s.duration); err != nil {
			t.Errorf("chain step %s→%s failed: %v", s.granter, s.grantee, err)
		}
	}
}

func TestValidateGrant_ChiefJusticeRequiredForJustice(t *testing.T) {
	c := MustRoleCatalog()
	// court_clerk cannot grant justice.
	err := c.ValidateGrant("court_clerk", "justice",
		[]string{"opinion_publication"}, 365*24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("expected unauthorized delegator error, got: %v", err)
	}
}

func TestRoles_ExpectedCount(t *testing.T) {
	const want = 3 // chief_justice, justice, court_clerk
	if got := len(Roles()); got != want {
		t.Errorf("Sup Ct role count: want %d, got %d", want, got)
	}
}

func TestMustRoleCatalog_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustRoleCatalog panicked: %v", r)
		}
	}()
	_ = MustRoleCatalog()
}
