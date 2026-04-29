/*
FILE PATH: schemas/role_catalog_test.go

DESCRIPTION:
    Tests pinning the RoleCatalog contract: Lookup, List,
    ValidateGrant, hot reload, and the Davidson reference fixture.
*/
package schemas

import (
	"strings"
	"testing"
	"time"
)

func TestNewInMemoryCatalog_RejectsInvalid(t *testing.T) {
	cases := []struct {
		name    string
		role    Role
		wantSub string
	}{
		{
			name:    "empty name",
			role:    Role{Name: "", MaxDuration: time.Hour, DefaultDuration: time.Hour, AllowedScope: []string{"x"}, DefaultScope: []string{"x"}},
			wantSub: "name required",
		},
		{
			name:    "zero max_duration",
			role:    Role{Name: "x", DefaultDuration: time.Hour, AllowedScope: []string{"a"}, DefaultScope: []string{"a"}},
			wantSub: "max_duration",
		},
		{
			name:    "default exceeds max",
			role:    Role{Name: "x", MaxDuration: time.Hour, DefaultDuration: 2 * time.Hour, AllowedScope: []string{"a"}, DefaultScope: []string{"a"}},
			wantSub: "exceeds max_duration",
		},
		{
			name:    "default scope not subset of allowed",
			role:    Role{Name: "x", MaxDuration: time.Hour, DefaultDuration: time.Hour, AllowedScope: []string{"a"}, DefaultScope: []string{"b"}},
			wantSub: "default_scope",
		},
		{
			name:    "delegable scope not subset of allowed",
			role:    Role{Name: "x", MaxDuration: time.Hour, DefaultDuration: time.Hour, AllowedScope: []string{"a"}, DefaultScope: []string{"a"}, DelegableScope: []string{"b"}},
			wantSub: "delegable_scope",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewInMemoryCatalog([]Role{tc.role})
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("got %v want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestNewInMemoryCatalog_RejectsDuplicates(t *testing.T) {
	r := Role{
		Name:            "judge",
		MaxDuration:     time.Hour,
		DefaultDuration: time.Hour,
		AllowedScope:    []string{"a"},
		DefaultScope:    []string{"a"},
	}
	_, err := NewInMemoryCatalog([]Role{r, r})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate err, got %v", err)
	}
}

func TestInMemoryCatalog_Lookup(t *testing.T) {
	c := MustDavidsonCatalog()

	r, err := c.Lookup("judge")
	if err != nil {
		t.Fatalf("lookup judge: %v", err)
	}
	if r.Name != "judge" {
		t.Errorf("name drift: %s", r.Name)
	}

	if _, err := c.Lookup("non-existent"); err == nil {
		t.Fatal("expected error on missing role")
	}
}

func TestInMemoryCatalog_List_DeterministicOrder(t *testing.T) {
	c := MustDavidsonCatalog()
	got := c.List()
	want := []string{"chief_justice", "court_clerk", "court_staff", "deputy_judge", "judge"}
	if len(got) != len(want) {
		t.Fatalf("list len: got %d want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("list[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

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
			MaxDuration:     time.Hour,
			DefaultDuration: time.Hour,
			AllowedScope:    []string{"a"},
			DefaultScope:    []string{"a"},
			DelegableBy:     []string{"*"},
		},
		{
			Name:            "any_role",
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

// ─── Replace / hot-reload ───────────────────────────────────────────

func TestInMemoryCatalog_Replace(t *testing.T) {
	c := MustDavidsonCatalog()

	newRoles := []Role{
		{
			Name:            "magistrate",
			MaxDuration:     time.Hour,
			DefaultDuration: time.Hour,
			AllowedScope:    []string{"x"},
			DefaultScope:    []string{"x"},
		},
	}
	if err := c.Replace(newRoles); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	if _, err := c.Lookup("magistrate"); err != nil {
		t.Errorf("magistrate after Replace: %v", err)
	}
	if _, err := c.Lookup("judge"); err == nil {
		t.Errorf("judge should be gone after Replace")
	}
}

func TestInMemoryCatalog_Replace_AtomicOnError(t *testing.T) {
	c := MustDavidsonCatalog()
	pre := c.List()

	bad := []Role{{Name: "incomplete"}} // missing required fields
	if err := c.Replace(bad); err == nil {
		t.Fatal("expected validation error")
	}

	// Catalog must be unchanged after failed Replace.
	post := c.List()
	if len(post) != len(pre) {
		t.Errorf("catalog mutated despite Replace failure: pre=%d post=%d", len(pre), len(post))
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

// ─── helpers tests ──────────────────────────────────────────────────

func TestSubsetHelper(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, []string{"a"}, true},
		{[]string{}, []string{"a"}, true},
		{[]string{"a"}, []string{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a", "c"}, []string{"a", "b"}, false},
		{[]string{"a"}, nil, false},
	}
	for i, tc := range cases {
		if got := subset(tc.a, tc.b); got != tc.want {
			t.Errorf("case %d subset(%v,%v): got %v want %v", i, tc.a, tc.b, got, tc.want)
		}
	}
}
