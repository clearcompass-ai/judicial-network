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
			role:    Role{Name: "", Tier: Tier1Signer, MaxDuration: time.Hour, DefaultDuration: time.Hour, AllowedScope: []string{"x"}, DefaultScope: []string{"x"}},
			wantSub: "name required",
		},
		{
			name:    "missing tier (zero value)",
			role:    Role{Name: "x", MaxDuration: time.Hour, DefaultDuration: time.Hour, AllowedScope: []string{"a"}, DefaultScope: []string{"a"}},
			wantSub: "tier must be one of",
		},
		{
			name:    "non-tier-1 role rejected (catalog only lists key-holders)",
			role:    Role{Name: "attorney", Tier: Tier2Advocate, MaxDuration: time.Hour, DefaultDuration: time.Hour, AllowedScope: []string{"a"}, DefaultScope: []string{"a"}},
			wantSub: "tier_2_advocate",
		},
		{
			name:    "tier_3_party also rejected",
			role:    Role{Name: "plaintiff", Tier: Tier3Party, MaxDuration: time.Hour, DefaultDuration: time.Hour, AllowedScope: []string{"a"}, DefaultScope: []string{"a"}},
			wantSub: "tier_3_party",
		},
		{
			name:    "tier out-of-range",
			role:    Role{Name: "x", Tier: Tier(99), MaxDuration: time.Hour, DefaultDuration: time.Hour, AllowedScope: []string{"a"}, DefaultScope: []string{"a"}},
			wantSub: "tier must be one of",
		},
		{
			name:    "zero max_duration",
			role:    Role{Name: "x", Tier: Tier1Signer, DefaultDuration: time.Hour, AllowedScope: []string{"a"}, DefaultScope: []string{"a"}},
			wantSub: "max_duration",
		},
		{
			name:    "default exceeds max",
			role:    Role{Name: "x", Tier: Tier1Signer, MaxDuration: time.Hour, DefaultDuration: 2 * time.Hour, AllowedScope: []string{"a"}, DefaultScope: []string{"a"}},
			wantSub: "exceeds max_duration",
		},
		{
			name:    "default scope not subset of allowed",
			role:    Role{Name: "x", Tier: Tier1Signer, MaxDuration: time.Hour, DefaultDuration: time.Hour, AllowedScope: []string{"a"}, DefaultScope: []string{"b"}},
			wantSub: "default_scope",
		},
		{
			name:    "delegable scope not subset of allowed",
			role:    Role{Name: "x", Tier: Tier1Signer, MaxDuration: time.Hour, DefaultDuration: time.Hour, AllowedScope: []string{"a"}, DefaultScope: []string{"a"}, DelegableScope: []string{"b"}},
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
		Tier:            Tier1Signer,
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
	// Davidson fixture: chief_justice, judge, deputy_judge,
	// court_clerk, court_staff, court_reporter (alphabetic).
	want := []string{
		"chief_justice", "court_clerk", "court_reporter",
		"court_staff", "deputy_judge", "judge",
	}
	if len(got) != len(want) {
		t.Fatalf("list len: got %d want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("list[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

// ─── Replace / hot-reload ───────────────────────────────────────────
// (ValidateGrant + Davidson hierarchy/fixture tests live in
//  role_catalog_grant_test.go in the same package.)

func TestInMemoryCatalog_Replace(t *testing.T) {
	c := MustDavidsonCatalog()

	newRoles := []Role{
		{
			Name:            "magistrate",
			Tier:            Tier1Signer,
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
