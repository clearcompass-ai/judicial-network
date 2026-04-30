/*
FILE PATH: policy/cosignature_mix_test.go

DESCRIPTION:
    Tests for CosignatureRule + InMemoryPolicy: validation, rule
    helpers (PermitsFilerRole / PermitsSignerRole / RequiresFiler /
    EffectiveMinCosigners), Lookup, Add, List ordering, Replace,
    duplicate detection, concurrent reads.
*/
package policy

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── helpers ────────────────────────────────────────────────────────

func motionRule() CosignatureRule {
	return CosignatureRule{
		EventType:           "motion_continuance",
		AllowedFilerRoles:   []schemas.FilerRole{schemas.FilerRoleDefenseCounsel},
		RequiredSignerRoles: []string{"court_clerk"},
		MinSignerCosigners:  1,
		IntraExchangeOnly:   true,
		RequiredCredentials: []string{"bpr_number"},
	}
}

func verdictRule() CosignatureRule {
	return CosignatureRule{
		EventType:           "verdict",
		RequiredSignerRoles: []string{"judge"},
		IntraExchangeOnly:   true,
	}
}

// ─── rule helpers ──────────────────────────────────────────────────

func TestRule_PermitsFilerRole(t *testing.T) {
	r := motionRule()
	if !r.PermitsFilerRole(schemas.FilerRoleDefenseCounsel) {
		t.Error("defense_counsel should be permitted")
	}
	if r.PermitsFilerRole(schemas.FilerRoleProsecutor) {
		t.Error("prosecutor must NOT be permitted")
	}
}

func TestRule_PermitsSignerRole(t *testing.T) {
	r := motionRule()
	if !r.PermitsSignerRole("court_clerk") {
		t.Error("court_clerk should be permitted")
	}
	if r.PermitsSignerRole("court_staff") {
		t.Error("court_staff must NOT be permitted")
	}
}

func TestRule_RequiresFiler(t *testing.T) {
	r1 := motionRule()
	if !r1.RequiresFiler() {
		t.Error("motion_continuance should require a filer")
	}
	r2 := verdictRule()
	if r2.RequiresFiler() {
		t.Error("verdict must NOT require a filer (pure ActorSigner event)")
	}
}

func TestRule_EffectiveMinCosigners(t *testing.T) {
	r := motionRule()
	if got := r.EffectiveMinCosigners(); got != 1 {
		t.Errorf("motion default: got %d, want 1", got)
	}
	r.MinSignerCosigners = 0 // explicit zero falls back to 1 for filer events
	if got := r.EffectiveMinCosigners(); got != 1 {
		t.Errorf("zero default for filer event: got %d, want 1", got)
	}
	r.MinSignerCosigners = 3
	if got := r.EffectiveMinCosigners(); got != 3 {
		t.Errorf("explicit 3: got %d, want 3", got)
	}
	// Pure-signer event with min=0 returns 0 (no Tier 2 cosig).
	v := verdictRule()
	if got := v.EffectiveMinCosigners(); got != 0 {
		t.Errorf("verdict (no filer): got %d, want 0", got)
	}
}

// ─── validateRule ──────────────────────────────────────────────────

func TestValidateRule_RejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		rule CosignatureRule
		want string
	}{
		{
			name: "empty event_type",
			rule: CosignatureRule{},
			want: "event_type required",
		},
		{
			name: "unknown filer role",
			rule: CosignatureRule{
				EventType:           "x",
				AllowedFilerRoles:   []schemas.FilerRole{"wizard"},
				RequiredSignerRoles: []string{"judge"},
			},
			want: "FilerRole closed set",
		},
		{
			name: "filer roles but no signer roles",
			rule: CosignatureRule{
				EventType:         "x",
				AllowedFilerRoles: []schemas.FilerRole{schemas.FilerRoleDefenseCounsel},
			},
			want: "no required_signer_roles",
		},
		{
			name: "empty signer role string",
			rule: CosignatureRule{
				EventType:           "x",
				RequiredSignerRoles: []string{""},
			},
			want: "required_signer_roles[0] empty",
		},
		{
			name: "negative min cosigners",
			rule: CosignatureRule{
				EventType:           "x",
				RequiredSignerRoles: []string{"judge"},
				MinSignerCosigners:  -1,
			},
			want: "min_signer_cosigners",
		},
		{
			name: "empty credential",
			rule: CosignatureRule{
				EventType:           "x",
				AllowedFilerRoles:   []schemas.FilerRole{schemas.FilerRoleDefenseCounsel},
				RequiredSignerRoles: []string{"judge"},
				RequiredCredentials: []string{""},
			},
			want: "required_credentials[0] empty",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRule(tc.rule)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !errors.Is(err, ErrInvalidRule) {
				t.Errorf("expected ErrInvalidRule, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err missing %q: %v", tc.want, err)
			}
		})
	}
}

// ─── InMemoryPolicy: Lookup / List ─────────────────────────────────

func TestInMemoryPolicy_Lookup(t *testing.T) {
	p, err := NewInMemoryPolicy([]CosignatureRule{motionRule(), verdictRule()})
	if err != nil {
		t.Fatalf("NewInMemoryPolicy: %v", err)
	}

	got, err := p.Lookup("motion_continuance")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.EventType != "motion_continuance" {
		t.Errorf("event drift: %q", got.EventType)
	}

	if _, err := p.Lookup("nonexistent"); !errors.Is(err, ErrRuleNotFound) {
		t.Errorf("expected ErrRuleNotFound, got: %v", err)
	}
}

func TestInMemoryPolicy_List_Order(t *testing.T) {
	p, _ := NewInMemoryPolicy([]CosignatureRule{
		verdictRule(),       // "verdict"
		motionRule(),        // "motion_continuance"
		{                    // "abc"
			EventType:           "abc",
			RequiredSignerRoles: []string{"judge"},
		},
	})
	got := p.List()
	want := []string{"abc", "motion_continuance", "verdict"}
	if len(got) != len(want) {
		t.Fatalf("len: got %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].EventType != w {
			t.Errorf("[%d]: got %q want %q", i, got[i].EventType, w)
		}
	}
}

// ─── Add / Duplicate / Replace ─────────────────────────────────────

func TestInMemoryPolicy_RejectsDuplicates(t *testing.T) {
	r := motionRule()
	_, err := NewInMemoryPolicy([]CosignatureRule{r, r})
	if !errors.Is(err, ErrDuplicateRule) {
		t.Errorf("expected ErrDuplicateRule, got: %v", err)
	}
}

func TestInMemoryPolicy_Add(t *testing.T) {
	p, _ := NewInMemoryPolicy([]CosignatureRule{motionRule()})
	if err := p.Add(verdictRule()); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := p.Lookup("verdict"); err != nil {
		t.Errorf("verdict missing after Add: %v", err)
	}

	// Duplicate add → ErrDuplicateRule.
	if err := p.Add(verdictRule()); !errors.Is(err, ErrDuplicateRule) {
		t.Errorf("dup add: %v", err)
	}

	// Invalid add → ErrInvalidRule.
	if err := p.Add(CosignatureRule{}); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("invalid add: %v", err)
	}
}

func TestInMemoryPolicy_Replace(t *testing.T) {
	p, _ := NewInMemoryPolicy([]CosignatureRule{motionRule(), verdictRule()})
	if err := p.Replace([]CosignatureRule{verdictRule()}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if _, err := p.Lookup("motion_continuance"); !errors.Is(err, ErrRuleNotFound) {
		t.Error("motion_continuance should be gone after Replace")
	}
	if _, err := p.Lookup("verdict"); err != nil {
		t.Errorf("verdict should remain: %v", err)
	}
}

func TestInMemoryPolicy_Replace_AtomicOnError(t *testing.T) {
	p, _ := NewInMemoryPolicy([]CosignatureRule{motionRule()})
	pre := len(p.List())

	bad := []CosignatureRule{{EventType: ""}} // invalid
	if err := p.Replace(bad); err == nil {
		t.Fatal("expected validation error")
	}

	// Policy must be unchanged after failed Replace.
	if got := len(p.List()); got != pre {
		t.Errorf("policy mutated despite Replace failure: pre=%d post=%d", pre, got)
	}
}

func TestInMemoryPolicy_Replace_RejectsDuplicates(t *testing.T) {
	p, _ := NewInMemoryPolicy([]CosignatureRule{motionRule()})
	r := motionRule()
	err := p.Replace([]CosignatureRule{r, r})
	if !errors.Is(err, ErrDuplicateRule) {
		t.Errorf("expected ErrDuplicateRule, got: %v", err)
	}
}

// ─── Concurrency ───────────────────────────────────────────────────

func TestInMemoryPolicy_ConcurrentReadsSafe(t *testing.T) {
	p, _ := NewInMemoryPolicy([]CosignatureRule{
		motionRule(), verdictRule(),
	})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = p.Lookup("motion_continuance")
				_, _ = p.Lookup("verdict")
				_ = p.List()
			}
		}()
	}
	wg.Wait()
}
