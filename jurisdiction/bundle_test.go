// FILE PATH: jurisdiction/bundle_test.go
//
// Tests pinning the Bundle interface contract + Validate gate.
// Uses a small inline fake Bundle to avoid pulling in any
// jurisdiction-specific code (deployments/...).
package jurisdiction

import (
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── inline fake Bundle ─────────────────────────────────────────────

type fakeBundle struct {
	exchange string
	roles    schemas.RoleCatalog
	cosig    policy.CosignatureMixPolicy
	preqs    prerequisites.Policy
}

func (f *fakeBundle) ExchangeDID() string                      { return f.exchange }
func (f *fakeBundle) RoleCatalog() schemas.RoleCatalog         { return f.roles }
func (f *fakeBundle) CosignaturePolicy() policy.CosignatureMixPolicy {
	return f.cosig
}
func (f *fakeBundle) PrerequisitePolicy() prerequisites.Policy { return f.preqs }

// minimalCatalog returns a 1-role catalog so Validate's len-check
// passes.
func minimalCatalog(t *testing.T) schemas.RoleCatalog {
	t.Helper()
	c, err := schemas.NewInMemoryCatalog([]schemas.Role{
		{
			Name:            "judge",
			Actor:           schemas.ActorSigner,
			MaxDuration:     365 * 24 * time.Hour,
			DefaultDuration: 365 * 24 * time.Hour,
			AllowedScope:    []string{"case_decision"},
			DefaultScope:    []string{"case_decision"},
		},
	})
	if err != nil {
		t.Fatalf("minimalCatalog: %v", err)
	}
	return c
}

func minimalCosigPolicy(t *testing.T, eventTypes ...string) policy.CosignatureMixPolicy {
	t.Helper()
	rules := make([]policy.CosignatureRule, 0, len(eventTypes))
	for _, e := range eventTypes {
		rules = append(rules, policy.CosignatureRule{
			EventType:           e,
			RequiredSignerRoles: []string{"judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		})
	}
	p, err := policy.NewInMemoryPolicy(rules)
	if err != nil {
		t.Fatalf("cosig policy: %v", err)
	}
	return p
}

func minimalPrereqPolicy(t *testing.T, eventTypes ...string) prerequisites.Policy {
	t.Helper()
	rules := make(map[string][]prerequisites.Prereq, len(eventTypes))
	for _, e := range eventTypes {
		rules[e] = nil
	}
	p, err := prerequisites.NewInMemoryPolicy(rules)
	if err != nil {
		t.Fatalf("prereq policy: %v", err)
	}
	return p
}

func goodBundle(t *testing.T) Bundle {
	t.Helper()
	return &fakeBundle{
		exchange: "did:web:test:exchange",
		roles:    minimalCatalog(t),
		cosig:    minimalCosigPolicy(t, "evt_a"),
		preqs:    minimalPrereqPolicy(t, "evt_a"),
	}
}

// ─── Validate ───────────────────────────────────────────────────────

func TestValidate_HappyPath(t *testing.T) {
	if err := Validate(goodBundle(t)); err != nil {
		t.Errorf("good bundle: %v", err)
	}
}

func TestValidate_NilBundle(t *testing.T) {
	if err := Validate(nil); !errors.Is(err, ErrInvalidBundle) {
		t.Errorf("nil bundle: %v", err)
	}
}

func TestValidate_EmptyExchangeDID(t *testing.T) {
	b := &fakeBundle{
		exchange: "",
		roles:    minimalCatalog(t),
		cosig:    minimalCosigPolicy(t, "evt_a"),
		preqs:    minimalPrereqPolicy(t, "evt_a"),
	}
	if err := Validate(b); !errors.Is(err, ErrInvalidBundle) {
		t.Errorf("empty exchange: %v", err)
	}
}

func TestValidate_NilRoleCatalog(t *testing.T) {
	b := &fakeBundle{
		exchange: "did:web:x",
		roles:    nil,
		cosig:    minimalCosigPolicy(t, "evt_a"),
		preqs:    minimalPrereqPolicy(t, "evt_a"),
	}
	if err := Validate(b); !errors.Is(err, ErrInvalidBundle) {
		t.Errorf("nil catalog: %v", err)
	}
}

func TestValidate_EmptyRoleCatalog(t *testing.T) {
	emptyCat, err := schemas.NewInMemoryCatalog(nil)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	b := &fakeBundle{
		exchange: "did:web:x",
		roles:    emptyCat,
		cosig:    minimalCosigPolicy(t, "evt_a"),
		preqs:    minimalPrereqPolicy(t, "evt_a"),
	}
	if err := Validate(b); !errors.Is(err, ErrInvalidBundle) {
		t.Errorf("empty catalog: %v", err)
	}
}

func TestValidate_NilCosignaturePolicy(t *testing.T) {
	b := &fakeBundle{
		exchange: "did:web:x",
		roles:    minimalCatalog(t),
		cosig:    nil,
		preqs:    minimalPrereqPolicy(t, "evt_a"),
	}
	if err := Validate(b); !errors.Is(err, ErrInvalidBundle) {
		t.Errorf("nil cosig: %v", err)
	}
}

func TestValidate_NilPrerequisitePolicy(t *testing.T) {
	b := &fakeBundle{
		exchange: "did:web:x",
		roles:    minimalCatalog(t),
		cosig:    minimalCosigPolicy(t, "evt_a"),
		preqs:    nil,
	}
	if err := Validate(b); !errors.Is(err, ErrInvalidBundle) {
		t.Errorf("nil preqs: %v", err)
	}
}

func TestValidate_VocabularyMismatch(t *testing.T) {
	// Cosig has "evt_a"; prereq does NOT — should fail.
	b := &fakeBundle{
		exchange: "did:web:x",
		roles:    minimalCatalog(t),
		cosig:    minimalCosigPolicy(t, "evt_a"),
		preqs:    minimalPrereqPolicy(t, "evt_b"),
	}
	if err := Validate(b); !errors.Is(err, ErrVocabularyMismatch) {
		t.Errorf("expected vocabulary mismatch, got: %v", err)
	}
}

func TestValidate_PrereqMaySupersetCosig(t *testing.T) {
	// Prereq vocabulary includes bootstrap events that have no
	// cosignature mix — that's allowed.
	b := &fakeBundle{
		exchange: "did:web:x",
		roles:    minimalCatalog(t),
		cosig:    minimalCosigPolicy(t, "evt_a"),
		preqs:    minimalPrereqPolicy(t, "evt_a", "case_initiated"),
	}
	if err := Validate(b); err != nil {
		t.Errorf("prereq superset must be allowed: %v", err)
	}
}
