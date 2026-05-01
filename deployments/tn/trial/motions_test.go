/*
FILE PATH: deployments/tn/trial/motions_test.go

DESCRIPTION:
    Tests for the motionSpec abstraction + helpers. Covers:
      - allMotions() concatenation across §3A–§3I.
      - motionCosigRule produces the canonical TN trial shape:
          court_clerk-signed, intra-exchange, MinSignerCosigners=1,
          RequiredCredentials defaulting to ["bpr_number"].
      - Override of RequiredCredentials propagates.
      - motionPrereqs prepends Hard case_initiated.
      - AdditionalPrereqs append after the default.
      - motionCosignatureRules / motionPrerequisiteRules build
        consistent vocabularies (every motion appears in both).
      - With empty section stubs (this commit), every helper
        returns a zero-length slice / map.
      - caseInitAncestor is the shared Hard prereq.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── allMotions == sum of every section ──────────────────────────

// TestAllMotions_EqualsSectionSum pins that allMotions() returns
// exactly the union of motions3A()..motions3I(). Adding a new
// section must extend allMotions; this guards against missing
// the call.
func TestAllMotions_EqualsSectionSum(t *testing.T) {
	want := len(motions3A()) + len(motions3B()) + len(motions3C()) +
		len(motions3D()) + len(motions3E()) + len(motions3F()) +
		len(motions3G()) + len(motions3H()) + len(motions3I())
	if got := len(allMotions()); got != want {
		t.Errorf("allMotions() = %d; sum of sections = %d", got, want)
	}
}

func TestMotionCosignatureRules_OnePerMotion(t *testing.T) {
	want := len(allMotions())
	if got := len(motionCosignatureRules()); got != want {
		t.Errorf("motionCosignatureRules = %d; allMotions = %d", got, want)
	}
}

func TestMotionPrerequisiteRules_OnePerMotion(t *testing.T) {
	want := len(allMotions())
	if got := len(motionPrerequisiteRules()); got != want {
		t.Errorf("motionPrerequisiteRules = %d; allMotions = %d", got, want)
	}
}

// ─── motionCosigRule shape ───────────────────────────────────────

func TestMotionCosigRule_DefaultShape(t *testing.T) {
	spec := motionSpec{
		EventType: "motion_test",
		AllowedFilers: []schemas.FilerRole{
			schemas.FilerRoleDefenseCounsel,
		},
	}
	r := motionCosigRule(spec)

	if r.EventType != "motion_test" {
		t.Errorf("EventType drift: %q", r.EventType)
	}
	if !r.IntraExchangeOnly {
		t.Error("default must be intra-exchange")
	}
	if r.MinSignerCosigners != 1 {
		t.Errorf("MinSignerCosigners default: want 1, got %d",
			r.MinSignerCosigners)
	}
	if len(r.RequiredSignerRoles) != 1 || r.RequiredSignerRoles[0] != "court_clerk" {
		t.Errorf("RequiredSignerRoles default: want [court_clerk], got %v",
			r.RequiredSignerRoles)
	}
	if len(r.RequiredCredentials) != 1 || r.RequiredCredentials[0] != "bpr_number" {
		t.Errorf("RequiredCredentials default: want [bpr_number], got %v",
			r.RequiredCredentials)
	}
}

func TestMotionCosigRule_CredentialsOverride(t *testing.T) {
	spec := motionSpec{
		EventType:           "motion_other",
		AllowedFilers:       []schemas.FilerRole{schemas.FilerRoleProsecutor},
		RequiredCredentials: []string{"prosecutor_id"},
	}
	r := motionCosigRule(spec)
	if len(r.RequiredCredentials) != 1 || r.RequiredCredentials[0] != "prosecutor_id" {
		t.Errorf("override drift: %v", r.RequiredCredentials)
	}
}

func TestMotionCosigRule_FilerSetPropagates(t *testing.T) {
	spec := motionSpec{
		EventType: "motion_three_filers",
		AllowedFilers: []schemas.FilerRole{
			schemas.FilerRoleDefenseCounsel,
			schemas.FilerRoleCivilAttorney,
			schemas.FilerRoleProsecutor,
		},
	}
	r := motionCosigRule(spec)
	if len(r.AllowedFilerRoles) != 3 {
		t.Errorf("AllowedFilerRoles count: want 3, got %d",
			len(r.AllowedFilerRoles))
	}
	for _, want := range []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleCivilAttorney,
		schemas.FilerRoleProsecutor,
	} {
		found := false
		for _, got := range r.AllowedFilerRoles {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Filer %q missing from rule", want)
		}
	}
}

// ─── motionPrereqs default + additional ───────────────────────────

func TestMotionPrereqs_DefaultsToCaseInitOnly(t *testing.T) {
	spec := motionSpec{EventType: "motion_simple"}
	got := motionPrereqs(spec)
	if len(got) != 1 {
		t.Fatalf("default prereq count: want 1, got %d", len(got))
	}
	if got[0].Mode != prerequisites.PrereqModeHard {
		t.Errorf("default prereq mode: want Hard, got %v", got[0].Mode)
	}
	if len(got[0].RequiredAncestor) != 1 || got[0].RequiredAncestor[0] != "case_initiated" {
		t.Errorf("default ancestor drift: %v", got[0].RequiredAncestor)
	}
}

func TestMotionPrereqs_AppendsAdditional(t *testing.T) {
	addl := prerequisites.Prereq{
		Mode:             prerequisites.PrereqModeHard,
		RequiredAncestor: []string{"responsive_pleading"},
		Reason:           "test additional prereq",
	}
	spec := motionSpec{
		EventType:         "motion_with_extra",
		AdditionalPrereqs: []prerequisites.Prereq{addl},
	}
	got := motionPrereqs(spec)
	if len(got) != 2 {
		t.Fatalf("with-additional prereq count: want 2, got %d", len(got))
	}
	// case_initiated must come first (default).
	if got[0].RequiredAncestor[0] != "case_initiated" {
		t.Errorf("first prereq must be case_initiated, got %v",
			got[0].RequiredAncestor)
	}
	// Additional prereq must follow.
	if got[1].RequiredAncestor[0] != "responsive_pleading" {
		t.Errorf("second prereq must be additional, got %v",
			got[1].RequiredAncestor)
	}
}

// ─── caseInitAncestor pin ────────────────────────────────────────

func TestCaseInitAncestor_HardCaseInitiated(t *testing.T) {
	if caseInitAncestor.Mode != prerequisites.PrereqModeHard {
		t.Errorf("caseInitAncestor mode drift: %v", caseInitAncestor.Mode)
	}
	if len(caseInitAncestor.RequiredAncestor) != 1 ||
		caseInitAncestor.RequiredAncestor[0] != "case_initiated" {
		t.Errorf("caseInitAncestor target drift: %v",
			caseInitAncestor.RequiredAncestor)
	}
}

// ─── helper integration: rules ↔ prereqs vocabulary parity ──────

// TestMotionRules_VocabularyParity pins that every motion in the
// cosig rules also appears in the prereq vocabulary (and vice
// versa). Drift here would break jurisdiction.Validate.
func TestMotionRules_VocabularyParity(t *testing.T) {
	cosig := motionCosignatureRules()
	preq := motionPrerequisiteRules()

	cosigSet := map[string]bool{}
	for _, r := range cosig {
		cosigSet[r.EventType] = true
	}
	for _, r := range cosig {
		if _, ok := preq[r.EventType]; !ok {
			t.Errorf("cosig event %q missing from prereq vocabulary",
				r.EventType)
		}
	}
	for evt := range preq {
		if !cosigSet[evt] {
			t.Errorf("prereq event %q missing from cosig rules", evt)
		}
	}
}

// TestMotionRules_BundleStillValidates pins that wiring the
// motion helpers into CosignatureRules / PrerequisiteRules
// keeps the bundle valid against jurisdiction.Validate. With
// empty section stubs nothing is added, but this guards the
// integration shape.
func TestMotionRules_PolicyConstructible(t *testing.T) {
	if _, err := policy.NewInMemoryPolicy(motionCosignatureRules()); err != nil {
		t.Errorf("motion cosig rules failed construction: %v", err)
	}
	if _, err := prerequisites.NewInMemoryPolicy(motionPrerequisiteRules()); err != nil {
		t.Errorf("motion prereq rules failed construction: %v", err)
	}
}
