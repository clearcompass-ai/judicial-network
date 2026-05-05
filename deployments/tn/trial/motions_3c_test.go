/*
FILE PATH: deployments/tn/trial/motions_3c_test.go

DESCRIPTION:

	Tests for v1.8 §3C equitable, provisional & class motions.
	Pins:
	  - 4 motion types (3 + 1 catch-all).
	  - Class certification is civil-only (the structural
	    invariant: only civil_attorneys move for class cert).
	  - Catch-all carries CustomTitleRequired.
	  - All §3C events reach both policies via the helpers.
	  - Walker accepts each with case_initiated.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

func TestMotions3C_ExpectedEvents(t *testing.T) {
	want := map[string]bool{
		"motion_tro_preliminary_injunction": true,
		"motion_attachment_receivership":    true,
		"motion_class_certification":        true,
		"motion_equitable_general":          true,
	}
	got := map[string]bool{}
	for _, m := range motions3C() {
		got[m.EventType] = true
	}
	if len(got) != len(want) {
		t.Errorf("§3C count: want %d, got %d", len(want), len(got))
	}
	for evt := range want {
		if !got[evt] {
			t.Errorf("§3C missing %q", evt)
		}
	}
}

func TestMotions3C_ClassCertificationCivilOnly(t *testing.T) {
	for _, m := range motions3C() {
		if m.EventType != "motion_class_certification" {
			continue
		}
		if len(m.AllowedFilers) != 1 ||
			m.AllowedFilers[0] != schemas.FilerRoleCivilAttorney {
			t.Errorf("motion_class_certification filer drift: %v",
				m.AllowedFilers)
		}
		return
	}
	t.Error("motion_class_certification missing")
}

func TestMotions3C_CatchAllFlag(t *testing.T) {
	for _, m := range motions3C() {
		if m.EventType == "motion_equitable_general" {
			if !m.CustomTitleRequired {
				t.Error("motion_equitable_general must have CustomTitleRequired=true")
			}
			return
		}
	}
	t.Error("motion_equitable_general missing")
}

func TestMotions3C_InCosignatureRules(t *testing.T) {
	rules := MustCosignaturePolicy()
	for _, m := range motions3C() {
		if _, err := rules.Lookup(m.EventType); err != nil {
			t.Errorf("§3C event %q missing from CosignatureRules: %v",
				m.EventType, err)
		}
	}
}

func TestMotions3C_InPrerequisiteRules(t *testing.T) {
	preq := MustPrerequisitePolicy()
	for _, m := range motions3C() {
		if !preq.KnowsEventType(m.EventType) {
			t.Errorf("§3C event %q missing from PrerequisiteRules",
				m.EventType)
		}
	}
}

func TestFunctional_AllMotions3C_AcceptedAfterCaseInit(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	for _, m := range motions3C() {
		v := w.Check(m.EventType, prerequisites.CaseContext{
			ObservedEvents: []string{"case_initiated"},
		})
		if !v.OK {
			t.Errorf("§3C %q must accept after case_initiated: %s",
				m.EventType, v.Reason)
		}
	}
}

// TestFunctional_ProsecutorCannotFileClassCert pins the v1.8 rule
// that class actions are a civil-only construct: a prosecutor
// cannot move for class certification.
func TestFunctional_ProsecutorCannotFileClassCert(t *testing.T) {
	r, err := MustCosignaturePolicy().Lookup("motion_class_certification")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if r.PermitsFilerRole(schemas.FilerRoleProsecutor) {
		t.Error("prosecutor must NOT file motion_class_certification")
	}
	if r.PermitsFilerRole(schemas.FilerRoleDefenseCounsel) {
		t.Error("defense counsel must NOT file motion_class_certification (civil-only)")
	}
}
