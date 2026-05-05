/*
FILE PATH: deployments/tn/trial/motions_3e_test.go

DESCRIPTION:

	Tests for v1.8 §3E trial-prep motions. Pins:
	  - 5 motion types (no catch-all in §3E per v1.8).
	  - motion_suppress / motion_competency_evaluation are
	    criminal-only (defense + prosecutor; no civil_attorney).
	  - All §3E motions reach both policies via helpers.
	  - Walker accepts each with case_initiated.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

func TestMotions3E_ExpectedEvents(t *testing.T) {
	want := map[string]bool{
		"motion_in_limine":                 true,
		"motion_suppress":                  true,
		"motion_judicial_notice":           true,
		"motion_special_jury_instructions": true,
		"motion_competency_evaluation":     true,
	}
	got := map[string]bool{}
	for _, m := range motions3E() {
		got[m.EventType] = true
	}
	if len(got) != len(want) {
		t.Errorf("§3E count: want %d, got %d", len(want), len(got))
	}
	for evt := range want {
		if !got[evt] {
			t.Errorf("§3E missing %q", evt)
		}
	}
}

// motion_suppress and motion_competency_evaluation are criminal-
// only — civil_attorney must NOT be in the filer set.
func TestMotions3E_CriminalOnlyMotions(t *testing.T) {
	criminal := map[string]bool{
		"motion_suppress":              true,
		"motion_competency_evaluation": true,
	}
	for _, m := range motions3E() {
		if !criminal[m.EventType] {
			continue
		}
		for _, f := range m.AllowedFilers {
			if f == schemas.FilerRoleCivilAttorney {
				t.Errorf("§3E criminal-only %q must not permit civil_attorney",
					m.EventType)
			}
		}
	}
}

func TestMotions3E_InCosignatureRules(t *testing.T) {
	rules := MustCosignaturePolicy()
	for _, m := range motions3E() {
		if _, err := rules.Lookup(m.EventType); err != nil {
			t.Errorf("§3E event %q missing from CosignatureRules: %v",
				m.EventType, err)
		}
	}
}

func TestFunctional_AllMotions3E_AcceptedAfterCaseInit(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	for _, m := range motions3E() {
		v := w.Check(m.EventType, prerequisites.CaseContext{
			ObservedEvents: []string{"case_initiated"},
		})
		if !v.OK {
			t.Errorf("§3E %q must accept after case_initiated: %s",
				m.EventType, v.Reason)
		}
	}
}

// TestFunctional_CivilAttorneyCannotSuppress pins the criminal-
// only invariant for motion_suppress.
func TestFunctional_CivilAttorneyCannotSuppress(t *testing.T) {
	r, err := MustCosignaturePolicy().Lookup("motion_suppress")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if r.PermitsFilerRole(schemas.FilerRoleCivilAttorney) {
		t.Error("civil_attorney must NOT file motion_suppress")
	}
	if !r.PermitsFilerRole(schemas.FilerRoleDefenseCounsel) {
		t.Error("defense_counsel must file motion_suppress")
	}
	if !r.PermitsFilerRole(schemas.FilerRoleProsecutor) {
		t.Error("prosecutor must file motion_suppress")
	}
}
