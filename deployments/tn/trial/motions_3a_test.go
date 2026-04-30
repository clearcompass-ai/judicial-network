/*
FILE PATH: deployments/tn/trial/motions_3a_test.go

DESCRIPTION:
    Tests for v1.8 §3A pleading motions. Pins:
      - 9 motion types (8 + 1 catch-all).
      - Every entry follows the §3 default cosig shape.
      - Filer sets are correct per v1.8 (civil-side, criminal-
        side, both).
      - The catch-all carries CustomTitleRequired=true.
      - Every §3A event ends up in CosignatureRules() and
        PrerequisiteRules() through the helpers.
      - Walker accepts each §3A motion with case_initiated
        observed.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── §3A vocabulary pin ──────────────────────────────────────────

func TestMotions3A_ExpectedEvents(t *testing.T) {
	want := map[string]bool{
		"motion_dismiss_jurisdiction":          true,
		"motion_dismiss_process_defects":       true,
		"motion_dismiss_failure_to_state_claim": true,
		"motion_dismiss_charging_defect":       true,
		"motion_dismiss_no_probable_cause":     true,
		"motion_more_definite_statement":       true,
		"motion_to_strike":                     true,
		"motion_amend_pleadings":               true,
		"motion_pleading_general":              true,
	}
	got := map[string]bool{}
	for _, m := range motions3A() {
		got[m.EventType] = true
	}
	if len(got) != len(want) {
		t.Errorf("§3A motion count: want %d, got %d (%v)",
			len(want), len(got), got)
	}
	for evt := range want {
		if !got[evt] {
			t.Errorf("§3A missing event %q", evt)
		}
	}
	for evt := range got {
		if !want[evt] {
			t.Errorf("§3A unexpected event %q", evt)
		}
	}
}

// ─── Filer set: criminal-only motions reject civil_attorney ─────

func TestMotions3A_CriminalOnlyMotions(t *testing.T) {
	criminalOnly := map[string]bool{
		"motion_dismiss_charging_defect":   true,
		"motion_dismiss_no_probable_cause": true,
	}
	for _, m := range motions3A() {
		if !criminalOnly[m.EventType] {
			continue
		}
		hasCivil := false
		for _, f := range m.AllowedFilers {
			if f == schemas.FilerRoleCivilAttorney {
				hasCivil = true
				break
			}
		}
		if hasCivil {
			t.Errorf("§3A criminal-only motion %q must not permit civil_attorney",
				m.EventType)
		}
	}
}

func TestMotions3A_CatchAllFlag(t *testing.T) {
	for _, m := range motions3A() {
		if m.EventType == "motion_pleading_general" {
			if !m.CustomTitleRequired {
				t.Error("motion_pleading_general must have CustomTitleRequired=true")
			}
			return
		}
	}
	t.Error("motion_pleading_general missing from §3A")
}

// ─── integration: every §3A event reaches the policies ─────────

func TestMotions3A_InCosignatureRules(t *testing.T) {
	rules := MustCosignaturePolicy()
	for _, m := range motions3A() {
		if _, err := rules.Lookup(m.EventType); err != nil {
			t.Errorf("§3A event %q missing from CosignatureRules: %v",
				m.EventType, err)
		}
	}
}

func TestMotions3A_InPrerequisiteRules(t *testing.T) {
	preq := MustPrerequisitePolicy()
	for _, m := range motions3A() {
		if !preq.KnowsEventType(m.EventType) {
			t.Errorf("§3A event %q missing from PrerequisiteRules",
				m.EventType)
		}
	}
}

// ─── functional: Walker accepts each §3A with case_initiated ───

func TestFunctional_AllMotions3A_AcceptedAfterCaseInit(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	for _, m := range motions3A() {
		v := w.Check(m.EventType, prerequisites.CaseContext{
			ObservedEvents: []string{"case_initiated"},
		})
		if !v.OK {
			t.Errorf("§3A %q must accept after case_initiated: %s",
				m.EventType, v.Reason)
		}
	}
}

func TestFunctional_AllMotions3A_RejectedWithoutCaseInit(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	for _, m := range motions3A() {
		v := w.Check(m.EventType, prerequisites.CaseContext{})
		if v.OK {
			t.Errorf("§3A %q must reject without case_initiated", m.EventType)
		}
	}
}

// ─── functional: defense counsel files motion_to_strike ─────────

func TestFunctional_DefenseCounselFilesMotionToStrike(t *testing.T) {
	rules := MustCosignaturePolicy()
	r, err := rules.Lookup("motion_to_strike")
	if err != nil {
		t.Fatalf("motion_to_strike missing: %v", err)
	}
	if !r.PermitsFilerRole(schemas.FilerRoleDefenseCounsel) {
		t.Error("motion_to_strike must permit defense_counsel")
	}
	if r.PermitsFilerRole(schemas.FilerRoleProsecutor) {
		t.Error("motion_to_strike must NOT permit prosecutor (civil-side)")
	}
}
