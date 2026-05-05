/*
FILE PATH: deployments/tn/trial/motions_3h_test.go

DESCRIPTION:

	Tests for v1.8 §3H post-trial / post-conviction motions.
	Pins:
	  - 11 motion types (10 + 1 catch-all).
	  - Each has a Hard prereq tied to verdict / final_judgment
	    (see per-event semantics).
	  - Defense-only motions (reduction of sentence, correct
	    illegal sentence, coram nobis, post-conviction relief).
	  - Civil-only (motion_discretionary_costs).
	  - Catch-all flag.
	  - Walker accept/reject around verdict / final_judgment.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

func TestMotions3H_ExpectedEvents(t *testing.T) {
	want := map[string]bool{
		"motion_new_trial":                      true,
		"motion_alter_amend_judgment":           true,
		"motion_renewed_directed_verdict_jnov":  true,
		"motion_arrest_of_judgment":             true,
		"motion_set_aside_relief_from_judgment": true,
		"motion_reduction_of_sentence":          true,
		"motion_correct_illegal_sentence":       true,
		"motion_discretionary_costs":            true,
		"petition_coram_nobis":                  true,
		"petition_post_conviction_relief":       true,
		"motion_post_trial_general":             true,
	}
	got := map[string]bool{}
	for _, m := range motions3H() {
		got[m.EventType] = true
	}
	if len(got) != len(want) {
		t.Errorf("§3H count: want %d, got %d", len(want), len(got))
	}
	for evt := range want {
		if !got[evt] {
			t.Errorf("§3H missing %q", evt)
		}
	}
}

func TestMotions3H_DefenseOnlyMotions(t *testing.T) {
	defenseOnly := map[string]bool{
		"motion_reduction_of_sentence":    true,
		"motion_correct_illegal_sentence": true,
		"petition_coram_nobis":            true,
		"petition_post_conviction_relief": true,
	}
	for _, m := range motions3H() {
		if !defenseOnly[m.EventType] {
			continue
		}
		if len(m.AllowedFilers) != 1 ||
			m.AllowedFilers[0] != schemas.FilerRoleDefenseCounsel {
			t.Errorf("§3H %q must be defense_counsel only; got %v",
				m.EventType, m.AllowedFilers)
		}
	}
}

func TestMotions3H_CivilOnly_DiscretionaryCosts(t *testing.T) {
	for _, m := range motions3H() {
		if m.EventType != "motion_discretionary_costs" {
			continue
		}
		if len(m.AllowedFilers) != 1 ||
			m.AllowedFilers[0] != schemas.FilerRoleCivilAttorney {
			t.Errorf("motion_discretionary_costs must be civil_attorney only; got %v",
				m.AllowedFilers)
		}
		return
	}
	t.Error("motion_discretionary_costs missing")
}

func TestMotions3H_AllHaveHardPostJudgmentPrereq(t *testing.T) {
	for _, m := range motions3H() {
		hardCount := 0
		for _, p := range m.AdditionalPrereqs {
			if p.Mode == prerequisites.PrereqModeHard {
				hardCount++
			}
		}
		if hardCount == 0 {
			t.Errorf("§3H %q must have at least one Hard prereq",
				m.EventType)
		}
	}
}

func TestMotions3H_CatchAllFlag(t *testing.T) {
	for _, m := range motions3H() {
		if m.EventType == "motion_post_trial_general" {
			if !m.CustomTitleRequired {
				t.Error("motion_post_trial_general must have CustomTitleRequired=true")
			}
			return
		}
	}
	t.Error("motion_post_trial_general missing")
}

// ─── functional walks ────────────────────────────────────────────

func TestFunctional_NewTrial_RequiresVerdictOrFJ(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("motion_new_trial", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if v.OK {
		t.Error("must reject without verdict/final_judgment")
	}

	v = w.Check("motion_new_trial", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated", "verdict"},
	})
	if !v.OK {
		t.Errorf("must accept with verdict: %s", v.Reason)
	}

	v = w.Check("motion_new_trial", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated", "final_judgment"},
	})
	if !v.OK {
		t.Errorf("must accept with final_judgment: %s", v.Reason)
	}
}

func TestFunctional_JNOV_RequiresVerdictExclusively(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	// final_judgment alone is not enough — JNOV is post-VERDICT.
	v := w.Check("motion_renewed_directed_verdict_jnov",
		prerequisites.CaseContext{
			ObservedEvents: []string{"case_initiated", "final_judgment"},
		})
	if v.OK {
		t.Error("JNOV must reject without verdict (final_judgment alone)")
	}

	v = w.Check("motion_renewed_directed_verdict_jnov",
		prerequisites.CaseContext{
			ObservedEvents: []string{"case_initiated", "verdict"},
		})
	if !v.OK {
		t.Errorf("JNOV must accept with verdict: %s", v.Reason)
	}
}

func TestMotions3H_InCosignatureRules(t *testing.T) {
	rules := MustCosignaturePolicy()
	for _, m := range motions3H() {
		if _, err := rules.Lookup(m.EventType); err != nil {
			t.Errorf("§3H event %q missing from CosignatureRules: %v",
				m.EventType, err)
		}
	}
}
