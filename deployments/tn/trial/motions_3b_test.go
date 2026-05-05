/*
FILE PATH: deployments/tn/trial/motions_3b_test.go

DESCRIPTION:

	Tests for v1.8 §3B dispositive motions. Pins:
	  - 6 motion types (5 + 1 catch-all).
	  - motion_judgment_on_pleadings has Hard responsive_pleading
	    prereq (pleadings closed).
	  - motion_default_judgment has Hard party_binding prereq.
	  - Filer sets: civil-side dispositive vs prosecutor-only.
	  - Both motion_summary_judgment and motion_state_dismissal
	    flow through the helper (no longer in the base file).
	  - Walker accepts/rejects appropriately.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── §3B vocabulary pin ──────────────────────────────────────────

func TestMotions3B_ExpectedEvents(t *testing.T) {
	want := map[string]bool{
		"motion_summary_judgment":          true,
		"motion_judgment_on_pleadings":     true,
		"motion_default_judgment":          true,
		"motion_state_dismissal":           true,
		"motion_dismiss_unnecessary_delay": true,
		"motion_dispositive_general":       true,
	}
	got := map[string]bool{}
	for _, m := range motions3B() {
		got[m.EventType] = true
	}
	if len(got) != len(want) {
		t.Errorf("§3B count: want %d, got %d", len(want), len(got))
	}
	for evt := range want {
		if !got[evt] {
			t.Errorf("§3B missing %q", evt)
		}
	}
}

// ─── additional prereqs ──────────────────────────────────────────

func TestMotions3B_JudgmentOnPleadingsRequiresResponsive(t *testing.T) {
	for _, m := range motions3B() {
		if m.EventType != "motion_judgment_on_pleadings" {
			continue
		}
		if len(m.AdditionalPrereqs) != 1 {
			t.Fatalf("want 1 additional prereq, got %d", len(m.AdditionalPrereqs))
		}
		p := m.AdditionalPrereqs[0]
		if p.Mode != prerequisites.PrereqModeHard {
			t.Errorf("mode: want Hard, got %v", p.Mode)
		}
		if len(p.RequiredAncestor) != 1 || p.RequiredAncestor[0] != "responsive_pleading" {
			t.Errorf("ancestor drift: %v", p.RequiredAncestor)
		}
		return
	}
	t.Error("motion_judgment_on_pleadings missing")
}

func TestMotions3B_DefaultJudgmentRequiresPartyBinding(t *testing.T) {
	for _, m := range motions3B() {
		if m.EventType != "motion_default_judgment" {
			continue
		}
		if len(m.AdditionalPrereqs) != 1 {
			t.Fatalf("want 1 additional prereq, got %d", len(m.AdditionalPrereqs))
		}
		p := m.AdditionalPrereqs[0]
		if len(p.RequiredAncestor) != 1 || p.RequiredAncestor[0] != "party_binding" {
			t.Errorf("ancestor drift: %v", p.RequiredAncestor)
		}
		return
	}
	t.Error("motion_default_judgment missing")
}

// ─── filer sets ──────────────────────────────────────────────────

func TestMotions3B_StateDismissalProsOnly(t *testing.T) {
	for _, m := range motions3B() {
		if m.EventType != "motion_state_dismissal" {
			continue
		}
		if len(m.AllowedFilers) != 1 ||
			m.AllowedFilers[0] != schemas.FilerRoleProsecutor {
			t.Errorf("motion_state_dismissal filer drift: %v", m.AllowedFilers)
		}
		return
	}
	t.Error("motion_state_dismissal missing")
}

func TestMotions3B_CatchAllFlag(t *testing.T) {
	for _, m := range motions3B() {
		if m.EventType == "motion_dispositive_general" {
			if !m.CustomTitleRequired {
				t.Error("motion_dispositive_general must have CustomTitleRequired=true")
			}
			return
		}
	}
	t.Error("motion_dispositive_general missing")
}

// ─── integration: every §3B event reaches the policies ──────────

func TestMotions3B_InCosignatureRules(t *testing.T) {
	rules := MustCosignaturePolicy()
	for _, m := range motions3B() {
		if _, err := rules.Lookup(m.EventType); err != nil {
			t.Errorf("§3B event %q missing from CosignatureRules: %v",
				m.EventType, err)
		}
	}
}

// ─── functional walks ────────────────────────────────────────────

func TestFunctional_JudgmentOnPleadings_RequiresResponsive(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	// case_initiated only → reject (responsive_pleading missing).
	v := w.Check("motion_judgment_on_pleadings", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if v.OK {
		t.Error("must reject without responsive_pleading")
	}

	// case_initiated + responsive_pleading → accept.
	v = w.Check("motion_judgment_on_pleadings", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated", "responsive_pleading"},
	})
	if !v.OK {
		t.Errorf("must accept with both prereqs: %s", v.Reason)
	}
}

func TestFunctional_DefaultJudgment_RequiresPartyBinding(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("motion_default_judgment", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if v.OK {
		t.Error("must reject without party_binding")
	}

	v = w.Check("motion_default_judgment", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated", "party_binding"},
	})
	if !v.OK {
		t.Errorf("must accept with both prereqs: %s", v.Reason)
	}
}

// ─── functional: prosecutor cannot file civil dispositive ───────

func TestFunctional_ProsecutorCannotFileCivilDispositive(t *testing.T) {
	r, _ := MustCosignaturePolicy().Lookup("motion_summary_judgment")
	if r.PermitsFilerRole(schemas.FilerRoleProsecutor) {
		t.Error("motion_summary_judgment is civil-side; prosecutor must not file")
	}
}
