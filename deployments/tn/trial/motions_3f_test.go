/*
FILE PATH: deployments/tn/trial/motions_3f_test.go

DESCRIPTION:

	Tests for v1.8 §3F in-trial dispositive motions. Pins:
	  - 3 motion types.
	  - Each carries Advisory hearing_convened_concluded prereq.
	  - Walker accepts even without the hearing event (Advisory
	    race tolerance).
	  - motion_directed_verdict is civil-only-by-name (TRCP 50);
	    motion_judgment_acquittal is criminal-only (TRCrP 29).
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

func TestMotions3F_ExpectedEvents(t *testing.T) {
	want := map[string]bool{
		"motion_directed_verdict":   true,
		"motion_judgment_acquittal": true,
		"motion_mistrial":           true,
	}
	got := map[string]bool{}
	for _, m := range motions3F() {
		got[m.EventType] = true
	}
	if len(got) != len(want) {
		t.Errorf("§3F count: want %d, got %d", len(want), len(got))
	}
	for evt := range want {
		if !got[evt] {
			t.Errorf("§3F missing %q", evt)
		}
	}
}

func TestMotions3F_AllHaveHearingAdvisory(t *testing.T) {
	for _, m := range motions3F() {
		found := false
		for _, p := range m.AdditionalPrereqs {
			if p.Mode == prerequisites.PrereqModeAdvisory &&
				len(p.RequiredAncestor) == 1 &&
				p.RequiredAncestor[0] == "hearing_convened_concluded" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("§3F %q missing Advisory hearing_convened_concluded prereq",
				m.EventType)
		}
	}
}

func TestMotions3F_CivilOnly_DirectedVerdict(t *testing.T) {
	for _, m := range motions3F() {
		if m.EventType != "motion_directed_verdict" {
			continue
		}
		for _, f := range m.AllowedFilers {
			if f == schemas.FilerRoleProsecutor {
				t.Error("motion_directed_verdict is civil-side; prosecutor must not file")
			}
		}
		return
	}
	t.Error("motion_directed_verdict missing")
}

func TestMotions3F_CriminalOnly_JudgmentAcquittal(t *testing.T) {
	for _, m := range motions3F() {
		if m.EventType != "motion_judgment_acquittal" {
			continue
		}
		for _, f := range m.AllowedFilers {
			if f == schemas.FilerRoleCivilAttorney {
				t.Error("motion_judgment_acquittal is criminal-side; civil_attorney must not file")
			}
		}
		return
	}
	t.Error("motion_judgment_acquittal missing")
}

func TestMotions3F_InCosignatureRules(t *testing.T) {
	rules := MustCosignaturePolicy()
	for _, m := range motions3F() {
		if _, err := rules.Lookup(m.EventType); err != nil {
			t.Errorf("§3F event %q missing from CosignatureRules: %v",
				m.EventType, err)
		}
	}
}

// TestFunctional_Mistrial_AdvisoryPasses pins that motion_mistrial
// accepts even when hearing_convened_concluded is missing
// (Advisory race tolerance).
func TestFunctional_Mistrial_AdvisoryPasses(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	v := w.Check("motion_mistrial", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if !v.OK {
		t.Errorf("Advisory must NOT block: %s", v.Reason)
	}
	if len(v.Advisory) != 1 {
		t.Errorf("expected 1 Advisory violation, got %d", len(v.Advisory))
	}
}
