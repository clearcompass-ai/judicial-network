/*
FILE PATH: deployments/tn/trial/motions_3g_test.go

DESCRIPTION:
    Tests for v1.8 §3G docket-management motions. Pins:
      - 9 motion types (8 + 1 catch-all).
      - Hard prereqs: substitution_parties (party_binding),
        withdraw_counsel (counsel_appearance),
        disqualification_recusal (judicial_assignment).
      - Advisory prereq: continuance (scheduling_order).
      - Catch-all (motion_procedural_general) flag.
      - Walker accepts/rejects appropriately.
      - motion_continuance permits all 3 advocate roles
        (multi-filer pin moved here from base after motion
        relocation).
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

func TestMotions3G_ExpectedEvents(t *testing.T) {
	want := map[string]bool{
		"motion_continuance":             true,
		"motion_consolidation_severance": true,
		"motion_substitution_parties":    true,
		"motion_change_of_venue":         true,
		"motion_withdraw_counsel":        true,
		"motion_disqualification_recusal": true,
		"motion_juvenile_transfer_custody": true,
		"motion_bond_modification":       true,
		"motion_procedural_general":      true,
	}
	got := map[string]bool{}
	for _, m := range motions3G() {
		got[m.EventType] = true
	}
	if len(got) != len(want) {
		t.Errorf("§3G count: want %d, got %d", len(want), len(got))
	}
	for evt := range want {
		if !got[evt] {
			t.Errorf("§3G missing %q", evt)
		}
	}
}

func TestMotions3G_HardPrereqs(t *testing.T) {
	want := map[string]string{
		"motion_substitution_parties":     "party_binding",
		"motion_withdraw_counsel":         "counsel_appearance",
		"motion_disqualification_recusal": "judicial_assignment",
	}
	for _, m := range motions3G() {
		needAncestor, ok := want[m.EventType]
		if !ok {
			continue
		}
		found := false
		for _, p := range m.AdditionalPrereqs {
			if p.Mode == prerequisites.PrereqModeHard &&
				len(p.RequiredAncestor) == 1 &&
				p.RequiredAncestor[0] == needAncestor {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("§3G %q must have Hard %q prereq",
				m.EventType, needAncestor)
		}
	}
}

func TestMotions3G_ContinuanceAdvisory(t *testing.T) {
	for _, m := range motions3G() {
		if m.EventType != "motion_continuance" {
			continue
		}
		found := false
		for _, p := range m.AdditionalPrereqs {
			if p.Mode == prerequisites.PrereqModeAdvisory &&
				len(p.RequiredAncestor) == 1 &&
				p.RequiredAncestor[0] == "scheduling_order" {
				found = true
				break
			}
		}
		if !found {
			t.Error("motion_continuance must have Advisory scheduling_order prereq")
		}
		return
	}
	t.Error("motion_continuance missing")
}

func TestMotions3G_CatchAllFlag(t *testing.T) {
	for _, m := range motions3G() {
		if m.EventType == "motion_procedural_general" {
			if !m.CustomTitleRequired {
				t.Error("motion_procedural_general must have CustomTitleRequired=true")
			}
			return
		}
	}
	t.Error("motion_procedural_general missing")
}

func TestMotions3G_InCosignatureRules(t *testing.T) {
	rules := MustCosignaturePolicy()
	for _, m := range motions3G() {
		if _, err := rules.Lookup(m.EventType); err != nil {
			t.Errorf("§3G event %q missing from CosignatureRules: %v",
				m.EventType, err)
		}
	}
}

// motion_continuance multi-filer pin (moved from base after the
// motion relocated into §3G).
func TestCosignatureRules_MotionContinuanceMultipleFilers(t *testing.T) {
	r, err := MustCosignaturePolicy().Lookup("motion_continuance")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	for _, want := range []schemas.FilerRole{
		schemas.FilerRoleDefenseCounsel,
		schemas.FilerRoleCivilAttorney,
		schemas.FilerRoleProsecutor,
	} {
		if !r.PermitsFilerRole(want) {
			t.Errorf("motion_continuance must permit %q", want)
		}
	}
	if r.PermitsFilerRole(schemas.FilerRoleFiduciary) {
		t.Error("motion_continuance must NOT permit fiduciary")
	}
}

// ─── functional walks ────────────────────────────────────────────

func TestFunctional_WithdrawCounsel_RequiresAppearance(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("motion_withdraw_counsel", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if v.OK {
		t.Error("must reject without counsel_appearance")
	}

	v = w.Check("motion_withdraw_counsel", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated", "counsel_appearance"},
	})
	if !v.OK {
		t.Errorf("must accept with counsel_appearance: %s", v.Reason)
	}
}

func TestFunctional_RecusalRequiresAssignment(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("motion_disqualification_recusal", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if v.OK {
		t.Error("must reject without judicial_assignment")
	}

	v = w.Check("motion_disqualification_recusal", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated", "judicial_assignment"},
	})
	if !v.OK {
		t.Errorf("must accept with judicial_assignment: %s", v.Reason)
	}
}

// motion_continuance walk (moved here from base after relocation).
func TestWalk_MotionContinuance_RequiresCaseInit(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("motion_continuance", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if !v.OK {
		t.Errorf("with case_initiated must be OK: %+v", v)
	}

	v = w.Check("motion_continuance", prerequisites.CaseContext{
		ObservedEvents: nil,
	})
	if v.OK {
		t.Error("without case_initiated must be rejected")
	}
}
