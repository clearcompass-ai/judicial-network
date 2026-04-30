/*
FILE PATH: deployments/tn/trial/motions_3i_test.go

DESCRIPTION:
    Tests for v1.8 §3I appellate-bridge motions. Pins:
      - 3 motion types (no catch-all per v1.8).
      - motion_interlocutory_appeal — Hard interlocutory_order.
      - motion_stay_of_execution_pending_appeal — Hard notice_of_appeal.
      - motion_extraordinary_appeal — default only.
      - All open to every advocate.
      - Walker accept/reject around prereqs.

    With §3I, every v1.8 §3 section is now populated.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
)

func TestMotions3I_ExpectedEvents(t *testing.T) {
	want := map[string]bool{
		"motion_interlocutory_appeal":             true,
		"motion_extraordinary_appeal":             true,
		"motion_stay_of_execution_pending_appeal": true,
	}
	got := map[string]bool{}
	for _, m := range motions3I() {
		got[m.EventType] = true
	}
	if len(got) != len(want) {
		t.Errorf("§3I count: want %d, got %d", len(want), len(got))
	}
	for evt := range want {
		if !got[evt] {
			t.Errorf("§3I missing %q", evt)
		}
	}
}

func TestMotions3I_HardPrereqs(t *testing.T) {
	want := map[string]string{
		"motion_interlocutory_appeal":             "interlocutory_order",
		"motion_stay_of_execution_pending_appeal": "notice_of_appeal",
	}
	for _, m := range motions3I() {
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
			t.Errorf("§3I %q must have Hard %q prereq",
				m.EventType, needAncestor)
		}
	}
}

func TestMotions3I_InCosignatureRules(t *testing.T) {
	rules := MustCosignaturePolicy()
	for _, m := range motions3I() {
		if _, err := rules.Lookup(m.EventType); err != nil {
			t.Errorf("§3I event %q missing from CosignatureRules: %v",
				m.EventType, err)
		}
	}
}

func TestFunctional_StayPendingAppeal_RequiresNoticeOfAppeal(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("motion_stay_of_execution_pending_appeal",
		prerequisites.CaseContext{
			ObservedEvents: []string{"case_initiated"},
		})
	if v.OK {
		t.Error("must reject without notice_of_appeal")
	}

	v = w.Check("motion_stay_of_execution_pending_appeal",
		prerequisites.CaseContext{
			ObservedEvents: []string{"case_initiated", "notice_of_appeal"},
		})
	if !v.OK {
		t.Errorf("must accept with notice_of_appeal: %s", v.Reason)
	}
}

func TestFunctional_InterlocutoryAppeal_RequiresInterlocutoryOrder(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("motion_interlocutory_appeal", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if v.OK {
		t.Error("must reject without interlocutory_order")
	}

	v = w.Check("motion_interlocutory_appeal", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated", "interlocutory_order"},
	})
	if !v.OK {
		t.Errorf("must accept with interlocutory_order: %s", v.Reason)
	}
}

// TestSection_AllSectionsPopulated pins that with §3I landing,
// every motions_3X stub function returns at least one motion —
// no section is empty.
func TestSection_AllSectionsPopulated(t *testing.T) {
	for name, fn := range map[string]func() []motionSpec{
		"§3A": motions3A,
		"§3B": motions3B,
		"§3C": motions3C,
		"§3D": motions3D,
		"§3E": motions3E,
		"§3F": motions3F,
		"§3G": motions3G,
		"§3H": motions3H,
		"§3I": motions3I,
	} {
		if got := len(fn()); got == 0 {
			t.Errorf("%s must be populated; got 0 motions", name)
		}
	}
}
