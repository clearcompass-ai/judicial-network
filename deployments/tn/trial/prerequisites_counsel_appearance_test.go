/*
FILE PATH: deployments/tn/trial/prerequisites_counsel_appearance_test.go

DESCRIPTION:

	Targeted prereq-walker tests for the v1.8 §1
	counsel_appearance event:

	  - Hard: case_initiated ancestor (the case root must exist
	    before counsel can appear).
	  - Walker accepts when case_initiated is observed.
	  - Walker rejects (WalkRejectMissingAncestor) when not.
	  - The Advisory "party_binding for each binding_id in
	    represents" check is enforced at the verifier (payload
	    walk over represents) — outside the prereq Walker's
	    single-event surface — and pinned in the
	    api/exchange/handlers integration test once submit-
	    handler gates land.

	Functional tests emulate real attorney filings.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
)

// ─── Hard: case_initiated ancestor ────────────────────────────────

func TestWalk_CounselAppearance_RequiresCaseInit(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	// Without case_initiated → reject.
	v := w.Check("counsel_appearance",
		prerequisites.CaseContext{ObservedEvents: nil})
	if v.OK {
		t.Error("counsel_appearance without case_initiated must reject")
	}
	if v.Rejection != prerequisites.WalkRejectMissingAncestor {
		t.Errorf("rejection drift: want %s, got %s",
			prerequisites.WalkRejectMissingAncestor, v.Rejection)
	}

	// With case_initiated → accept.
	v = w.Check("counsel_appearance", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if !v.OK {
		t.Errorf("counsel_appearance with case_initiated must accept: %+v", v)
	}
}

// ─── functional emulation ────────────────────────────────────────

// TestFunctional_CounselAppearance_AfterPartyBinding emulates the
// canonical flow: case_initiated → party_binding for the
// defendant → defense counsel files counsel_appearance. The
// Walker accepts; the binding-side Advisory check is enforced
// elsewhere.
func TestFunctional_CounselAppearance_AfterPartyBinding(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	v := w.Check("counsel_appearance", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated", "party_binding"},
	})
	if !v.OK {
		t.Errorf("counsel_appearance after case_initiated + party_binding must accept: %+v",
			v)
	}
}

// TestFunctional_CounselAppearance_BeforePartyBindingIsAccepted
// emulates the documented "real-world race" where the
// appearance arrives before the party_binding finishes
// docketing. The prereq policy treats this as accepted (the
// binding check is Advisory at the verifier layer).
func TestFunctional_CounselAppearance_BeforePartyBindingIsAccepted(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	v := w.Check("counsel_appearance", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if !v.OK {
		t.Errorf("counsel_appearance with only case_initiated must accept (Advisory race tolerance): %+v",
			v)
	}
}
