/*
FILE PATH: deployments/TEMPLATE/rules/prerequisites_test.go

DESCRIPTION:

	Tests for the TEMPLATE prerequisite skeleton. Pins:
	  - the skeleton validates,
	  - exactly 1 event (case_initiated) exists with no prereqs,
	  - a Walker check on case_initiated returns OK.
*/
package rules

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
)

func TestPrerequisitePolicy_Validates(t *testing.T) {
	p, err := prerequisites.NewInMemoryPolicy(PrerequisiteRules())
	if err != nil {
		t.Fatalf("TEMPLATE prereq fixture failed validation: %v", err)
	}
	if len(p.EventTypes()) == 0 {
		t.Fatal("TEMPLATE prereq policy must have at least one event_type")
	}
}

func TestMustPrerequisitePolicy_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustPrerequisitePolicy panicked: %v", r)
		}
	}()
	_ = MustPrerequisitePolicy()
}

func TestPrerequisitePolicy_VocabularyPin(t *testing.T) {
	p := MustPrerequisitePolicy()
	got := p.EventTypes()
	if len(got) != 1 || got[0] != "case_initiated" {
		t.Errorf("TEMPLATE skeleton vocabulary drift: want [case_initiated], got %v",
			got)
	}
}

func TestWalk_CaseInitiated_NoPrereqs(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	v := w.Check("case_initiated", prerequisites.CaseContext{})
	if !v.OK {
		t.Errorf("case_initiated must be OK at the bootstrap: %+v", v)
	}
}

func TestWalk_UnknownEvent_Rejected(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	v := w.Check("wizard_motion", prerequisites.CaseContext{})
	if v.Rejection != prerequisites.WalkRejectUnknownEvent {
		t.Errorf("unknown event_type Rejection=%s", v.Rejection)
	}
}
