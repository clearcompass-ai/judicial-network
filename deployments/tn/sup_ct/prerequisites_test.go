/*
FILE PATH: deployments/tn/sup_ct/prerequisites_test.go

DESCRIPTION:

	Tests for the TN Supreme Court prereq fixture. Pins the
	11-event vocabulary AND the §12C revocation Hard prereq.
*/
package sup_ct

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
)

func TestPrerequisitePolicy_Validates(t *testing.T) {
	p, err := prerequisites.NewInMemoryPolicy(PrerequisiteRules())
	if err != nil {
		t.Fatalf("Sup Ct prereq fixture failed validation: %v", err)
	}
	if len(p.EventTypes()) == 0 {
		t.Fatal("must have at least one event_type")
	}
}

func TestPrerequisitePolicy_VocabularyPin(t *testing.T) {
	p := MustPrerequisitePolicy()
	want := map[string]bool{
		"appellate_case_initiation":         true,
		"appellate_opinion_publication":     true,
		"appellate_opinion_participation":   true,
		"appellate_disposition":             true,
		"remand_affirmance":                 true,
		"authority_revocation_disciplinary": true,
		"judicial_appointment":              true,
		"clerk_appointment":                 true,
		"case_transfer_inbound":             true,
		"case_transfer_outbound":            true,
		"relay_attestation":                 true,
	}
	got := p.EventTypes()
	if len(got) != len(want) {
		t.Errorf("vocabulary size = %d, want %d", len(got), len(want))
	}
	for evt := range want {
		if !p.KnowsEventType(evt) {
			t.Errorf("missing %q", evt)
		}
	}
}

// ─── §12C revocation prereq ──────────────────────────────────────

func TestWalk_Revocation_RequiresAppointmentAncestor(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	// Without prior appointment → reject.
	v := w.Check("authority_revocation_disciplinary",
		prerequisites.CaseContext{ObservedEvents: nil})
	if v.OK {
		t.Error("revocation without judicial_appointment must reject")
	}

	// With prior appointment → accept.
	v = w.Check("authority_revocation_disciplinary",
		prerequisites.CaseContext{
			ObservedEvents: []string{"judicial_appointment"},
		})
	if !v.OK {
		t.Errorf("revocation with appointment ancestor must accept: %s",
			v.Reason)
	}
}

// ─── appellate disposition prereq chain ──────────────────────────

func TestWalk_Disposition_RequiresAppellateRootAndMeritsOpinion(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("appellate_disposition", prerequisites.CaseContext{
		ObservedEvents: []string{"appellate_case_initiation"},
	})
	if v.OK {
		t.Error("must reject without merits opinion")
	}

	v = w.Check("appellate_disposition", prerequisites.CaseContext{
		ObservedEvents: []string{
			"appellate_case_initiation",
			"appellate_opinion_publication",
		},
	})
	if !v.OK {
		t.Errorf("must accept with both prereqs: %s", v.Reason)
	}
}

// ─── topology events have no prereqs ────────────────────────────

func TestWalk_TopologyEvents_NoPrereqs(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	for _, evt := range []string{
		"case_transfer_inbound",
		"case_transfer_outbound",
		"relay_attestation",
	} {
		v := w.Check(evt, prerequisites.CaseContext{})
		if !v.OK {
			t.Errorf("%s must be OK with no prereqs: %+v", evt, v)
		}
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
