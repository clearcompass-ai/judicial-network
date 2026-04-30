/*
FILE PATH: deployments/tn/coa/prerequisites_test.go

DESCRIPTION:
    Tests for the TN COA prerequisite fixture. Pins:
      - Construction validates.
      - Vocabulary matches the cosignature policy (10 events).
      - Each appellate event has the right prereq shape:
          * appellate_case_initiation — Advisory notice_of_appeal
          * publication / participation — Hard appellate_root
          * disposition — Hard root + Hard merits opinion
          * remand_affirmance — Advisory notice_of_appeal
      - Personnel events require authority scopes.
      - Topology events have no prereqs.
*/
package coa

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
)

// ─── Construction & validation ─────────────────────────────────────

func TestPrerequisitePolicy_Validates(t *testing.T) {
	p, err := prerequisites.NewInMemoryPolicy(PrerequisiteRules())
	if err != nil {
		t.Fatalf("TN COA prereq fixture failed validation: %v", err)
	}
	if len(p.EventTypes()) == 0 {
		t.Fatal("TN COA prereq policy must have at least one event_type")
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

func TestMustPrerequisitePolicy_IndependentCalls(t *testing.T) {
	a := MustPrerequisitePolicy()
	b := MustPrerequisitePolicy()
	if a == b {
		t.Error("MustPrerequisitePolicy should return a fresh policy per call")
	}
}

// ─── Vocabulary pin ────────────────────────────────────────────────

func TestPrerequisitePolicy_VocabularyPin(t *testing.T) {
	p := MustPrerequisitePolicy()
	want := map[string]bool{
		"appellate_case_initiation":       true,
		"appellate_opinion_publication":   true,
		"appellate_opinion_participation": true,
		"appellate_disposition":           true,
		"remand_affirmance":               true,
		"judicial_appointment":            true,
		"clerk_appointment":               true,
		"case_transfer_inbound":           true,
		"case_transfer_outbound":          true,
		"relay_attestation":               true,
	}
	got := p.EventTypes()
	if len(got) != len(want) {
		t.Errorf("vocabulary size = %d, want %d (%v)",
			len(got), len(want), got)
	}
	for _, evt := range got {
		if !want[evt] {
			t.Errorf("unexpected event_type in vocabulary: %q", evt)
		}
	}
	for evt := range want {
		if !p.KnowsEventType(evt) {
			t.Errorf("missing event_type in vocabulary: %q", evt)
		}
	}
}

// ─── representative walks ──────────────────────────────────────────

func TestWalk_AppellateCaseInitiation_AdvisoryNoticeOfAppeal(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	// Without notice_of_appeal in the subtree, the walker must
	// still accept (Advisory only — v1.8 §7B.1).
	v := w.Check("appellate_case_initiation",
		prerequisites.CaseContext{ObservedEvents: nil})
	if !v.OK {
		t.Errorf("Advisory must NOT block: %+v", v)
	}
	if len(v.Advisory) != 1 {
		t.Errorf("expected 1 Advisory violation, got %d", len(v.Advisory))
	}

	// With notice_of_appeal, no Advisory.
	v = w.Check("appellate_case_initiation", prerequisites.CaseContext{
		ObservedEvents: []string{"notice_of_appeal"},
	})
	if !v.OK {
		t.Errorf("with notice_of_appeal must be OK: %+v", v)
	}
	if len(v.Advisory) != 0 {
		t.Errorf("expected 0 Advisory violations, got %d", len(v.Advisory))
	}
}

func TestWalk_OpinionPublication_RequiresAppellateRoot(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	// Without appellate_case_initiation: Hard rejection.
	v := w.Check("appellate_opinion_publication",
		prerequisites.CaseContext{ObservedEvents: nil})
	if v.OK {
		t.Error("publication without appellate root must reject")
	}
	if v.Rejection != prerequisites.WalkRejectMissingAncestor {
		t.Errorf("Rejection=%s", v.Rejection)
	}

	// With appellate_case_initiation: OK.
	v = w.Check("appellate_opinion_publication", prerequisites.CaseContext{
		ObservedEvents: []string{"appellate_case_initiation"},
	})
	if !v.OK {
		t.Errorf("with appellate root must be OK: %+v", v)
	}
}

func TestWalk_OpinionParticipation_RequiresAppellateRoot(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("appellate_opinion_participation",
		prerequisites.CaseContext{ObservedEvents: nil})
	if v.OK {
		t.Error("participation without appellate root must reject")
	}

	v = w.Check("appellate_opinion_participation", prerequisites.CaseContext{
		ObservedEvents: []string{"appellate_case_initiation"},
	})
	if !v.OK {
		t.Errorf("with appellate root must be OK: %+v", v)
	}
}

func TestWalk_Disposition_RequiresMeritsOpinion(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	// Without merits opinion: rejected (Hard).
	v := w.Check("appellate_disposition", prerequisites.CaseContext{
		ObservedEvents: []string{"appellate_case_initiation"},
	})
	if v.OK {
		t.Error("disposition without merits opinion must reject")
	}

	// With merits opinion: OK.
	v = w.Check("appellate_disposition", prerequisites.CaseContext{
		ObservedEvents: []string{
			"appellate_case_initiation",
			"appellate_opinion_publication",
		},
	})
	if !v.OK {
		t.Errorf("with merits opinion must be OK: %+v", v)
	}
}

func TestWalk_RemandAffirmance_AdvisoryNoticeOfAppeal(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("remand_affirmance", prerequisites.CaseContext{})
	if !v.OK {
		t.Errorf("Advisory must NOT block: %+v", v)
	}
	if len(v.Advisory) != 1 {
		t.Errorf("expected 1 Advisory violation, got %d", len(v.Advisory))
	}
}

func TestWalk_JudicialAppointment_RequiresAuthority(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("judicial_appointment", prerequisites.CaseContext{
		PrimaryAuthorityScopes: []string{"judicial_appointment_authority"},
	})
	if !v.OK {
		t.Errorf("with authority must be OK: %+v", v)
	}

	v = w.Check("judicial_appointment", prerequisites.CaseContext{
		PrimaryAuthorityScopes: []string{"some_other_authority"},
	})
	if v.OK {
		t.Error("missing authority must reject")
	}
	if v.Rejection != prerequisites.WalkRejectMissingAuthority {
		t.Errorf("Rejection=%s", v.Rejection)
	}
}

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

func TestWalk_UnknownEvent_Rejected(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	v := w.Check("wizard_motion", prerequisites.CaseContext{})
	if v.Rejection != prerequisites.WalkRejectUnknownEvent {
		t.Errorf("unknown event_type Rejection=%s", v.Rejection)
	}
}
