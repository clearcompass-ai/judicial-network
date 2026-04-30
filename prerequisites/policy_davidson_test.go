/*
FILE PATH: prerequisites/policy_davidson_test.go

DESCRIPTION:
    Tests the Davidson reference fixture: vocabulary completeness,
    structural validation of every rule, and a representative
    walk for each major event category. Pinning the fixture keeps
    silent vocabulary drift from breaking the closed-set guarantee.
*/
package prerequisites

import (
	"testing"
)

// ─── Construction & validation ─────────────────────────────────────

func TestNewDavidsonPolicy_Validates(t *testing.T) {
	p, err := NewDavidsonPolicy()
	if err != nil {
		t.Fatalf("Davidson fixture failed validation: %v", err)
	}
	if len(p.EventTypes()) == 0 {
		t.Fatal("Davidson policy must have at least one event_type")
	}
}

func TestMustDavidsonPolicy_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustDavidsonPolicy panicked: %v", r)
		}
	}()
	_ = MustDavidsonPolicy()
}

// ─── Vocabulary pin ────────────────────────────────────────────────

// TestDavidsonPolicy_VocabularyPin pins the EXACT closed-set
// vocabulary. New event_types should require an explicit policy
// + test update — silent additions are a v1.6 invariant violation.
func TestDavidsonPolicy_VocabularyPin(t *testing.T) {
	p := MustDavidsonPolicy()
	want := map[string]bool{
		"motion_continuance":            true,
		"motion_summary_judgment":       true,
		"responsive_pleading":           true,
		"motion_state_dismissal":        true,
		"fiduciary_accounting":          true,
		"asset_disposition_order":       true,
		"appointment_guardian_ad_litem": true,
		"verdict":                       true,
		"final_judgment":                true,
		"transcript_publication":        true,
		"judicial_appointment":          true,
		"clerk_appointment":             true,
		"court_reporter_appointment":    true,
		"case_transfer_outbound":        true,
		"case_transfer_inbound":         true,
		"relay_attestation":             true,
		"case_initiated":                true,
		"hearing":                       true,
	}
	got := p.EventTypes()
	if len(got) != len(want) {
		t.Errorf("vocabulary size = %d, want %d (%v)", len(got), len(want), got)
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

func TestDavidsonWalk_MotionContinuance_RequiresCaseInit(t *testing.T) {
	w := &Walker{Policy: MustDavidsonPolicy()}

	v := w.Check("motion_continuance", CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if !v.OK {
		t.Errorf("with case_initiated must be OK: %+v", v)
	}

	v = w.Check("motion_continuance", CaseContext{ObservedEvents: nil})
	if v.OK {
		t.Error("without case_initiated must be rejected")
	}
	if v.Rejection != WalkRejectMissingAncestor {
		t.Errorf("Rejection=%s", v.Rejection)
	}
}

func TestDavidsonWalk_Verdict_RequiresMeritsPosture(t *testing.T) {
	w := &Walker{Policy: MustDavidsonPolicy()}

	// case_initiated alone is NOT enough: the merits-posture rule
	// also fires.
	v := w.Check("verdict", CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if v.OK {
		t.Error("verdict without merits posture must reject")
	}

	v = w.Check("verdict", CaseContext{
		ObservedEvents: []string{"case_initiated", "responsive_pleading"},
	})
	if !v.OK {
		t.Errorf("verdict with merits posture must be OK: %+v", v)
	}
}

func TestDavidsonWalk_JudicialAppointment_RequiresAuthority(t *testing.T) {
	w := &Walker{Policy: MustDavidsonPolicy()}

	v := w.Check("judicial_appointment", CaseContext{
		PrimaryAuthorityScopes: []string{"judicial_appointment_authority"},
	})
	if !v.OK {
		t.Errorf("with authority must be OK: %+v", v)
	}

	v = w.Check("judicial_appointment", CaseContext{
		PrimaryAuthorityScopes: []string{"some_other_authority"},
	})
	if v.OK {
		t.Error("missing authority must reject")
	}
	if v.Rejection != WalkRejectMissingAuthority {
		t.Errorf("Rejection=%s", v.Rejection)
	}
}

func TestDavidsonWalk_CrossExchange_NoPrereqs(t *testing.T) {
	w := &Walker{Policy: MustDavidsonPolicy()}
	for _, evt := range []string{
		"case_transfer_outbound",
		"case_transfer_inbound",
		"relay_attestation",
	} {
		v := w.Check(evt, CaseContext{})
		if !v.OK {
			t.Errorf("%s must be OK with no prereqs: %+v", evt, v)
		}
	}
}

func TestDavidsonWalk_CaseInitiated_NoPrereqs(t *testing.T) {
	w := &Walker{Policy: MustDavidsonPolicy()}
	v := w.Check("case_initiated", CaseContext{})
	if !v.OK {
		t.Errorf("case_initiated must be OK at the bootstrap: %+v", v)
	}
}

func TestDavidsonWalk_TranscriptPublication_AdvisoryHearing(t *testing.T) {
	w := &Walker{Policy: MustDavidsonPolicy()}

	// case_initiated present + hearing absent: Hard rule satisfied,
	// Advisory rule violated. Walker should report OK with one
	// Advisory violation surfaced.
	v := w.Check("transcript_publication", CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if !v.OK {
		t.Errorf("Advisory must NOT block: %+v", v)
	}
	if len(v.Advisory) != 1 {
		t.Errorf("expected 1 Advisory violation, got %d", len(v.Advisory))
	}

	// Both present: OK with no violations.
	v = w.Check("transcript_publication", CaseContext{
		ObservedEvents: []string{"case_initiated", "hearing"},
	})
	if !v.OK {
		t.Errorf("with hearing must be OK: %+v", v)
	}
	if len(v.Advisory) != 0 {
		t.Errorf("expected 0 Advisory violations, got %d", len(v.Advisory))
	}
}

func TestDavidsonWalk_UnknownEvent_Rejected(t *testing.T) {
	w := &Walker{Policy: MustDavidsonPolicy()}
	v := w.Check("wizard_motion", CaseContext{})
	if v.Rejection != WalkRejectUnknownEvent {
		t.Errorf("unknown event_type Rejection=%s", v.Rejection)
	}
}
