/*
FILE PATH: deployments/tn/trial/prerequisites_test.go

DESCRIPTION:
    Tests the TN trial prereq fixture. Lifted from
    internal/testfixtures/davidsonlegacy/prerequisites_test.go and
    re-scoped to the shared TN trial framework. Pins:
      - vocabulary completeness (closed-set size + names),
      - structural validation,
      - representative walks for each major event category.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
)

// ─── Construction & validation ─────────────────────────────────────

func TestPrerequisitePolicy_Validates(t *testing.T) {
	p, err := prerequisites.NewInMemoryPolicy(PrerequisiteRules())
	if err != nil {
		t.Fatalf("TN trial prereq fixture failed validation: %v", err)
	}
	if len(p.EventTypes()) == 0 {
		t.Fatal("TN trial prereq policy must have at least one event_type")
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

// TestPrerequisitePolicy_VocabularyPin pins the EXACT closed-set
// vocabulary. New event_types should require an explicit policy
// + test update — silent additions are a v1.8 invariant violation.
// TestPrerequisitePolicy_VocabularyPin pins the BASE vocabulary
// (the events declared directly in PrerequisiteRules() — 19
// entries: counsel_appearance + the §1–§13 lifecycle subset).
// §3A–§3I motion event_types are merged in via motion_*; pinned
// separately below.
func TestPrerequisitePolicy_VocabularyPin(t *testing.T) {
	p := MustPrerequisitePolicy()
	baseWant := map[string]bool{
		"counsel_appearance":            true,
		"responsive_pleading":           true,
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
	// Every base event must be present.
	for evt := range baseWant {
		if !p.KnowsEventType(evt) {
			t.Errorf("missing base event_type in vocabulary: %q", evt)
		}
	}
	// Every motion-helper event must also be present.
	for _, m := range allMotions() {
		if !p.KnowsEventType(m.EventType) {
			t.Errorf("missing motion event_type in vocabulary: %q",
				m.EventType)
		}
	}
	// Total size = base + motions, no extras.
	wantSize := len(baseWant) + len(allMotions())
	// motion_continuance / motion_summary_judgment / responsive_pleading
	// / motion_state_dismissal currently appear in BOTH lists (legacy
	// base + §3 helper). De-dup before comparing.
	for _, m := range allMotions() {
		if baseWant[m.EventType] {
			wantSize--
		}
	}
	if got := len(p.EventTypes()); got != wantSize {
		t.Errorf("vocabulary size = %d, want %d", got, wantSize)
	}
}

// ─── representative walks ──────────────────────────────────────────

// motion_continuance walk is pinned in motions_3g_test.go after
// §3G lands; the helper-supplied event_type isn't in the
// vocabulary until §3G's commit.

func TestWalk_Verdict_RequiresMeritsPosture(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("verdict", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if v.OK {
		t.Error("verdict without merits posture must reject")
	}

	v = w.Check("verdict", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated", "responsive_pleading"},
	})
	if !v.OK {
		t.Errorf("verdict with merits posture must be OK: %+v", v)
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

func TestWalk_CrossExchange_NoPrereqs(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	for _, evt := range []string{
		"case_transfer_outbound",
		"case_transfer_inbound",
		"relay_attestation",
	} {
		v := w.Check(evt, prerequisites.CaseContext{})
		if !v.OK {
			t.Errorf("%s must be OK with no prereqs: %+v", evt, v)
		}
	}
}

func TestWalk_CaseInitiated_NoPrereqs(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	v := w.Check("case_initiated", prerequisites.CaseContext{})
	if !v.OK {
		t.Errorf("case_initiated must be OK at the bootstrap: %+v", v)
	}
}

func TestWalk_TranscriptPublication_AdvisoryHearing(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("transcript_publication", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if !v.OK {
		t.Errorf("Advisory must NOT block: %+v", v)
	}
	if len(v.Advisory) != 1 {
		t.Errorf("expected 1 Advisory violation, got %d", len(v.Advisory))
	}

	v = w.Check("transcript_publication", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated", "hearing"},
	})
	if !v.OK {
		t.Errorf("with hearing must be OK: %+v", v)
	}
	if len(v.Advisory) != 0 {
		t.Errorf("expected 0 Advisory violations, got %d", len(v.Advisory))
	}
}

func TestWalk_UnknownEvent_Rejected(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	v := w.Check("wizard_motion", prerequisites.CaseContext{})
	if v.Rejection != prerequisites.WalkRejectUnknownEvent {
		t.Errorf("unknown event_type Rejection=%s", v.Rejection)
	}
}
