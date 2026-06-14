package trial

import (
	"errors"
	"testing"

	"github.com/baseproof/tooling/libs/policy"
)

// TestDictionaryCoverage_EveryPrereqEventHasACosignatureRule locks the
// invariant that surfaced the hearing_convened_concluded gap: the cosignature
// policy is a CLOSED SET (an unknown event_type ⇒ ErrRuleNotFound ⇒ the entry
// is rejected), so every event_type the prerequisite dictionary recognizes MUST
// carry a cosignature rule — i.e. defined roles — or it is unfileable. This
// makes a future "event in the dictionary, no roles" gap unconstructible: add a
// dictionary entry without a cosignature rule and this test fails.
func TestDictionaryCoverage_EveryPrereqEventHasACosignatureRule(t *testing.T) {
	pol := MustCosignaturePolicy()
	dict := PrerequisiteRules()
	if len(dict) == 0 {
		t.Fatal("prerequisite dictionary is empty — extraction bug")
	}
	for eventType := range dict {
		_, err := pol.Lookup(eventType)
		switch {
		case err == nil:
			// covered — has a rule (roles defined).
		case errors.Is(err, policy.ErrRuleNotFound):
			t.Errorf("dictionary event_type %q has a prerequisite but NO cosignature rule — "+
				"the closed-set policy rejects it (no roles defined)", eventType)
		default:
			t.Errorf("Lookup(%q): unexpected error: %v", eventType, err)
		}
	}
}

// TestHearingConvenedConcluded_HasClerkSigner pins the specific fix: the
// trial-in-progress docket record is a single court_clerk-signed event (its
// docket_management act), with no party filer — same shape as verdict /
// transcript_publication.
func TestHearingConvenedConcluded_HasClerkSigner(t *testing.T) {
	r, err := MustCosignaturePolicy().Lookup("hearing_convened_concluded")
	if err != nil {
		t.Fatalf("hearing_convened_concluded must have a rule: %v", err)
	}
	if r.RequiresFiler() {
		t.Error("hearing_convened_concluded is a court record, not a party filing — no AllowedFilerRoles")
	}
	if len(r.RequiredSignerRoles) != 1 || r.RequiredSignerRoles[0] != "court_clerk" {
		t.Errorf("RequiredSignerRoles = %v, want [court_clerk]", r.RequiredSignerRoles)
	}
}
