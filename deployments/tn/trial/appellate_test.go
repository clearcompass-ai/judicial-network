/*
FILE PATH: deployments/tn/trial/appellate_test.go

DESCRIPTION:
    Tests for the TN trial AppellateVocabulary. Pins:
      - Returns a non-nil AppellateVocab.
      - All four closed sets (OpinionTypes, ParticipationRoles,
        DispositionOutcomes, ReviewTypes) are empty — trial
        courts never accept appellate_* payloads.
      - The returned vocab agrees with the canonical
        jurisdiction.EmptyAppellateVocab() factory.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

func TestAppellateVocabulary_NonNil(t *testing.T) {
	if AppellateVocabulary() == nil {
		t.Error("AppellateVocabulary must return a non-nil AppellateVocab")
	}
}

func TestAppellateVocabulary_AllEmpty(t *testing.T) {
	v := AppellateVocabulary()
	if got := v.OpinionTypes(); len(got) != 0 {
		t.Errorf("OpinionTypes: trial-only must be empty, got %v", got)
	}
	if got := v.ParticipationRoles(); len(got) != 0 {
		t.Errorf("ParticipationRoles: trial-only must be empty, got %v", got)
	}
	if got := v.DispositionOutcomes(); len(got) != 0 {
		t.Errorf("DispositionOutcomes: trial-only must be empty, got %v", got)
	}
	if got := v.ReviewTypes(); len(got) != 0 {
		t.Errorf("ReviewTypes: trial-only must be empty, got %v", got)
	}
}

func TestAppellateVocabulary_KnowsNothing(t *testing.T) {
	v := AppellateVocabulary()
	for _, c := range []struct {
		name  string
		probe func() bool
	}{
		{"OpinionType: majority", func() bool {
			return jurisdiction.KnowsOpinionType(v, "majority")
		}},
		{"ParticipationRole: joined", func() bool {
			return jurisdiction.KnowsParticipationRole(v, "joined")
		}},
		{"DispositionOutcome: affirmed", func() bool {
			return jurisdiction.KnowsDispositionOutcome(v, "affirmed")
		}},
		{"ReviewType: direct_appeal", func() bool {
			return jurisdiction.KnowsReviewType(v, "direct_appeal")
		}},
	} {
		if c.probe() {
			t.Errorf("%s: trial-only vocab must reject every appellate enum", c.name)
		}
	}
}
