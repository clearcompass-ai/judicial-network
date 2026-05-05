/*
FILE PATH: deployments/TEMPLATE/rules/appellate_test.go

DESCRIPTION:

	Tests for the TEMPLATE AppellateVocabulary. Pins the
	trial-only contract: non-nil return + every closed set is
	empty.
*/
package rules

import "testing"

func TestAppellateVocabulary_NonNil(t *testing.T) {
	if AppellateVocabulary() == nil {
		t.Error("AppellateVocabulary must return a non-nil AppellateVocab")
	}
}

func TestAppellateVocabulary_AllEmpty(t *testing.T) {
	v := AppellateVocabulary()
	if len(v.OpinionTypes()) != 0 {
		t.Errorf("OpinionTypes: skeleton must be empty, got %v", v.OpinionTypes())
	}
	if len(v.ParticipationRoles()) != 0 {
		t.Errorf("ParticipationRoles: skeleton must be empty, got %v",
			v.ParticipationRoles())
	}
	if len(v.DispositionOutcomes()) != 0 {
		t.Errorf("DispositionOutcomes: skeleton must be empty, got %v",
			v.DispositionOutcomes())
	}
	if len(v.ReviewTypes()) != 0 {
		t.Errorf("ReviewTypes: skeleton must be empty, got %v", v.ReviewTypes())
	}
}
