/*
FILE PATH: deployments/tn/sup_ct/appellate_test.go

DESCRIPTION:

	Tests for the TN Sup Ct AppellateVocabulary. Same closed
	sets as TN COA per v0.7.0 baseline; the file exists
	separately so future Sup-Ct-only additions can land here.
*/
package sup_ct

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

func TestOpinionTypes_Count(t *testing.T) {
	if got := len(OpinionTypes()); got != 11 {
		t.Errorf("OpinionTypes count: want 11, got %d", got)
	}
}

func TestParticipationRoles_Count(t *testing.T) {
	if got := len(ParticipationRoles()); got != 6 {
		t.Errorf("ParticipationRoles count: want 6, got %d", got)
	}
}

func TestDispositionOutcomes_Count(t *testing.T) {
	if got := len(DispositionOutcomes()); got != 6 {
		t.Errorf("DispositionOutcomes count: want 6, got %d", got)
	}
}

func TestReviewTypes_Count(t *testing.T) {
	if got := len(ReviewTypes()); got != 3 {
		t.Errorf("ReviewTypes count: want 3, got %d", got)
	}
}

func TestMeritsOpinionTypes_SubsetOfOpinionTypes(t *testing.T) {
	full := map[string]bool{}
	for _, s := range OpinionTypes() {
		full[s] = true
	}
	for _, m := range MeritsOpinionTypes() {
		if !full[m] {
			t.Errorf("MeritsOpinionType %q is not in OpinionTypes()", m)
		}
	}
}

func TestAppellateVocabulary_NonNil(t *testing.T) {
	if AppellateVocabulary() == nil {
		t.Error("AppellateVocabulary must return non-nil")
	}
}

func TestAppellateVocabulary_KnowsCanonicalTokens(t *testing.T) {
	v := AppellateVocabulary()
	if !jurisdiction.KnowsOpinionType(v, "majority") {
		t.Error("majority must be known")
	}
	if !jurisdiction.KnowsParticipationRole(v, "joined") {
		t.Error("joined must be known")
	}
	if !jurisdiction.KnowsDispositionOutcome(v, "affirmed") {
		t.Error("affirmed must be known")
	}
	if !jurisdiction.KnowsReviewType(v, "direct_appeal") {
		t.Error("direct_appeal must be known")
	}
}

// SCOTUS-only tokens stay out of the Sup Ct vocab too — TN
// Supreme Court is intermediate-state, not a federal cert court.
func TestAppellateVocabulary_NoSCOTUSOnlyTokens(t *testing.T) {
	v := AppellateVocabulary()
	if jurisdiction.KnowsOpinionType(v, "seriatim") {
		t.Error("seriatim is SCOTUS-only")
	}
	if jurisdiction.KnowsOpinionType(v, "in_chambers") {
		t.Error("in_chambers is SCOTUS-only")
	}
	if jurisdiction.KnowsReviewType(v, "certiorari") {
		t.Error("TN Sup Ct uses direct_appeal, not certiorari")
	}
}
