/*
FILE PATH: deployments/tn/coa/appellate_test.go

DESCRIPTION:

	Tests for the TN COA AppellateVocabulary. Pins the v1.8 §7B
	closed sets:
	  - 11 opinion types (no seriatim, no in_chambers)
	  - 6 participation roles (no authored)
	  - 6 disposition outcomes (no cert_*)
	  - 3 review types (no certiorari)
	  - 4 merits-level opinion types (subset of 11)
*/
package coa

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// ─── set sizes ──────────────────────────────────────────────────────

func TestOpinionTypes_v18Count(t *testing.T) {
	const want = 11
	if got := len(OpinionTypes()); got != want {
		t.Errorf("OpinionTypes count: want %d (v1.8 §7B.2), got %d",
			want, got)
	}
}

func TestParticipationRoles_v18Count(t *testing.T) {
	const want = 6
	if got := len(ParticipationRoles()); got != want {
		t.Errorf("ParticipationRoles count: want %d (v1.8 §7B.2), got %d",
			want, got)
	}
}

func TestDispositionOutcomes_v18Count(t *testing.T) {
	const want = 6
	if got := len(DispositionOutcomes()); got != want {
		t.Errorf("DispositionOutcomes count: want %d (v1.8 §7B.3), got %d",
			want, got)
	}
}

func TestReviewTypes_v18Count(t *testing.T) {
	const want = 3
	if got := len(ReviewTypes()); got != want {
		t.Errorf("ReviewTypes count: want %d (v1.8 §7B.1), got %d",
			want, got)
	}
}

func TestMeritsOpinionTypes_v18Count(t *testing.T) {
	const want = 4 // majority, plurality, per_curiam, memorandum
	if got := len(MeritsOpinionTypes()); got != want {
		t.Errorf("MeritsOpinionTypes count: want %d (v1.8 §7B.3), got %d",
			want, got)
	}
}

// ─── presence: every v1.8 token MUST be in the set ─────────────────

func TestOpinionTypes_KnownTokens(t *testing.T) {
	v := AppellateVocabulary()
	for _, want := range []string{
		"majority", "plurality", "per_curiam", "memorandum",
		"concurrence", "concurrence_in_judgment", "concurrence_in_part",
		"concurrence_in_part_concurrence_in_judgment",
		"dissent", "dissent_in_part",
		"concurrence_in_part_dissent_in_part",
	} {
		if !jurisdiction.KnowsOpinionType(v, want) {
			t.Errorf("v1.8 OpinionType %q missing from TN COA vocab", want)
		}
	}
}

func TestParticipationRoles_KnownTokens(t *testing.T) {
	v := AppellateVocabulary()
	for _, want := range []string{
		"joined", "joined_in_part", "joined_except_as_to",
		"did_not_join", "recused", "did_not_participate",
	} {
		if !jurisdiction.KnowsParticipationRole(v, want) {
			t.Errorf("v1.8 ParticipationRole %q missing from TN COA vocab", want)
		}
	}
}

func TestDispositionOutcomes_KnownTokens(t *testing.T) {
	v := AppellateVocabulary()
	for _, want := range []string{
		"affirmed", "reversed", "vacated", "remanded",
		"affirmed_in_part_reversed_in_part", "dismissed",
	} {
		if !jurisdiction.KnowsDispositionOutcome(v, want) {
			t.Errorf("v1.8 DispositionOutcome %q missing from TN COA vocab", want)
		}
	}
}

func TestReviewTypes_KnownTokens(t *testing.T) {
	v := AppellateVocabulary()
	for _, want := range []string{
		"direct_appeal", "interlocutory_appeal", "extraordinary_appeal",
	} {
		if !jurisdiction.KnowsReviewType(v, want) {
			t.Errorf("v1.8 ReviewType %q missing from TN COA vocab", want)
		}
	}
}

// ─── absence: SCOTUS-only tokens MUST NOT be in TN COA vocab ───────

func TestOpinionTypes_NoSCOTUSTokens(t *testing.T) {
	v := AppellateVocabulary()
	for _, scotus := range []string{"seriatim", "in_chambers"} {
		if jurisdiction.KnowsOpinionType(v, scotus) {
			t.Errorf("SCOTUS-only OpinionType %q must NOT be in TN COA vocab",
				scotus)
		}
	}
}

func TestParticipationRoles_NoAuthored(t *testing.T) {
	v := AppellateVocabulary()
	if jurisdiction.KnowsParticipationRole(v, "authored") {
		t.Error("authored is not a v1.8 participation role; authorship is on publication")
	}
}

func TestDispositionOutcomes_NoCertTokens(t *testing.T) {
	v := AppellateVocabulary()
	for _, cert := range []string{
		"cert_granted", "cert_denied", "cert_dismissed",
	} {
		if jurisdiction.KnowsDispositionOutcome(v, cert) {
			t.Errorf("SCOTUS-only outcome %q must NOT be in TN COA vocab",
				cert)
		}
	}
}

func TestReviewTypes_NoCertiorari(t *testing.T) {
	v := AppellateVocabulary()
	if jurisdiction.KnowsReviewType(v, "certiorari") {
		t.Error("certiorari is SCOTUS-only; TN COA has no cert stage")
	}
}

// ─── MeritsOpinionTypes is a subset of OpinionTypes ────────────────

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

// ─── AppellateVocabulary returns non-nil ───────────────────────────

func TestAppellateVocabulary_NonNil(t *testing.T) {
	if AppellateVocabulary() == nil {
		t.Error("AppellateVocabulary must return a non-nil AppellateVocab")
	}
}
