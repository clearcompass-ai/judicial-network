/*
FILE PATH: jurisdiction/appellate_vocab_test.go

DESCRIPTION:
    Unit tests for AppellateVocab. Covers:

      - EmptyAppellateVocab returns empty closed sets.
      - Knows* predicates return correct membership for empty,
        nil, and populated vocabs.
      - The contains helper handles nil and empty inputs.
      - A test stub (stubVocab) demonstrates the interface
        contract for future per-jurisdiction implementations.
*/
package jurisdiction

import "testing"

// ─── EmptyAppellateVocab ─────────────────────────────────────────────

func TestEmptyAppellateVocab_AllEmpty(t *testing.T) {
	v := EmptyAppellateVocab()
	if got := v.OpinionTypes(); len(got) != 0 {
		t.Errorf("OpinionTypes: want empty, got %v", got)
	}
	if got := v.ParticipationRoles(); len(got) != 0 {
		t.Errorf("ParticipationRoles: want empty, got %v", got)
	}
	if got := v.DispositionOutcomes(); len(got) != 0 {
		t.Errorf("DispositionOutcomes: want empty, got %v", got)
	}
	if got := v.ReviewTypes(); len(got) != 0 {
		t.Errorf("ReviewTypes: want empty, got %v", got)
	}
}

func TestEmptyAppellateVocab_KnowsNothing(t *testing.T) {
	v := EmptyAppellateVocab()
	if KnowsOpinionType(v, "majority") {
		t.Error("empty vocab should not know any opinion type")
	}
	if KnowsParticipationRole(v, "joined") {
		t.Error("empty vocab should not know any participation role")
	}
	if KnowsDispositionOutcome(v, "affirmed") {
		t.Error("empty vocab should not know any outcome")
	}
	if KnowsReviewType(v, "direct_appeal") {
		t.Error("empty vocab should not know any review type")
	}
}

// ─── nil vocab safety ────────────────────────────────────────────────

func TestKnows_NilVocab(t *testing.T) {
	if KnowsOpinionType(nil, "majority") {
		t.Error("nil vocab should not know any opinion type")
	}
	if KnowsParticipationRole(nil, "joined") {
		t.Error("nil vocab should not know any participation role")
	}
	if KnowsDispositionOutcome(nil, "affirmed") {
		t.Error("nil vocab should not know any outcome")
	}
	if KnowsReviewType(nil, "direct_appeal") {
		t.Error("nil vocab should not know any review type")
	}
}

// ─── populated vocab — TN COA-shaped ─────────────────────────────────

func TestKnowsOpinionType_TNCOAShaped(t *testing.T) {
	v := stubVocab{
		opinionTypes: []string{"majority", "plurality", "per_curiam",
			"memorandum", "concurrence", "dissent"},
	}
	for _, want := range []string{"majority", "dissent", "per_curiam"} {
		if !KnowsOpinionType(v, want) {
			t.Errorf("%q should be known in TN COA vocab", want)
		}
	}
	for _, notWant := range []string{"seriatim", "in_chambers", ""} {
		if KnowsOpinionType(v, notWant) {
			t.Errorf("%q should NOT be in TN COA vocab (SCOTUS-only or empty)", notWant)
		}
	}
}

func TestKnowsParticipationRole_TNCOAShaped(t *testing.T) {
	v := stubVocab{
		participationRoles: []string{"joined", "joined_in_part",
			"joined_except_as_to", "did_not_join", "recused",
			"did_not_participate"},
	}
	for _, want := range []string{"joined", "recused"} {
		if !KnowsParticipationRole(v, want) {
			t.Errorf("%q should be known in TN COA participation roles", want)
		}
	}
	if KnowsParticipationRole(v, "authored") {
		t.Error("authored is not a participation role; authorship is on publication")
	}
}

func TestKnowsDispositionOutcome_TNCOAShaped(t *testing.T) {
	v := stubVocab{
		dispositionOutcomes: []string{"affirmed", "reversed", "vacated",
			"remanded", "affirmed_in_part_reversed_in_part", "dismissed"},
	}
	for _, want := range []string{"affirmed", "vacated", "remanded"} {
		if !KnowsDispositionOutcome(v, want) {
			t.Errorf("%q should be known in TN COA outcomes", want)
		}
	}
	for _, notWant := range []string{"cert_granted", "cert_denied", "cert_dismissed"} {
		if KnowsDispositionOutcome(v, notWant) {
			t.Errorf("%q is SCOTUS-only, not in TN COA outcomes", notWant)
		}
	}
}

func TestKnowsReviewType_TNCOAShaped(t *testing.T) {
	v := stubVocab{
		reviewTypes: []string{"direct_appeal", "interlocutory_appeal",
			"extraordinary_appeal"},
	}
	for _, want := range []string{"direct_appeal", "interlocutory_appeal"} {
		if !KnowsReviewType(v, want) {
			t.Errorf("%q should be known in TN COA review types", want)
		}
	}
	if KnowsReviewType(v, "certiorari") {
		t.Error("certiorari is SCOTUS-only, not in TN COA review types")
	}
}

// ─── contains helper ─────────────────────────────────────────────────

func TestContains_NilSet(t *testing.T) {
	if contains(nil, "anything") {
		t.Error("nil set should never contain anything")
	}
}

func TestContains_EmptySet(t *testing.T) {
	if contains([]string{}, "anything") {
		t.Error("empty set should never contain anything")
	}
}

func TestContains_Found(t *testing.T) {
	if !contains([]string{"a", "b", "c"}, "b") {
		t.Error("b should be found in [a, b, c]")
	}
}

func TestContains_NotFound(t *testing.T) {
	if contains([]string{"a", "b", "c"}, "d") {
		t.Error("d should not be found in [a, b, c]")
	}
}

func TestContains_EmptyWant(t *testing.T) {
	if contains([]string{"a", "b"}, "") {
		t.Error("empty string should not match any non-empty entry")
	}
}

// ─── test stub for future per-jurisdiction implementations ──────────

// stubVocab is a hand-built AppellateVocab used by tests in this
// package and by downstream package tests that need to inject a
// known-shape vocabulary without bringing in a real Bundle.
type stubVocab struct {
	opinionTypes        []string
	participationRoles  []string
	dispositionOutcomes []string
	reviewTypes         []string
}

func (s stubVocab) OpinionTypes() []string        { return s.opinionTypes }
func (s stubVocab) ParticipationRoles() []string  { return s.participationRoles }
func (s stubVocab) DispositionOutcomes() []string { return s.dispositionOutcomes }
func (s stubVocab) ReviewTypes() []string         { return s.reviewTypes }
