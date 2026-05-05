/*
FILE PATH: deployments/tn/coa/appellate.go

DESCRIPTION:

	Tennessee Court of Appeals — AppellateVocabulary. Closed-set
	enums for the v1.8 §7B appellate event payloads. The verifier
	consults these sets when validating appellate_* event payload
	enums; values outside the closed set are rejected.

	v1.8 §7B explicitly trimmed the enums for TN COA practice:
	  - opinion_type DROPS seriatim (SCOTUS-only) and
	    in_chambers (SCOTUS-only); KEEPS the eleven canonical
	    TN COA opinion shapes.
	  - review_type has THREE values: direct_appeal,
	    interlocutory_appeal, extraordinary_appeal. NO certiorari
	    (TN COA has no cert stage).
	  - disposition outcome has SIX values; NO cert_granted /
	    cert_denied / cert_dismissed.
	  - participation roles list six judge positions (joined,
	    joined_in_part, joined_except_as_to, did_not_join,
	    recused, did_not_participate). NO authored — authorship
	    is recorded via author_did on publication.

	SCOTUS / federal Bundles will return supersets that include
	the SCOTUS-specific values; this file is the TN COA closed
	set verbatim from v1.8.

OVERVIEW:

	AppellateVocabulary  — returns the populated COA AppellateVocab.
	coaVocab             — unexported impl carrying the four sets.

KEY DEPENDENCIES:
  - jurisdiction.AppellateVocab.
*/
package coa

import "github.com/clearcompass-ai/judicial-network/jurisdiction"

// OpinionTypes returns the closed set of opinion_type values
// the TN Court of Appeals accepts on appellate_opinion_publication
// payloads. v1.8 §7B.2.
func OpinionTypes() []string {
	return []string{
		"majority",
		"plurality",
		"per_curiam",
		"memorandum",
		"concurrence",
		"concurrence_in_judgment",
		"concurrence_in_part",
		"concurrence_in_part_concurrence_in_judgment",
		"dissent",
		"dissent_in_part",
		"concurrence_in_part_dissent_in_part",
	}
}

// ParticipationRoles returns the closed set of role values the
// TN COA accepts on appellate_opinion_participation payloads.
// v1.8 §7B.2.
//
// Note: "authored" is NOT a participation role. Authorship is
// captured by author_did on the publication event.
func ParticipationRoles() []string {
	return []string{
		"joined",
		"joined_in_part",
		"joined_except_as_to",
		"did_not_join",
		"recused",
		"did_not_participate",
	}
}

// DispositionOutcomes returns the closed set of outcome values
// the TN COA accepts on appellate_disposition payloads.
// v1.8 §7B.3.
func DispositionOutcomes() []string {
	return []string{
		"affirmed",
		"reversed",
		"vacated",
		"remanded",
		"affirmed_in_part_reversed_in_part",
		"dismissed",
	}
}

// ReviewTypes returns the closed set of review_type values the
// TN COA accepts on appellate_case_initiation payloads.
// v1.8 §7B.1.
func ReviewTypes() []string {
	return []string{
		"direct_appeal",
		"interlocutory_appeal",
		"extraordinary_appeal",
	}
}

// MeritsOpinionTypes returns the subset of OpinionTypes that
// count as merits-level opinions (per v1.8 §7B.3, the prereq
// for appellate_disposition).
func MeritsOpinionTypes() []string {
	return []string{
		"majority",
		"plurality",
		"per_curiam",
		"memorandum",
	}
}

// coaVocab is the AppellateVocab implementation carrying the
// four closed sets defined above.
type coaVocab struct{}

func (coaVocab) OpinionTypes() []string        { return OpinionTypes() }
func (coaVocab) ParticipationRoles() []string  { return ParticipationRoles() }
func (coaVocab) DispositionOutcomes() []string { return DispositionOutcomes() }
func (coaVocab) ReviewTypes() []string         { return ReviewTypes() }

// AppellateVocabulary returns the populated TN COA AppellateVocab.
// The COA Bundle returns this from Bundle.AppellateVocabulary().
func AppellateVocabulary() jurisdiction.AppellateVocab {
	return coaVocab{}
}
