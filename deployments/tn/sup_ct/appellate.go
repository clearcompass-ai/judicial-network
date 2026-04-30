/*
FILE PATH: deployments/tn/sup_ct/appellate.go

DESCRIPTION:
    TN Supreme Court — AppellateVocabulary. Closed-set enums for
    the appellate event payloads. v1.8 §7B's enum is the COA
    baseline; the Sup Ct extends it slightly for highest-court
    practice:

      OpinionTypes        v1.8 §7B.2 (11 values, COA baseline);
                          Sup Ct does NOT add seriatim or
                          in_chambers (those remain SCOTUS-
                          specific). per_curiam more common at
                          Sup Ct than COA but vocabulary same.
      ParticipationRoles  v1.8 §7B.2 baseline.
      DispositionOutcomes v1.8 §7B.3 baseline.
      ReviewTypes         v1.8 §7B.1 baseline.

    Sup Ct keeps the same closed-set as COA for v0.7.0; the file
    exists separately so future Sup-Ct-only additions (e.g.,
    en_banc_rehearing_grant) can land here without cross-Bundle
    coupling.
*/
package sup_ct

import "github.com/clearcompass-ai/judicial-network/jurisdiction"

// OpinionTypes returns the closed set of opinion_type values
// the TN Supreme Court accepts. v1.8 §7B.2 baseline.
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

// ParticipationRoles returns the closed set of role values.
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

// DispositionOutcomes returns the closed set of outcome values.
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

// ReviewTypes returns the closed set of review_type values.
func ReviewTypes() []string {
	return []string{
		"direct_appeal",
		"interlocutory_appeal",
		"extraordinary_appeal",
	}
}

// MeritsOpinionTypes returns the merits-opinion subset.
func MeritsOpinionTypes() []string {
	return []string{
		"majority",
		"plurality",
		"per_curiam",
		"memorandum",
	}
}

// supCtVocab is the AppellateVocab implementation.
type supCtVocab struct{}

func (supCtVocab) OpinionTypes() []string        { return OpinionTypes() }
func (supCtVocab) ParticipationRoles() []string  { return ParticipationRoles() }
func (supCtVocab) DispositionOutcomes() []string { return DispositionOutcomes() }
func (supCtVocab) ReviewTypes() []string         { return ReviewTypes() }

// AppellateVocabulary returns the TN Sup Ct AppellateVocab.
func AppellateVocabulary() jurisdiction.AppellateVocab {
	return supCtVocab{}
}
