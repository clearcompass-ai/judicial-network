/*
FILE PATH: jurisdiction/appellate_vocab.go

DESCRIPTION:
    AppellateVocab — per-jurisdiction closed-set vocabulary for
    appellate event payload enums. Each appellate exchange (TN
    Court of Appeals, future TN Supreme Court, future SCOTUS,
    federal circuits) defines its own enum values for opinion
    types, participation roles, disposition outcomes, and review
    types. Trial-only exchanges (TN counties, federal districts)
    return EmptyAppellateVocab().

    Why per-Bundle, not global: TN COA accepts {majority,
    plurality, per_curiam, memorandum, concurrence, ..., dissent,
    ...}; SCOTUS additionally accepts {seriatim, in_chambers,
    cert_*}; the federal circuit accepts panel-vs-en-banc
    distinctions. None of these enum sets belong in shared
    verifier code — they are jurisdictional facts owned by the
    Bundle.

    The Bundle.AppellateVocabulary() method returns the current
    jurisdiction's vocabulary. The verifier consults it when
    validating appellate_* event payloads.

OVERVIEW:
    AppellateVocab           — interface (4 lookup methods).
    EmptyAppellateVocab      — factory for trial-only exchanges.
    Knows{Opinion,Participation,Disposition,Review}Type — predicates.

KEY DEPENDENCIES: none (pure data structure).
*/
package jurisdiction

// AppellateVocab is the per-jurisdiction closed-set vocabulary
// for appellate event payload enums. Implementations MUST be
// safe for concurrent use; the registry hands the same instance
// to every caller.
type AppellateVocab interface {
	// OpinionTypes returns the closed set of opinion_type values
	// this jurisdiction accepts on appellate_opinion_publication
	// events.
	OpinionTypes() []string

	// ParticipationRoles returns the closed set of role values
	// this jurisdiction accepts on appellate_opinion_participation
	// events.
	ParticipationRoles() []string

	// DispositionOutcomes returns the closed set of outcome
	// values this jurisdiction accepts on appellate_disposition
	// events.
	DispositionOutcomes() []string

	// ReviewTypes returns the closed set of review_type values
	// this jurisdiction accepts on appellate_case_initiation
	// events.
	ReviewTypes() []string
}

// emptyVocab is the trial-only zero value. Returns nil from
// every method — every payload-enum membership test against it
// fails. Trial exchanges (TN counties, federal districts) wire
// EmptyAppellateVocab() into their Bundle so the type system
// still sees a non-nil AppellateVocab while the closed sets
// remain definitionally empty.
type emptyVocab struct{}

func (emptyVocab) OpinionTypes() []string        { return nil }
func (emptyVocab) ParticipationRoles() []string  { return nil }
func (emptyVocab) DispositionOutcomes() []string { return nil }
func (emptyVocab) ReviewTypes() []string         { return nil }

// EmptyAppellateVocab returns an AppellateVocab whose every
// closed set is empty. Trial-only exchanges return this from
// their Bundle.AppellateVocabulary().
func EmptyAppellateVocab() AppellateVocab {
	return emptyVocab{}
}

// KnowsOpinionType reports whether v includes opinionType in
// its closed set. Returns false for nil v or empty set.
func KnowsOpinionType(v AppellateVocab, opinionType string) bool {
	if v == nil {
		return false
	}
	return contains(v.OpinionTypes(), opinionType)
}

// KnowsParticipationRole reports whether v includes role in its
// closed set. Returns false for nil v or empty set.
func KnowsParticipationRole(v AppellateVocab, role string) bool {
	if v == nil {
		return false
	}
	return contains(v.ParticipationRoles(), role)
}

// KnowsDispositionOutcome reports whether v includes outcome in
// its closed set. Returns false for nil v or empty set.
func KnowsDispositionOutcome(v AppellateVocab, outcome string) bool {
	if v == nil {
		return false
	}
	return contains(v.DispositionOutcomes(), outcome)
}

// KnowsReviewType reports whether v includes reviewType in its
// closed set. Returns false for nil v or empty set.
func KnowsReviewType(v AppellateVocab, reviewType string) bool {
	if v == nil {
		return false
	}
	return contains(v.ReviewTypes(), reviewType)
}

// contains is a linear-scan membership test. Closed sets are
// small (≤16 entries) so a hash set would be overkill.
func contains(set []string, want string) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}
