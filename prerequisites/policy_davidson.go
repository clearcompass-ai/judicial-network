/*
FILE PATH: prerequisites/policy_davidson.go

DESCRIPTION:
    Davidson County reference fixture for prerequisites.Policy. The
    16 event_types match cosignature_mix_davidson.go's vocabulary;
    each carries the rules that the v1.6 Event Dictionary asserts
    must hold before the event lands.

    Categories:
      - case-lifecycle filings (motions, pleadings, accountings):
        require a case_initiated ancestor in the subtree.
      - judicial outcomes (verdict, final_judgment): require a
        responsive_pleading or motion_state_dismissal in the
        subtree (i.e. some merits posture before judgment).
      - personnel events (judicial_appointment, clerk_appointment,
        court_reporter_appointment): require the primary signer to
        hold the matching authority scope.
      - cross-exchange events (case_transfer_*, relay_attestation):
        no prereqs — transfers are bootstrap-friendly.
      - transcript_publication: ADVISORY ancestor (the dictionary
        recommends but does not require a hearing event).

    The fixture is deliberately small and explicit. New event_types
    require an explicit policy update — the closed-set vocabulary
    is the v1.6 invariant.

OVERVIEW:
    DavidsonRules        — map[event_type][]Prereq.
    NewDavidsonPolicy    — validated policy.
    MustDavidsonPolicy   — panics on construction failure
                           (test/CLI only).

KEY DEPENDENCIES:
    None — pure data.
*/
package prerequisites

// ─── Reference rules ────────────────────────────────────────────────

// DavidsonRules returns the closed-set Davidson prerequisite
// vocabulary. Edit-with-care: changing this set changes the
// network's accept/reject contract.
func DavidsonRules() map[string][]Prereq {
	caseInitAncestor := Prereq{
		Mode:             PrereqModeHard,
		RequiredAncestor: []string{"case_initiated"},
		Reason:           "every case-lifecycle event requires a case_initiated ancestor",
	}
	meritsPostureAncestor := Prereq{
		Mode: PrereqModeHard,
		RequiredAncestor: []string{
			"responsive_pleading",
			"motion_state_dismissal",
			"motion_summary_judgment",
		},
		Reason: "judgment requires a merits-posture event in the subtree",
	}
	hearingAdvisory := Prereq{
		Mode:             PrereqModeAdvisory,
		RequiredAncestor: []string{"hearing"},
		Reason:           "transcript_publication advisory: hearing should precede transcript",
	}

	return map[string][]Prereq{
		// ── attorney-driven filings ──────────────────────────────
		"motion_continuance":      {caseInitAncestor},
		"motion_summary_judgment": {caseInitAncestor},
		"responsive_pleading":     {caseInitAncestor},

		// ── prosecutor-driven ────────────────────────────────────
		"motion_state_dismissal": {caseInitAncestor},

		// ── fiduciary filings ────────────────────────────────────
		"fiduciary_accounting":    {caseInitAncestor},
		"asset_disposition_order": {caseInitAncestor},

		// ── guardian ad litem ────────────────────────────────────
		"appointment_guardian_ad_litem": {caseInitAncestor},

		// ── judicial outcomes (Hard merits-posture rule) ────────
		"verdict":        {caseInitAncestor, meritsPostureAncestor},
		"final_judgment": {caseInitAncestor, meritsPostureAncestor},

		// ── transcript_publication: Advisory hearing ancestor ───
		"transcript_publication": {caseInitAncestor, hearingAdvisory},

		// ── personnel events: authority-scope rules ─────────────
		"judicial_appointment": {{
			Mode:              PrereqModeHard,
			RequiredAuthority: "judicial_appointment_authority",
			Reason:            "judicial_appointment requires judicial_appointment_authority",
		}},
		"clerk_appointment": {{
			Mode:              PrereqModeHard,
			RequiredAuthority: "clerk_appointment_authority",
			Reason:            "clerk_appointment requires clerk_appointment_authority",
		}},
		"court_reporter_appointment": {{
			Mode:              PrereqModeHard,
			RequiredAuthority: "court_reporter_appointment_authority",
			Reason:            "court_reporter_appointment requires court_reporter_appointment_authority",
		}},

		// ── cross-exchange events: no prereqs ───────────────────
		"case_transfer_outbound": {},
		"case_transfer_inbound":  {},
		"relay_attestation":      {},

		// ── case bootstrap: anchor of the subtree, no prereq ────
		"case_initiated": {},

		// ── hearing: a posture event with no formal prereq ──────
		"hearing": {caseInitAncestor},
	}
}

// NewDavidsonPolicy returns a validated InMemoryPolicy populated
// with DavidsonRules. Returns an error if the rules do not
// validate (signaling a bug in this file).
func NewDavidsonPolicy() (*InMemoryPolicy, error) {
	return NewInMemoryPolicy(DavidsonRules())
}

// MustDavidsonPolicy is the convenience helper for tests and CLI
// fixtures. Panics on validation failure.
func MustDavidsonPolicy() *InMemoryPolicy {
	p, err := NewDavidsonPolicy()
	if err != nil {
		panic("prerequisites: Davidson fixture failed to validate: " + err.Error())
	}
	return p
}
