/*
FILE PATH: deployments/tn/coa/cosignature_mix.go

DESCRIPTION:
    Tennessee Court of Appeals — cosignature-mix policy. The
    COA exchange handles a different vocabulary from trial
    courts. Per v1.8 §7B, the appellate event family is:

      appellate_case_initiation        clerk-signed; mints
                                       appellate case root
      appellate_opinion_publication    judge-signed; mints
                                       opinion_id
      appellate_opinion_participation  judge-signed; per-judge
                                       role on an opinion
      appellate_disposition            ≥2 judge cosignatures;
                                       three-judge panel outcome
      remand_affirmance                clerk-signed; flows back
                                       to trial root via cross-
                                       network reference

    Plus standard personnel events for COA Signers
    (judicial_appointment, clerk_appointment, succession, etc.).

    No filer-driven motions arrive at the COA — appellate motions
    (motion_interlocutory_appeal, etc.) originate at trial and
    travel via cross-network reference. The COA's filer-events
    list is therefore empty; AllowedFilerRoles never appears.

OVERVIEW:
    CosignatureRules         — slice of CosignatureRule.
    MustCosignaturePolicy    — convenience constructor (panics).

KEY DEPENDENCIES:
    - policy.CosignatureRule / policy.NewInMemoryPolicy.
*/
package coa

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/policy"
)

// CosignatureRules is the TN COA cosig fixture.
func CosignatureRules() []policy.CosignatureRule {
	return []policy.CosignatureRule{
		// ── appellate case lifecycle ─────────────────────────────
		{
			EventType:           "appellate_case_initiation",
			RequiredSignerRoles: []string{"court_clerk"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "appellate_opinion_publication",
			RequiredSignerRoles: []string{"judge", "chief_judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "appellate_opinion_participation",
			RequiredSignerRoles: []string{"judge", "chief_judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			// Three-judge panel disposition — require ≥2
			// cosignatures so a single judge cannot dispose of
			// the appeal alone.
			EventType:           "appellate_disposition",
			RequiredSignerRoles: []string{"judge", "chief_judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},

		// ── cross-network: remand back to trial root ────────────
		// IntraExchangeOnly=false: the remand_affirmance event
		// references a trial-court case root from a different
		// exchange.
		{
			EventType:           "remand_affirmance",
			RequiredSignerRoles: []string{"court_clerk", "judge", "chief_judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   false,
		},

		// ── personnel events at the COA ──────────────────────────
		{
			EventType:           "judicial_appointment",
			RequiredSignerRoles: []string{"chief_judge", "judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           "clerk_appointment",
			RequiredSignerRoles: []string{"chief_judge", "judge"},
			MinSignerCosigners:  2,
			IntraExchangeOnly:   true,
		},

		// ── cross-exchange topology events ───────────────────────
		// Inbound case transfers from trial courts (e.g., when
		// the appeal moves between TN COA divisions or to TN
		// Supreme Court).
		{
			EventType:           "case_transfer_inbound",
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   false,
		},
		{
			EventType:           "case_transfer_outbound",
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   false,
		},
		{
			EventType:           "relay_attestation",
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			MinSignerCosigners:  1,
			IntraExchangeOnly:   false,
		},
	}
}

// MustCosignaturePolicy returns a policy populated with
// CosignatureRules or panics.
func MustCosignaturePolicy() *policy.InMemoryPolicy {
	p, err := policy.NewInMemoryPolicy(CosignatureRules())
	if err != nil {
		panic(fmt.Sprintf("tn/coa: cosignature policy invalid: %v", err))
	}
	return p
}
