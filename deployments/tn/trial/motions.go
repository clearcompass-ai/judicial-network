/*
FILE PATH: deployments/tn/trial/motions.go

DESCRIPTION:

	motionSpec — concise per-motion declaration that drives both
	the cosignature mix AND the prerequisite policy from a single
	source of truth. Each §3A–§3I file exposes one section's
	motions as a slice of motionSpec; allMotions() concatenates
	them so CosignatureRules() / PrerequisiteRules() can append
	motion entries without per-motion boilerplate.

	Defaults applied by the helpers:
	  - Cosig: court_clerk-signed, intra-exchange, MinSignerCosigners=1.
	  - Cosig RequiredCredentials: ["bpr_number"] unless overridden.
	  - Prereq: Hard case_initiated ancestor + every spec.AdditionalPrereqs.

	The §3 catch-all motions (motion_pleading_general,
	motion_dispositive_general, etc.) carry CustomTitleRequired=true
	so the writer-side validator can reject empty custom_title fields
	before the entry reaches the ledger. The aggregator surfaces the
	custom_title for read-side queries.

OVERVIEW:

	motionSpec                   per-motion declaration shape.
	caseInitAncestor             shared Hard prereq.
	allMotions                   union of every §3A–§3I file.
	motionCosigRule              motionSpec → policy.CosignatureRule.
	motionPrereqs                motionSpec → []prerequisites.Prereq.
	motionCosignatureRules       allMotions → []policy.CosignatureRule.
	motionPrerequisiteRules      allMotions → map[evt][]prerequisites.Prereq.

KEY DEPENDENCIES:
  - policy.CosignatureRule
  - prerequisites.Prereq
  - schemas.FilerRole
*/
package trial

import (
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// motionSpec is the per-motion declaration. Each §3A–§3I file
// returns a slice of these; the helpers below build the full
// CosignatureRule and Prereq table from them.
type motionSpec struct {
	// EventType is the v1.8 §3 event_type identifier (e.g.
	// "motion_summary_judgment").
	EventType string

	// AllowedFilers is the closed-set Filer role list for this
	// motion. Empty slice = no Filer permitted (Signer-only).
	AllowedFilers []schemas.FilerRole

	// AdditionalPrereqs are appended AFTER the default Hard
	// case_initiated ancestor. May be Hard or Advisory.
	AdditionalPrereqs []prerequisites.Prereq

	// RequiredCredentials override. nil → ["bpr_number"]; empty
	// slice → no credential required (rare; pure-Signer events).
	RequiredCredentials []string

	// CustomTitleRequired flags the *_general catch-all motions
	// per v1.8 Appendix A. Currently informational — the
	// writer-side custom_title validation lives in the schema
	// layer; this flag lets the test suite pin the catch-all
	// list as it grows.
	CustomTitleRequired bool
}

// caseInitAncestor is the shared Hard "every case-lifecycle
// event requires a case_initiated ancestor" prereq used by every
// motion. Defined once here so the §3A–§3I files don't duplicate.
var caseInitAncestor = prerequisites.Prereq{
	Mode:             prerequisites.PrereqModeHard,
	RequiredAncestor: []string{"case_initiated"},
	Reason:           "every case-lifecycle event requires a case_initiated ancestor",
}

// allMotions is the master concatenation of every §3A–§3I
// section. Each file in this package contributes one
// motionsXX() function; this variable's initializer calls
// each in order so the §3 vocabulary is the union of the
// section files. Adding a new section is one append.
//
// Implementation detail: declared as a function (not a var)
// so the section files can return slices without ordering
// concerns at package-init time.
func allMotions() []motionSpec {
	var out []motionSpec
	out = append(out, motions3A()...)
	out = append(out, motions3B()...)
	out = append(out, motions3C()...)
	out = append(out, motions3D()...)
	out = append(out, motions3E()...)
	out = append(out, motions3F()...)
	out = append(out, motions3G()...)
	out = append(out, motions3H()...)
	out = append(out, motions3I()...)
	return out
}

// motionCosigRule maps a motionSpec to a policy.CosignatureRule
// using the §3 default shape (court_clerk-signed, intra-exchange,
// bpr_number-required) unless overridden by the spec.
func motionCosigRule(spec motionSpec) policy.CosignatureRule {
	creds := spec.RequiredCredentials
	if creds == nil {
		creds = []string{"bpr_number"}
	}
	return policy.CosignatureRule{
		EventType:           spec.EventType,
		AllowedFilerRoles:   spec.AllowedFilers,
		RequiredSignerRoles: []string{"court_clerk"},
		MinSignerCosigners:  1,
		IntraExchangeOnly:   true,
		RequiredCredentials: creds,
	}
}

// motionPrereqs prepends the default Hard case_initiated
// ancestor to spec.AdditionalPrereqs.
func motionPrereqs(spec motionSpec) []prerequisites.Prereq {
	out := []prerequisites.Prereq{caseInitAncestor}
	out = append(out, spec.AdditionalPrereqs...)
	return out
}

// motionCosignatureRules returns one CosignatureRule per
// declared motion across every §3A–§3I file.
func motionCosignatureRules() []policy.CosignatureRule {
	specs := allMotions()
	rules := make([]policy.CosignatureRule, 0, len(specs))
	for _, s := range specs {
		rules = append(rules, motionCosigRule(s))
	}
	return rules
}

// motionPrerequisiteRules returns one map entry per declared
// motion across every §3A–§3I file.
func motionPrerequisiteRules() map[string][]prerequisites.Prereq {
	specs := allMotions()
	out := make(map[string][]prerequisites.Prereq, len(specs))
	for _, s := range specs {
		out[s.EventType] = motionPrereqs(s)
	}
	return out
}

// ─── Empty-section stubs (filled by §3A–§3I files) ────────────────
//
// Each motions_3X.go file replaces its stub with the section's
// real motion list. The stubs let this file compile in isolation
// before the section files land.

// (Section files follow.)
