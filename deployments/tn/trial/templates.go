/*
FILE PATH: deployments/tn/trial/templates.go

DESCRIPTION:

	EntryTemplates — the THIRD leg of the TN trial-court deployment tripod, next
	to CosignatureRules (cosignature_mix.go) and PrerequisiteRules
	(prerequisites.go). Those two face the verifier (they REJECT); these face the
	author (jurisdiction.Compose READS them to EMIT a baseproof-entry-spec/v1).
	One source of truth, two directions.

	Each template carries the authoring shape policy can't: PrimaryRole — WHO
	signs first (Signatures[0]) — and the payload's required fields. The capacity
	blocks (filed_by_capacity / signed_by_capacities) are NOT here: Compose weaves
	them from the cosignature rule + the run's cast, so they cannot diverge from
	the rule.

	Scope: this is the case-lifecycle WALKTHROUGH subset, not the full ~50-event
	vocabulary. jurisdiction.Validate requires only that each template here aligns
	with the cosignature + prerequisite vocabularies (templates ⊆ policy), so the
	set grows event-by-event without a big-bang. Network-level governance events
	(schema_*, mirror_*, key rotation) join as their walkthroughs land.

	Authority inversion in practice: on the attorney filings the CLERK is
	PrimaryRole (the case root's signer, Path A) while the attorney FILES — the
	cast supplies the filer; the cosignature rule's AllowedFilerRoles makes Compose
	weave the filed_by_capacity.
*/
package trial

import "github.com/clearcompass-ai/judicial-network/jurisdiction"

// strv reads a string value from the caller's Values (missing ⇒ "").
func strv(v jurisdiction.Values, key string) string {
	if v == nil {
		return ""
	}
	s, _ := v[key].(string)
	return s
}

// EntryTemplates returns the TN trial-court authoring templates (walkthrough
// subset). Every EventType here has a matching cosignature rule + prerequisite
// vocabulary entry (asserted by jurisdiction.Validate when a bundle exposes
// these via TemplateProvider).
func EntryTemplates() []jurisdiction.EntryTemplate {
	// docket is the common skeleton: most case events carry only the docket.
	docket := func(_ *jurisdiction.CaseContext, v jurisdiction.Values) (map[string]any, error) {
		return map[string]any{"docket_number": strv(v, "docket_number")}, nil
	}
	// disposition skeleton: the judge's case decisions.
	disposition := func(_ *jurisdiction.CaseContext, v jurisdiction.Values) (map[string]any, error) {
		return map[string]any{
			"docket_number": strv(v, "docket_number"),
			"disposition":   strv(v, "disposition"),
		}, nil
	}

	return []jurisdiction.EntryTemplate{
		{
			// Origin event: the case root. Clerk primary + clerk cosign; no filer.
			EventType:   "case_initiation",
			SchemaURI:   "tn-case-initiation-v1",
			PrimaryRole: "court_clerk",
			Mints:       "docket_number",
			Skeleton: func(_ *jurisdiction.CaseContext, v jurisdiction.Values) (map[string]any, error) {
				return map[string]any{
					"docket_number": strv(v, "docket_number"),
					"caption":       strv(v, "caption"),
					"specialty":     strv(v, "specialty"),
				}, nil
			},
		},
		{
			// Attorney files; clerk primary (Path A on the case root) + clerk cosign.
			EventType:   "counsel_appearance",
			SchemaURI:   "tn-counsel-appearance-v1",
			PrimaryRole: "court_clerk",
			Mints:       "binding_id",
			Skeleton:    docket,
		},
		{
			EventType:   "responsive_pleading",
			SchemaURI:   "tn-responsive-pleading-v1",
			PrimaryRole: "court_clerk",
			Skeleton:    docket,
		},
		{
			EventType:   "verdict",
			SchemaURI:   "tn-verdict-v1",
			PrimaryRole: "judge",
			Skeleton:    disposition,
		},
		{
			EventType:   "final_judgment",
			SchemaURI:   "tn-final-judgment-v1",
			PrimaryRole: "judge",
			Skeleton:    disposition,
		},
		{
			EventType:   "transcript_publication",
			SchemaURI:   "tn-transcript-publication-v1",
			PrimaryRole: "court_reporter",
			Skeleton:    docket,
		},
		{
			EventType:   "hearing_convened_concluded",
			SchemaURI:   "tn-hearing-v1",
			PrimaryRole: "court_clerk",
			Skeleton:    docket,
		},
		{
			EventType:   "scheduling_order",
			SchemaURI:   "tn-scheduling-order-v1",
			PrimaryRole: "judge",
			Skeleton:    docket,
		},
		{
			// Fiduciary files; clerk primary + clerk/judge cosign.
			EventType:   "fiduciary_accounting",
			SchemaURI:   "tn-fiduciary-accounting-v1",
			PrimaryRole: "court_clerk",
			Skeleton:    docket,
		},
		{
			// Personnel: ≥2 sitting judges; judge primary.
			EventType:   "judicial_appointment",
			SchemaURI:   "tn-judicial-appointment-v1",
			PrimaryRole: "judge",
			Skeleton: func(_ *jurisdiction.CaseContext, v jurisdiction.Values) (map[string]any, error) {
				return map[string]any{
					"appointee_did":  strv(v, "appointee_did"),
					"appointee_name": strv(v, "appointee_name"),
				}, nil
			},
		},
	}
}

// MustTemplateSet returns the TN trial template registry or panics — the
// boot-time constructor TN county bundles wire into TemplateProvider.
func MustTemplateSet() jurisdiction.TemplateSet {
	return jurisdiction.MustTemplateSet(EntryTemplates()...)
}
