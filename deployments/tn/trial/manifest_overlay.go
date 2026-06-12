/*
FILE PATH: deployments/tn/trial/manifest_overlay.go

DESCRIPTION:

	The TN trial framework's authoring overlay for the network consumption
	manifest — the per-event knowledge the enforced policies do NOT carry
	(primary signer, payload datatype, minted identifiers). STRICTLY
	code-evidenced; events whose authoring shape has no in-repo evidence are
	left bare (the manifest still serves their enforced signing + requires).

	Primary-signer evidence is the ENFORCED model, not the walkthrough doc:
	the cosignature verifier skips Signatures[0] (verification/
	cosignature_signers.go — "Primary signer at sigs[0] is handled by
	AuthorityResolver") and counts the required Signer roles among the
	COSIGNERS — so for filer-driven events the FILER signs first and the
	clerk cosigns (cosignature_mix.go §0), and for pure Signer events the
	named role is the authoritative signature.
*/
package trial

import (
	"github.com/baseproof/tooling/libs/networkbundle"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ManifestOverlay is the trial framework's per-event authoring overlay,
// applied by netmanifest.Build on top of the enforced policy projection.
func ManifestOverlay() map[string]networkbundle.OpOverlay {
	return map[string]networkbundle.OpOverlay{
		// Genesis: the filer files, the clerk cosigns (cosignature_mix.go §0);
		// the case root anchors every later case_ref (prerequisites.go
		// caseInitAncestor).
		"case_initiation": {
			PrimaryRole: "filer",
			Datatype:    schemas.SchemaCivilCaseV1,
			Mints:       []string{"case_ref"},
		},
		// The attorney attests their own appearance (filer primary, clerk
		// cosigns, bpr_number credential — cosignature_mix.go §1) and mints the
		// appearance_id later withdrawals cite (schemas/counsel_appearance.go).
		"counsel_appearance": {
			PrimaryRole: "filer",
			Datatype:    schemas.SchemaCounselAppearanceV1,
			Mints:       []string{"appearance_id"},
		},
		"responsive_pleading": {PrimaryRole: "filer"},

		// §6 court orders: pure Signer-only judicial acts, judge-signed
		// (cosignature_mix.go Part A).
		"scheduling_order":       {PrimaryRole: "judge", Datatype: schemas.SchemaSchedulingOrderV1},
		"interlocutory_order":    {PrimaryRole: "judge", Datatype: schemas.SchemaInterlocutoryOrderV1},
		"verdict":                {PrimaryRole: "judge"},
		"final_judgment":         {PrimaryRole: "judge"},
		"transcript_publication": {PrimaryRole: "court_reporter"},
	}
}
