/*
FILE PATH: deployments/frameworks/clerk_base/cosignature_mix.go

DESCRIPTION:

	Cosignature mix rules for every clerk event_type. Reused across
	every clerk office in every state: the SAME marriage_license
	issuance rule applies whether issued by Davidson County Clerk
	or Knox County Clerk — only the office's institutional DID
	differs.

	# Rule shape

	  Each rule names:
	    - The Tier-1 FilerRole permitted to FILE the event (citizen,
	      attorney, branch_walk_in, etc.). Empty = ActorSigner-only.
	    - The clerk roles permitted to COSIGN (RequiredSignerRoles).
	    - The minimum cosigner count.
	    - Whether the event is intra-exchange-only.

	  Most clerk events require a FrontlineDeputyClerk cosignature.
	  High-value events (real_id_issued, transcript_certified) also
	  require a SeniorDeputyClerk or Executive cosignature. Public-
	  record events (judgment_recorded) require an ExecutiveClerk
	  certification.

	# Filer roles

	The Tier-1 FilerRole catalog (schemas/filer.go) doesn't yet have
	"citizen" or "branch_walk_in" filers; this dictionary uses
	whatever the existing FilerRole enum admits, falling back to
	empty (signer-only) when no appropriate FilerRole exists. As the
	FilerRole catalog expands, these rules update accordingly.
*/
package clerk_base

import (
	"github.com/baseproof/tooling/libs/auth/policy"

	"github.com/clearcompass-ai/judicial-network/deployments/platformkinds"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// MustCosignaturePolicy returns the clerk-event cosignature mix.
// Panics on duplicate or invalid rules.
func MustCosignaturePolicy() policy.CosignatureMixPolicy {
	p, err := policy.NewInMemoryPolicy(allClerkRules(), policy.WithKnownFilerRoles(schemas.KnownFilerRoles()...))
	if err != nil {
		panic("clerk_base: cosignature policy: " + err.Error())
	}
	return p
}

// allClerkRules returns one CosignatureRule per event_type the clerk
// dictionary publishes. Order doesn't matter (policy is keyed by
// EventType); listed by category for readability.
func allClerkRules() []policy.CosignatureRule {
	// Convenience role-set slices.
	frontlineOnly := []string{RoleFrontlineDeputyClerk}
	frontlinePlusSenior := []string{RoleFrontlineDeputyClerk, RoleSeniorDeputyClerk}
	frontlineSeniorMgr := []string{
		RoleFrontlineDeputyClerk, RoleSeniorDeputyClerk, RoleBranchManager,
	}
	executiveOnly := []string{RoleExecutiveClerk}
	executivePlusChief := []string{RoleExecutiveClerk, RoleChiefDeputyClerk}
	executiveChiefMgr := []string{
		RoleExecutiveClerk, RoleChiefDeputyClerk, RoleBranchManager,
	}

	rules := []policy.CosignatureRule{
		// ─── COUNTY CLERK civic events ──────────────────────────
		{
			EventType:           EventMarriageLicenseIssued,
			RequiredSignerRoles: frontlineOnly,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventMarriageLicenseReturned,
			RequiredSignerRoles: frontlineOnly,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventVehicleTitleTransfer,
			RequiredSignerRoles: frontlinePlusSenior,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventVehicleRegistrationRenewed,
			RequiredSignerRoles: frontlineOnly,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventBusinessTaxFiled,
			RequiredSignerRoles: frontlineOnly,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventNotaryCommissionIssued,
			RequiredSignerRoles: executivePlusChief,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventPassportApplicationProcessed,
			RequiredSignerRoles: frontlinePlusSenior,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventRealIDIssued,
			RequiredSignerRoles: frontlinePlusSenior,
			MinSignerCosigners:  2, // higher-stakes credential
			IntraExchangeOnly:   true,
		},

		// ─── COURT CLERK records events ─────────────────────────
		{
			EventType:           EventCivilCaseRecordFiled,
			RequiredSignerRoles: frontlineSeniorMgr,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventCriminalCaseRecordFiled,
			RequiredSignerRoles: frontlineSeniorMgr,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventCaseRecordCertified,
			RequiredSignerRoles: executivePlusChief,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventTranscriptCertified,
			RequiredSignerRoles: executiveOnly,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventJudgmentRecorded,
			RequiredSignerRoles: executivePlusChief,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventSubpoenaIssued,
			RequiredSignerRoles: frontlineSeniorMgr,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventBondCollected,
			RequiredSignerRoles: frontlinePlusSenior,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventBondReturned,
			RequiredSignerRoles: frontlinePlusSenior,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},

		// ─── CLERK AND MASTER events ────────────────────────────
		{
			EventType:           EventProbateWillFiled,
			RequiredSignerRoles: executiveChiefMgr,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventEstateInventoryFiled,
			RequiredSignerRoles: executiveChiefMgr,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventChanceryDecreeRecorded,
			RequiredSignerRoles: executiveOnly,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventReceivershipAppointed,
			RequiredSignerRoles: executiveOnly,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventQuasiJudicialOrder,
			RequiredSignerRoles: executiveOnly,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},

		// ─── Office administration ──────────────────────────────
		{
			EventType:           EventDeputyAppointed,
			RequiredSignerRoles: executiveChiefMgr,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
		{
			EventType:           EventBranchManagerAppointed,
			RequiredSignerRoles: executivePlusChief,
			MinSignerCosigners:  1,
			IntraExchangeOnly:   true,
		},
	}

	// ── PLATFORM REGISTRY KINDS (rc10) — clerk-exchange vocabulary:
	// destination governance is an executive-tier act here.
	rules = append(rules, platformkinds.CosignatureRulesWithRoles(executivePlusChief)...)
	return rules
}
