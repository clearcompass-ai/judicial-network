/*
FILE PATH: deployments/frameworks/clerk_base/event_dictionary.go

DESCRIPTION:

	Closed-set event_type catalog for clerk-office operations. The
	dictionary is intentionally SEPARATE from the court event
	dictionary (policy/cosignature_mix.go) because clerk events
	have different cosignature shapes, different prerequisite
	chains, and different audit-trail consumers.

	# Event categories

	  COUNTY CLERK (civic admin):
	    marriage_license_issued, marriage_license_returned
	    vehicle_title_transfer, vehicle_registration_renewed
	    business_tax_filed, notary_commission_issued
	    passport_application_processed, real_id_issued

	  COURT CLERK (records management):
	    civil_case_record_filed, criminal_case_record_filed
	    case_record_certified, transcript_certified
	    judgment_recorded, subpoena_issued
	    bond_collected, bond_returned

	  CLERK AND MASTER (chancery/probate-specific):
	    probate_will_filed, estate_inventory_filed
	    chancery_decree_recorded, receivership_appointed
	    quasi_judicial_order

	# Adding events

	A new event_type:
	   1. Const declared here.
	   2. CosignatureRule appended in cosignature_mix.go.
	   3. Verifier consumes it identically to existing events.
	No framework changes outside this directory.
*/
package clerk_base

// ─── County Clerk civic events ──────────────────────────────────────
const (
	EventMarriageLicenseIssued       = "clerk_marriage_license_issued"
	EventMarriageLicenseReturned     = "clerk_marriage_license_returned"
	EventVehicleTitleTransfer        = "clerk_vehicle_title_transfer"
	EventVehicleRegistrationRenewed  = "clerk_vehicle_registration_renewed"
	EventBusinessTaxFiled            = "clerk_business_tax_filed"
	EventNotaryCommissionIssued      = "clerk_notary_commission_issued"
	EventPassportApplicationProcessed = "clerk_passport_application_processed"
	EventRealIDIssued                = "clerk_real_id_issued"
)

// ─── Court Clerk records-management events ──────────────────────────
const (
	EventCivilCaseRecordFiled    = "clerk_civil_case_record_filed"
	EventCriminalCaseRecordFiled = "clerk_criminal_case_record_filed"
	EventCaseRecordCertified     = "clerk_case_record_certified"
	EventTranscriptCertified     = "clerk_transcript_certified"
	EventJudgmentRecorded        = "clerk_judgment_recorded"
	EventSubpoenaIssued          = "clerk_subpoena_issued"
	EventBondCollected           = "clerk_bond_collected"
	EventBondReturned            = "clerk_bond_returned"
)

// ─── Clerk and Master events ────────────────────────────────────────
const (
	EventProbateWillFiled       = "clerk_probate_will_filed"
	EventEstateInventoryFiled   = "clerk_estate_inventory_filed"
	EventChanceryDecreeRecorded = "clerk_chancery_decree_recorded"
	EventReceivershipAppointed  = "clerk_receivership_appointed"
	EventQuasiJudicialOrder     = "clerk_quasi_judicial_order"
)

// ─── Office-administration events (apply to every clerk type) ───────
const (
	EventDeputyAppointed   = "clerk_deputy_appointed"
	EventBranchManagerAppointed = "clerk_branch_manager_appointed"
)

// AllEventTypes returns every clerk event_type the framework
// dictionary publishes. Used by the cosignature_mix loader and by
// tests that pin coverage.
func AllEventTypes() []string {
	return []string{
		// County Clerk
		EventMarriageLicenseIssued,
		EventMarriageLicenseReturned,
		EventVehicleTitleTransfer,
		EventVehicleRegistrationRenewed,
		EventBusinessTaxFiled,
		EventNotaryCommissionIssued,
		EventPassportApplicationProcessed,
		EventRealIDIssued,
		// Court Clerk
		EventCivilCaseRecordFiled,
		EventCriminalCaseRecordFiled,
		EventCaseRecordCertified,
		EventTranscriptCertified,
		EventJudgmentRecorded,
		EventSubpoenaIssued,
		EventBondCollected,
		EventBondReturned,
		// Clerk and Master
		EventProbateWillFiled,
		EventEstateInventoryFiled,
		EventChanceryDecreeRecorded,
		EventReceivershipAppointed,
		EventQuasiJudicialOrder,
		// Office administration
		EventDeputyAppointed,
		EventBranchManagerAppointed,
	}
}
