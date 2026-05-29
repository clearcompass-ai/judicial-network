/*
FILE PATH: deployments/frameworks/county_profile/profile.go

DESCRIPTION:

	CountyProfile — the SINGLE declarative description of a county's
	court + clerk structure. Every county is one CountyProfile
	literal; per-county registry "functions" go away.

	A CountyProfile is data, not code. Adding a new county is one
	literal in deployments/registry/<state>_counties.go; the framework
	never changes.

	# Reusability model

	  Three orthogonal axes drive a county's institutional shape:

	    1. Size  (Large / Medium / Small) — drives WHICH clerk offices
	             exist. Large counties get separate elected Criminal
	             Court Clerk; small counties consolidate everything
	             under one Circuit Court Clerk. State conventions
	             decide; CountyProfile just declares Size.

	    2. Court inventory — the trial courts the county runs. Each
	             slot generates ONE OR MORE exchanges (a Davidson
	             Circuit Court "Part 7" is its own exchange, not a
	             subdivision of one umbrella court).

	    3. Courthouses — physical locations. Most counties have one;
	             Sullivan has three (Bristol / Kingsport / Blountville).
	             A CourtSlot can be replicated PER-COURTHOUSE for
	             multi-courthouse counties.

	The Expand function in generators.go takes a CountyProfile + a
	state_profile.Conventions and produces a flat list of composer
	Specs (courts) and ClerkSpecs (clerk offices).

	# Why "Part/Court" instead of "Division"

	Each TN judge's court is a separate exchange — its own
	institutional DID, its own signing key, its own filings. Calling
	it "Davidson Circuit Court, Division 1" suggests a subdivision of
	one umbrella court; the reality is 8 separate Circuit Courts that
	share the title. NameFmt formats the human-readable name with the
	per-court ordinal; the structure of independent courts is encoded
	in the per-court Spec the generator emits.
*/
package county_profile

import (
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
)

// CountySize classifies a county for the state convention's
// clerk-roster lookup. The classification is a state's editorial call
// (no nationwide threshold); state conventions interpret it locally.
type CountySize int

const (
	// SizeLarge — major metropolitan county. In TN, gets separate
	// elected Criminal Court Clerk and (usually) separate Juvenile
	// Court Clerk. Examples: Davidson, Knox, Shelby, Hamilton.
	SizeLarge CountySize = iota

	// SizeMedium — middle-tier county. Some role consolidation; the
	// state convention specifies exactly which roles consolidate.
	SizeMedium

	// SizeSmall — rural county. Circuit Court Clerk typically wears
	// Circuit + Criminal + General Sessions + Juvenile hats. The
	// County Clerk and Clerk and Master remain separate.
	SizeSmall
)

func (s CountySize) String() string {
	switch s {
	case SizeLarge:
		return "large"
	case SizeMedium:
		return "medium"
	case SizeSmall:
		return "small"
	default:
		return "unknown"
	}
}

// CountyProfile declares one county's institutional layout.
//
// The struct is data — every field has a zero value that means
// "default", and the generator + state convention fill in the
// missing pieces from the state's standard pattern.
type CountyProfile struct {
	// State is the two-letter postal code. Required.
	State string

	// Name is the county's display name (e.g. "Davidson", "Knox").
	// Combined with State to form the slug used in DIDs (lowercased,
	// underscores). Required.
	Name string

	// Size is the population/workload tier the state convention uses
	// to pick the clerk roster.
	Size CountySize

	// Courthouses are the physical buildings where this county's
	// courts hold session. Most counties have one; multi-courthouse
	// counties (e.g. Sullivan TN) list each with a stable ID.
	// At least one entry required.
	Courthouses []Courthouse

	// Courts lists the trial courts in this county. Each CourtSlot
	// generates Count exchanges (or len(Courthouses) * PerCourthouse
	// when PerCourthouse is set).
	Courts []CourtSlot

	// ExtraClerks lets a county add additional clerk offices beyond
	// the state convention's standard roster (e.g. a county that
	// has its OWN Juvenile Court Clerk separate from Circuit). Empty
	// for the common case — state convention determines the roster.
	ExtraClerks []ClerkSlot

	// SkipClerkTypes lets a county OMIT clerk offices the state
	// convention would normally generate (e.g. a small TN county
	// where General Sessions is folded under the Circuit Court Clerk
	// despite being a "medium-sized" county). Empty for the common
	// case.
	SkipClerkTypes []ClerkType
}

// Courthouse is a physical court location. The ID is used in DIDs
// and human-readable names when a multi-courthouse county replicates
// court slots across buildings.
type Courthouse struct {
	// ID is the slug used in DIDs. Required, lowercase, snake_case.
	// Examples: "main", "bristol", "kingsport".
	ID string

	// Name is human-readable. Surfaced in court-spec Name fields.
	Name string

	// Address is the public courthouse address. Cosmetic only;
	// surfaced in audit trails.
	Address string
}

// CourtSlot describes one TYPE of court in this county. Generates
// Count independent court exchanges (one per division/part) OR
// PerCourthouse * len(Courthouses) exchanges (for multi-courthouse
// counties).
type CourtSlot struct {
	// Type identifies the primary court_type (Circuit, Chancery, etc).
	Type composer.CourtType

	// Count is the number of independent courts of this type in
	// this county that share ONE courthouse. For Davidson:
	// Circuit Court has Count=8, Chancery has Count=4. For
	// single-court types: Count=1.
	//
	// Use Count XOR PerCourthouse, not both.
	Count int

	// PerCourthouse is the number of independent courts of this type
	// in EACH courthouse, for multi-courthouse counties. The
	// generator emits PerCourthouse * len(Courthouses) total
	// exchanges. Use for Sullivan-style counties.
	//
	// Use Count XOR PerCourthouse, not both.
	PerCourthouse int

	// ExtraTypes are additional court types this slot's courts also
	// exercise. Example: Knox Chancery hears Probate, so a Knox
	// Chancery CourtSlot lists ExtraTypes: []CourtType{Probate}.
	ExtraTypes []composer.CourtType

	// Overlays per ordinal lets a specific court within the slot
	// carry extra capabilities. Example: Davidson Circuit Court
	// Part 7 is the Probate Division — Overlays[7] = [Probate].
	// Keyed by 1-based ordinal.
	Overlays map[int][]composer.CourtType

	// NameFmt is the human-readable name template. Supports two
	// substitutions:
	//   %d  → ordinal (1, 2, ...)
	//   %s  → Roman numeral form of ordinal (I, II, ...) OR
	//         courthouse name (multi-courthouse mode)
	// Required.
	NameFmt string

	// DIDSegment is the segment used in DIDs (lowercased, snake_case).
	// Defaults to Type.String() when empty. Override to disambiguate
	// (e.g. Davidson splits "gen_sessions_civil" and
	// "gen_sessions_criminal" though both are CourtType=GeneralSessions).
	DIDSegment string

	// AppealCivilTo is the DID this slot's civil/equity courts appeal
	// to. Defaults vary by state — TN counties' AppealCivilTo is
	// "did:web:state:tn:coa:<grand-division>". Optional override per
	// CountyProfile.
	AppealCivilTo string

	// AppealCriminalTo is the DID this slot's criminal courts appeal
	// to. TN: "did:web:state:tn:coca:<grand-division>". Optional.
	AppealCriminalTo string
}

// ClerkType is the standardized clerk-office classification used
// across states. State conventions map state-specific role names
// (Court Executive Officer, Clerk and Master, …) to these tags.
type ClerkType int

const (
	// ClerkTypeCounty — civic-administration clerk: marriage
	// licenses, vehicle registrations, business tax, passports.
	// TN: elected County Clerk.
	ClerkTypeCounty ClerkType = iota

	// ClerkTypeCircuitCourt — civil-litigation records clerk.
	// TN: elected Circuit Court Clerk. In small TN counties may
	// also handle Criminal + GS + Juvenile records.
	ClerkTypeCircuitCourt

	// ClerkTypeCriminalCourt — separately-elected criminal-records
	// clerk. Exists in large TN counties only (Davidson, Knox, Shelby,
	// Hamilton).
	ClerkTypeCriminalCourt

	// ClerkTypeClerkAndMaster — chancery and probate records clerk
	// + quasi-judicial officer. Appointed by Chancellors, not elected.
	// Distinct from other clerks; ALWAYS separate in TN regardless
	// of county size.
	ClerkTypeClerkAndMaster

	// ClerkTypeGeneralSessions — separately-elected General Sessions
	// Court Clerk. Rare; most TN counties fold this under Circuit
	// Court Clerk.
	ClerkTypeGeneralSessions

	// ClerkTypeJuvenile — separately-elected Juvenile Court Clerk.
	// Rare; usually under Circuit Court Clerk.
	ClerkTypeJuvenile

	// ClerkTypeCourtExecutiveOfficer — CA model. ONE appointed
	// (by presiding judge) clerk per Superior Court, responsible
	// for the entire administrative apparatus of that court.
	ClerkTypeCourtExecutiveOfficer

	// ClerkTypeFederalDistrict — federal District Court Clerk
	// appointed by the Court.
	ClerkTypeFederalDistrict

	// ClerkTypeFederalCircuit — federal Circuit Court Clerk
	// appointed by the Court.
	ClerkTypeFederalCircuit

	// ClerkTypeSupremeCourt — SCOTUS Clerk + state Supreme Court Clerks.
	ClerkTypeSupremeCourt
)

func (c ClerkType) String() string {
	switch c {
	case ClerkTypeCounty:
		return "county_clerk"
	case ClerkTypeCircuitCourt:
		return "circuit_clerk"
	case ClerkTypeCriminalCourt:
		return "criminal_clerk"
	case ClerkTypeClerkAndMaster:
		return "clerk_and_master"
	case ClerkTypeGeneralSessions:
		return "gen_sessions_clerk"
	case ClerkTypeJuvenile:
		return "juvenile_clerk"
	case ClerkTypeCourtExecutiveOfficer:
		return "court_executive_officer"
	case ClerkTypeFederalDistrict:
		return "fed_district_clerk"
	case ClerkTypeFederalCircuit:
		return "fed_circuit_clerk"
	case ClerkTypeSupremeCourt:
		return "supreme_clerk"
	default:
		return "unknown"
	}
}

// Selection is how a clerk takes office. Drives the role catalog
// and the credential class the clerk's filings must carry.
type Selection int

const (
	// SelectionElected — chosen by the county's voters. Most TN
	// clerks. Term-limited per state law.
	SelectionElected Selection = iota

	// SelectionAppointedByChancellors — appointed by the local
	// Chancery Court Judges (Chancellors). TN's Clerk and Master
	// is appointed this way.
	SelectionAppointedByChancellors

	// SelectionAppointedByPresidingJudge — appointed by the
	// presiding judge of the court the clerk serves. CA's Court
	// Executive Officer is appointed this way.
	SelectionAppointedByPresidingJudge

	// SelectionAppointedByCourt — appointed by the court's panel
	// (federal Circuit Court Clerks).
	SelectionAppointedByCourt
)

func (s Selection) String() string {
	switch s {
	case SelectionElected:
		return "elected"
	case SelectionAppointedByChancellors:
		return "appointed_by_chancellors"
	case SelectionAppointedByPresidingJudge:
		return "appointed_by_presiding_judge"
	case SelectionAppointedByCourt:
		return "appointed_by_court"
	default:
		return "unknown"
	}
}

// ClerkSlot declares one clerk office. Generated by a state
// convention's roster for the CountyProfile, OR listed in
// CountyProfile.ExtraClerks for one-off additions.
type ClerkSlot struct {
	// Type identifies the clerk-office classification.
	Type ClerkType

	// Selection is how the clerk takes office.
	Selection Selection

	// ServesAlso lists OTHER clerk types this office covers in
	// counties where roles consolidate. Example: in small TN
	// counties the Circuit Court Clerk also serves Criminal + GS +
	// Juvenile records; ServesAlso would list those three types.
	ServesAlso []ClerkType

	// NameFmt is the human-readable name. Supports %s for the
	// county name (e.g. "Davidson"). Required.
	NameFmt string

	// DIDSegment is the segment used in clerk DIDs. Defaults to
	// Type.String() when empty. Example: "clerk:circuit".
	DIDSegment string

	// Branches are the physical satellite offices this clerk runs.
	// Knox County Clerk has Main + 5 satellites. Empty = single
	// office at the county's main courthouse.
	Branches []Branch
}

// Branch is a physical satellite location of a clerk office.
// Distinct from Courthouse: a Courthouse holds court session; a
// Branch is a service counter. Knox County Clerk's West Knoxville
// branch is a service counter; Davidson Circuit Court Part 1 sits
// in a Courthouse.
type Branch struct {
	// ID is the slug used in DIDs (lowercased, snake_case).
	ID string

	// Name is human-readable.
	Name string

	// Address is the public service-counter address.
	Address string
}
