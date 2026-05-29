/*
FILE PATH: deployments/frameworks/county_profile/generators.go

DESCRIPTION:

	Expand — takes a CountyProfile + a state Conventions instance
	and produces the flat list of court Specs + ClerkSpecs the
	registry registers. This is where declarative data becomes
	composable bundles.

	# Generation pipeline

	    CountyProfile + Conventions
	         ↓
	    Expand()
	         ↓
	    ┌──────────────────────────┬────────────────────────┐
	    │ expandCourts()           │ expandClerks()         │
	    │  - iterate CourtSlots    │  - state convention    │
	    │  - apply Count or        │    picks clerk roster  │
	    │    PerCourthouse         │    by CountyProfile.Size│
	    │  - apply Overlays per    │  - extras + skips      │
	    │    ordinal               │    applied             │
	    │  - emit one Spec per     │  - emit one ClerkSpec  │
	    │    independent court     │    per clerk           │
	    └──────────────────────────┴────────────────────────┘
*/
package county_profile

import (
	"fmt"
	"strings"

	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
)

// Conventions is the state-specific behavior the generator needs.
// Each state_profile/<state>.go provides its own implementation.
//
// The interface is intentionally narrow: state conventions answer
// "what clerks does a county of this size have?" and "what credentials
// do this state's courts require?" — nothing more.
type Conventions interface {
	// StatePostalCode returns the 2-letter code ("TN", "CA").
	StatePostalCode() string

	// AttorneyCredentials returns the bar credentials a court in
	// this state requires (TN BPR, CA Bar). Most states have one;
	// federal courts return per-court federal admissions.
	AttorneyCredentials(courtDID string) []credentials.Credential

	// ClerksFor returns the clerk roster a county of this Size has
	// in this state. TN's SizeLarge returns 4 clerks; SizeSmall
	// returns 3 consolidated. CA returns one CEO per Superior.
	ClerksFor(profile CountyProfile) []ClerkSlot

	// CivilAppellateDID returns the DID of the intermediate
	// appellate court that hears civil/equity appeals from the
	// given county. May vary by region (TN's COA grand divisions:
	// East / Middle / West).
	CivilAppellateDID(countyName string) string

	// CriminalAppellateDID is the same for criminal appeals
	// (TN: COCA grand divisions).
	CriminalAppellateDID(countyName string) string
}

// Expand reduces a CountyProfile to a flat list of court Specs and
// ClerkSpecs. The two lists are returned separately because the
// composer builds them with different paths.
func Expand(profile CountyProfile, conv Conventions) (courts []composer.Spec, clerks []ClerkSpec) {
	if profile.State == "" {
		panic("county_profile.Expand: profile.State is empty")
	}
	if profile.Name == "" {
		panic("county_profile.Expand: profile.Name is empty")
	}
	if len(profile.Courthouses) == 0 {
		panic(fmt.Sprintf("county_profile.Expand: %s has no Courthouses", profile.Name))
	}

	for _, slot := range profile.Courts {
		courts = append(courts, expandCourtSlot(profile, slot, conv)...)
	}
	clerks = append(clerks, expandClerks(profile, conv)...)
	return
}

// expandCourtSlot produces the independent-court Specs for one slot.
// Each ordinal becomes its OWN exchange (not a subdivision of an
// umbrella court). Multi-courthouse counties replicate the slot
// across each courthouse.
func expandCourtSlot(profile CountyProfile, slot CourtSlot, conv Conventions) []composer.Spec {
	if slot.Count > 0 && slot.PerCourthouse > 0 {
		panic(fmt.Sprintf("court slot %s in %s: Count and PerCourthouse mutually exclusive",
			slot.Type, profile.Name))
	}
	if slot.NameFmt == "" {
		panic(fmt.Sprintf("court slot %s in %s: NameFmt required", slot.Type, profile.Name))
	}

	didSegment := slot.DIDSegment
	if didSegment == "" {
		didSegment = slot.Type.String()
	}
	countySlug := slugify(profile.Name)
	appealCivil := slot.AppealCivilTo
	if appealCivil == "" {
		appealCivil = conv.CivilAppellateDID(profile.Name)
	}
	appealCriminal := slot.AppealCriminalTo
	if appealCriminal == "" {
		appealCriminal = conv.CriminalAppellateDID(profile.Name)
	}
	// Civil-side courts (Circuit/Chancery/Probate/GS/Juvenile) appeal
	// civil-side; Criminal-only courts appeal criminal-side.
	appeal := appealCivil
	if isCriminalOnly(slot.Type, slot.ExtraTypes) {
		appeal = appealCriminal
	}

	var specs []composer.Spec
	if slot.PerCourthouse > 0 {
		// Multi-courthouse: replicate slot across every courthouse.
		for _, ch := range profile.Courthouses {
			for i := 1; i <= slot.PerCourthouse; i++ {
				specs = append(specs, buildCourtSpec(
					profile, slot, conv,
					fmt.Sprintf("did:web:state:%s:%s:%s:%s:%d",
						strings.ToLower(profile.State), countySlug, didSegment, ch.ID, i),
					formatCourtName(slot.NameFmt, i, ch.Name),
					i, appeal,
				))
			}
		}
		return specs
	}
	// Single-courthouse: emit Count exchanges. For Count==1 the
	// ordinal suffix is dropped (a single-instance court like Davidson
	// Juvenile or a CA Superior gets did:web:state:..:<county>:<segment>
	// instead of …:<segment>:1).
	count := slot.Count
	if count <= 0 {
		count = 1
	}
	for i := 1; i <= count; i++ {
		var did string
		if count == 1 {
			did = fmt.Sprintf("did:web:state:%s:%s:%s",
				strings.ToLower(profile.State), countySlug, didSegment)
		} else {
			did = fmt.Sprintf("did:web:state:%s:%s:%s:%d",
				strings.ToLower(profile.State), countySlug, didSegment, i)
		}
		specs = append(specs, buildCourtSpec(
			profile, slot, conv, did,
			formatCourtName(slot.NameFmt, i, ""), i, appeal,
		))
	}
	return specs
}

// buildCourtSpec assembles one composer.Spec from a CourtSlot's
// per-ordinal data + the slot-level capabilities + any per-ordinal
// overlays (e.g. Davidson Circuit Part 7 = Probate Division).
func buildCourtSpec(profile CountyProfile, slot CourtSlot, conv Conventions,
	did, name string, ordinal int, appealTo string) composer.Spec {
	types := []composer.CourtType{slot.Type}
	types = append(types, slot.ExtraTypes...)
	if overlay, ok := slot.Overlays[ordinal]; ok {
		types = append(types, overlay...)
	}
	return composer.Spec{
		DID:                 did,
		Name:                name,
		Tier:                composer.TierTrial,
		CourtTypes:          types,
		Jurisdiction:        composer.Jurisdiction{State: profile.State, County: profile.Name},
		RequiredCredentials: conv.AttorneyCredentials(did),
		AppellatePath:       appealTo,
	}
}

// formatCourtName resolves NameFmt's %d / %s substitutions.
// %d → ordinal; %s → Roman numeral OR courthouse name (multi-courthouse mode).
func formatCourtName(format string, ordinal int, courthouse string) string {
	out := format
	if strings.Contains(out, "%d") {
		out = strings.Replace(out, "%d", fmt.Sprintf("%d", ordinal), 1)
	}
	if strings.Contains(out, "%s") {
		if courthouse != "" {
			out = strings.Replace(out, "%s", courthouse, 1)
		} else {
			out = strings.Replace(out, "%s", roman(ordinal), 1)
		}
	}
	return out
}

// isCriminalOnly reports whether a slot's type-set covers only
// criminal matters. Used to decide which appellate court to point
// to for the AppellatePath.
func isCriminalOnly(primary composer.CourtType, extras []composer.CourtType) bool {
	all := append([]composer.CourtType{primary}, extras...)
	hasCriminal := false
	hasCivil := false
	for _, t := range all {
		switch t {
		case composer.CourtTypeCriminal:
			hasCriminal = true
		case composer.CourtTypeCircuit,
			composer.CourtTypeChancery,
			composer.CourtTypeProbate,
			composer.CourtTypeJuvenile,
			composer.CourtTypeGeneralSessions,
			composer.CourtTypeUnifiedSuperior,
			composer.CourtTypeDistrict:
			hasCivil = true
		}
	}
	return hasCriminal && !hasCivil
}

// expandClerks applies the state convention's clerk roster to the
// county profile, plus any ExtraClerks the profile declares and any
// SkipClerkTypes the profile excludes.
func expandClerks(profile CountyProfile, conv Conventions) []ClerkSpec {
	roster := conv.ClerksFor(profile)
	// Apply SkipClerkTypes filter.
	skip := make(map[ClerkType]bool, len(profile.SkipClerkTypes))
	for _, s := range profile.SkipClerkTypes {
		skip[s] = true
	}
	var slots []ClerkSlot
	for _, s := range roster {
		if !skip[s.Type] {
			slots = append(slots, s)
		}
	}
	slots = append(slots, profile.ExtraClerks...)

	var specs []ClerkSpec
	countySlug := slugify(profile.Name)
	for _, slot := range slots {
		didSegment := slot.DIDSegment
		if didSegment == "" {
			didSegment = "clerk:" + clerkSlugPart(slot.Type)
		}
		did := fmt.Sprintf("did:web:state:%s:%s:%s",
			strings.ToLower(profile.State), countySlug, didSegment)
		name := slot.NameFmt
		if strings.Contains(name, "%s") {
			name = strings.Replace(name, "%s", profile.Name, 1)
		}
		// Merge slot's static branches with per-county overrides.
		branches := append([]Branch(nil), slot.Branches...)
		if extra, ok := profile.ClerkBranches[slot.Type]; ok {
			branches = append(branches, extra...)
		}
		specs = append(specs, ClerkSpec{
			DID:                 did,
			Name:                name,
			Type:                slot.Type,
			Selection:           slot.Selection,
			Jurisdiction:        composer.Jurisdiction{State: profile.State, County: profile.Name},
			ServesAlso:          slot.ServesAlso,
			Branches:            branches,
			RequiredCredentials: clerkCredentials(slot.Type, conv),
		})
	}
	return specs
}

// clerkSlugPart returns the DID segment fragment for a ClerkType when
// no explicit DIDSegment is set. Drops the "_clerk" suffix to keep
// DIDs tight.
func clerkSlugPart(ct ClerkType) string {
	switch ct {
	case ClerkTypeCounty:
		return "county"
	case ClerkTypeCircuitCourt:
		return "circuit"
	case ClerkTypeCriminalCourt:
		return "criminal"
	case ClerkTypeClerkAndMaster:
		return "chancery_master"
	case ClerkTypeGeneralSessions:
		return "gen_sessions"
	case ClerkTypeJuvenile:
		return "juvenile"
	case ClerkTypeCourtExecutiveOfficer:
		return "executive_officer"
	case ClerkTypeFederalDistrict:
		return "federal_district"
	case ClerkTypeFederalCircuit:
		return "federal_circuit"
	case ClerkTypeSupremeCourt:
		return "supreme"
	default:
		return "unknown"
	}
}

// clerkCredentials returns the credential classes a clerk's filings
// must carry. Today's stub returns the state's attorney credential
// (clerks often sign filings prepared by attorneys). When clerk-
// certification credentials land, this returns those alongside.
func clerkCredentials(_ ClerkType, conv Conventions) []credentials.Credential {
	// Clerks don't have a court DID for AttorneyCredentials; pass empty.
	return conv.AttorneyCredentials("")
}

// slugify lowercases and snake-cases a county name for DID embedding.
func slugify(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	return s
}

// roman returns the Roman numeral for 1-10. Used to render Chancery
// Court parts ("Part I", "Part II", ...) when NameFmt has %s.
func roman(n int) string {
	switch n {
	case 1:
		return "I"
	case 2:
		return "II"
	case 3:
		return "III"
	case 4:
		return "IV"
	case 5:
		return "V"
	case 6:
		return "VI"
	case 7:
		return "VII"
	case 8:
		return "VIII"
	case 9:
		return "IX"
	case 10:
		return "X"
	}
	return fmt.Sprintf("%d", n)
}
