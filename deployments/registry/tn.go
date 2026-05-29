/*
FILE PATH: deployments/registry/tn.go

DESCRIPTION:

	Tennessee court registry entries — every court in scope:

	  TN Supreme Court                   (1)
	  TN Court of Appeals                (3 grand divisions: East / Middle / West)
	  TN Court of Criminal Appeals       (3 grand divisions: East / Middle / West)
	  Davidson County trial courts       (Circuit 1-8, Chancery I-IV,
	                                      Criminal 1-6, General Sessions
	                                      civil + criminal, Juvenile)
	  Knox County trial courts           (Circuit 1-4, Chancery I-III,
	                                      Criminal 1-3, General Sessions,
	                                      Juvenile)

	# TN's trial-court structure (the design backing this file)

	TN has THIS structure (NOT a unified trial court like CA):

	  Circuit Court        — law (civil + some criminal). Multiple
	                         divisions per county; each "division" is
	                         an independently presided court.
	  Chancery Court       — equity. Multiple "parts" per county.
	                         Whether Chancery hears probate depends on
	                         the county: Davidson has a SEPARATE
	                         Probate Court; Knox folds probate into
	                         Chancery.
	  Criminal Court       — separately-organized felony court.
	                         Exists in Davidson, Knox, and other
	                         larger counties.
	  General Sessions     — limited jurisdiction: small claims,
	                         misdemeanors, preliminary hearings.
	                         Multiple divisions (civil + criminal).
	  Juvenile Court       — delinquency, dependency, neglect. One
	                         per county.

	# Divisions

	Each "Division N" is a separate court for our purposes — it has
	its own DID, its own assigned judge, and cases are routed to
	specific divisions. This is realer than treating "Davidson Circuit
	Court" as one entity. The framework's per-Spec model handles
	divisions naturally.
*/
package registry

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials/attorney"
)

// TennesseeSpecs returns every TN court entry. Stable order: Supreme,
// COA, COCA, Davidson, Knox.
func TennesseeSpecs() []composer.Spec {
	var specs []composer.Spec
	specs = append(specs, tnSupreme())
	specs = append(specs, tnCOAGrandDivisions()...)
	specs = append(specs, tnCOCAGrandDivisions()...)
	specs = append(specs, tnDavidsonCourts()...)
	specs = append(specs, tnKnoxCourts()...)
	return specs
}

// tnSupreme returns the TN Supreme Court spec.
func tnSupreme() composer.Spec {
	return composer.Spec{
		DID:                 "did:web:state:tn:sc",
		Name:                "Tennessee Supreme Court",
		Tier:                composer.TierSupreme,
		CourtTypes:          []composer.CourtType{composer.CourtTypeSupreme},
		Jurisdiction:        composer.Jurisdiction{State: "TN"},
		RequiredCredentials: []credentials.Credential{attorney.TN_BPR()},
	}
}

// tnCOAGrandDivisions returns the 3 TN Court of Appeals grand divisions.
// TN's intermediate civil appellate court sits as 3 grand divisions
// (Eastern in Knoxville, Middle in Nashville, Western in Jackson).
func tnCOAGrandDivisions() []composer.Spec {
	return []composer.Spec{
		tnIntermediateAppellate("coa", "east", "Eastern Grand Division (Knoxville)", "did:web:state:tn:sc"),
		tnIntermediateAppellate("coa", "middle", "Middle Grand Division (Nashville)", "did:web:state:tn:sc"),
		tnIntermediateAppellate("coa", "west", "Western Grand Division (Jackson)", "did:web:state:tn:sc"),
	}
}

// tnCOCAGrandDivisions returns the 3 TN Court of Criminal Appeals grand divisions.
// The TN criminal appellate court mirrors the COA's geographic structure.
func tnCOCAGrandDivisions() []composer.Spec {
	return []composer.Spec{
		tnIntermediateAppellate("coca", "east", "Eastern Grand Division (Knoxville)", "did:web:state:tn:sc"),
		tnIntermediateAppellate("coca", "middle", "Middle Grand Division (Nashville)", "did:web:state:tn:sc"),
		tnIntermediateAppellate("coca", "west", "Western Grand Division (Jackson)", "did:web:state:tn:sc"),
	}
}

// tnIntermediateAppellate is the per-grand-division spec builder.
func tnIntermediateAppellate(courtAbbrev, division, displayDivision, appealTo string) composer.Spec {
	courtName := "Court of Appeals"
	if courtAbbrev == "coca" {
		courtName = "Court of Criminal Appeals"
	}
	return composer.Spec{
		DID:                 fmt.Sprintf("did:web:state:tn:%s:%s", courtAbbrev, division),
		Name:                fmt.Sprintf("Tennessee %s, %s", courtName, displayDivision),
		Tier:                composer.TierIntermediateAppellate,
		CourtTypes:          []composer.CourtType{composer.CourtTypeIntermediateAppellate},
		Jurisdiction:        composer.Jurisdiction{State: "TN"},
		RequiredCredentials: []credentials.Credential{attorney.TN_BPR()},
		AppellatePath:       appealTo,
	}
}

// ─── Davidson County (Nashville) ─────────────────────────────────────
// Davidson has the most elaborated trial-court system in TN: 8
// Circuit divisions (the 7th Circuit Division IS the Probate Division),
// 4 Chancery parts (equity, NOT probate), 6 Criminal Court divisions,
// General Sessions (multiple civil + criminal divisions), and a
// Juvenile Court.

func tnDavidsonCourts() []composer.Spec {
	const county = "davidson"
	const appealCivil = "did:web:state:tn:coa:middle"
	const appealCriminal = "did:web:state:tn:coca:middle"

	var specs []composer.Spec

	// Circuit Court: divisions 1-8. Division 7 is the Probate Division
	// (handles estates, conservatorships, guardianships); it gets the
	// CourtTypeProbate overlay in addition to Circuit.
	for i := 1; i <= 8; i++ {
		ct := []composer.CourtType{composer.CourtTypeCircuit}
		name := fmt.Sprintf("Davidson County Circuit Court, Division %d", i)
		appeals := appealCivil
		if i == 7 {
			ct = append(ct, composer.CourtTypeProbate)
			name = "Davidson County Circuit Court, Division 7 (Probate Division)"
		}
		specs = append(specs, tnTrialCourt(
			fmt.Sprintf("did:web:state:tn:%s:circuit:%d", county, i),
			name, ct, appeals,
		))
	}

	// Chancery Court: parts I-IV (equity only — Davidson's probate is
	// in the Circuit Court's Probate Division above, NOT here).
	for i := 1; i <= 4; i++ {
		specs = append(specs, tnTrialCourt(
			fmt.Sprintf("did:web:state:tn:%s:chancery:%d", county, i),
			fmt.Sprintf("Davidson County Chancery Court, Part %s", roman(i)),
			[]composer.CourtType{composer.CourtTypeChancery},
			appealCivil,
		))
	}

	// Criminal Court: divisions 1-6 (felonies, post-conviction).
	for i := 1; i <= 6; i++ {
		specs = append(specs, tnTrialCourt(
			fmt.Sprintf("did:web:state:tn:%s:criminal:%d", county, i),
			fmt.Sprintf("Davidson County Criminal Court, Division %d", i),
			[]composer.CourtType{composer.CourtTypeCriminal},
			appealCriminal,
		))
	}

	// General Sessions: 4 civil + 7 criminal divisions in Davidson.
	// Model representatively: 4 civil + 4 criminal (the framework
	// extends trivially to all).
	for i := 1; i <= 4; i++ {
		specs = append(specs, tnTrialCourt(
			fmt.Sprintf("did:web:state:tn:%s:gen_sessions_civil:%d", county, i),
			fmt.Sprintf("Davidson County General Sessions, Civil Division %d", i),
			[]composer.CourtType{composer.CourtTypeGeneralSessions},
			appealCivil,
		))
	}
	for i := 1; i <= 4; i++ {
		specs = append(specs, tnTrialCourt(
			fmt.Sprintf("did:web:state:tn:%s:gen_sessions_criminal:%d", county, i),
			fmt.Sprintf("Davidson County General Sessions, Criminal Division %d", i),
			[]composer.CourtType{composer.CourtTypeGeneralSessions, composer.CourtTypeCriminal},
			appealCriminal,
		))
	}

	// Juvenile Court: single court, no division split.
	specs = append(specs, tnTrialCourt(
		"did:web:state:tn:davidson:juvenile",
		"Davidson County Juvenile Court",
		[]composer.CourtType{composer.CourtTypeJuvenile},
		appealCivil,
	))

	return specs
}

// ─── Knox County (Knoxville) ─────────────────────────────────────────
// Knox is smaller than Davidson but still has the full court mix.
// Critical difference from Davidson: Knox Chancery hears PROBATE
// (Knox has no separate Probate Court / Probate Division), so Knox
// Chancery specs include CourtTypeProbate alongside CourtTypeChancery.

func tnKnoxCourts() []composer.Spec {
	const county = "knox"
	const appealCivil = "did:web:state:tn:coa:east"
	const appealCriminal = "did:web:state:tn:coca:east"

	var specs []composer.Spec

	// Circuit Court: divisions 1-4 (law, including civil and select
	// criminal misdemeanor appeals).
	for i := 1; i <= 4; i++ {
		specs = append(specs, tnTrialCourt(
			fmt.Sprintf("did:web:state:tn:%s:circuit:%d", county, i),
			fmt.Sprintf("Knox County Circuit Court, Division %d", i),
			[]composer.CourtType{composer.CourtTypeCircuit},
			appealCivil,
		))
	}

	// Chancery Court: parts I-III. Knox Chancery handles PROBATE
	// (probate, conservatorships, guardianships) — no separate
	// Probate Court here. Each part lists both Chancery and Probate.
	for i := 1; i <= 3; i++ {
		specs = append(specs, tnTrialCourt(
			fmt.Sprintf("did:web:state:tn:%s:chancery:%d", county, i),
			fmt.Sprintf("Knox County Chancery Court, Part %s (hears probate)", roman(i)),
			[]composer.CourtType{composer.CourtTypeChancery, composer.CourtTypeProbate},
			appealCivil,
		))
	}

	// Criminal Court: divisions 1-3 (felonies).
	for i := 1; i <= 3; i++ {
		specs = append(specs, tnTrialCourt(
			fmt.Sprintf("did:web:state:tn:%s:criminal:%d", county, i),
			fmt.Sprintf("Knox County Criminal Court, Division %d", i),
			[]composer.CourtType{composer.CourtTypeCriminal},
			appealCriminal,
		))
	}

	// General Sessions: 4 divisions (mixed civil + criminal under
	// Tennessee's General Sessions design).
	for i := 1; i <= 4; i++ {
		specs = append(specs, tnTrialCourt(
			fmt.Sprintf("did:web:state:tn:%s:gen_sessions:%d", county, i),
			fmt.Sprintf("Knox County General Sessions Court, Division %d", i),
			[]composer.CourtType{composer.CourtTypeGeneralSessions},
			appealCivil,
		))
	}

	// Juvenile Court.
	specs = append(specs, tnTrialCourt(
		"did:web:state:tn:knox:juvenile",
		"Knox County Juvenile Court",
		[]composer.CourtType{composer.CourtTypeJuvenile},
		appealCivil,
	))

	return specs
}

// tnTrialCourt is the helper backing every TN trial-court Spec.
// Threads the TN_BPR credential and the standard trial-tier
// configuration so per-court entries stay one line each.
func tnTrialCourt(did, name string, types []composer.CourtType, appealTo string) composer.Spec {
	return composer.Spec{
		DID:                 did,
		Name:                name,
		Tier:                composer.TierTrial,
		CourtTypes:          types,
		Jurisdiction:        composer.Jurisdiction{State: "TN"},
		RequiredCredentials: []credentials.Credential{attorney.TN_BPR()},
		AppellatePath:       appealTo,
	}
}

// roman returns the Roman numeral for 1-10. Used to render Chancery
// Court parts ("Part I", "Part II", ...).
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
