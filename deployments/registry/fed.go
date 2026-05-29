/*
FILE PATH: deployments/registry/fed.go

DESCRIPTION:

	Federal court registry entries — every federal court in scope:

	  SCOTUS                              (1)
	  Courts of Appeals                   (6th Circuit, 9th Circuit)
	  US District Courts                  (M.D. TN, E.D. TN, C.D. CA, N.D. CA)

	# Federal appellate routing

	  TN Davidson (M.D. TN)   → 6th Circuit
	  TN Knox     (E.D. TN)   → 6th Circuit
	  CA Riverside (C.D. CA)  → 9th Circuit
	  CA Santa Clara (N.D. CA) → 9th Circuit
	  Both Circuits           → SCOTUS

	# Federal bar admission is per-court

	Federal admission is granted PER COURT — admission to the M.D.
	TN bar is separate from admission to the E.D. TN bar, both
	separate from the 6th Circuit bar, etc. Each spec lists its
	OWN Fed_BarFor(courtDID) credential; the composer threads the
	right ID through.
*/
package registry

import (
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials/attorney"
)

// FederalSpecs returns every federal court entry in scope. Stable
// order: SCOTUS, Circuits, Districts (alphabetic by district name).
func FederalSpecs() []composer.Spec {
	return []composer.Spec{
		// ─── SCOTUS ────────────────────────────────────────────
		{
			DID:                 "did:web:fed:scotus:us",
			Name:                "Supreme Court of the United States",
			Tier:                composer.TierSupreme,
			CourtTypes:          []composer.CourtType{composer.CourtTypeSupreme},
			Jurisdiction:        composer.Jurisdiction{Federal: true},
			RequiredCredentials: []credentials.Credential{attorney.SCOTUS_Bar()},
		},

		// ─── US Courts of Appeals ──────────────────────────────
		fedCircuit("did:web:fed:circuit:6th",
			"United States Court of Appeals for the Sixth Circuit",
			"did:web:fed:scotus:us"),
		fedCircuit("did:web:fed:circuit:9th",
			"United States Court of Appeals for the Ninth Circuit",
			"did:web:fed:scotus:us"),

		// ─── US District Courts ────────────────────────────────
		fedDistrict("did:web:fed:district:tn_middle",
			"United States District Court for the Middle District of Tennessee",
			"did:web:fed:circuit:6th"),
		fedDistrict("did:web:fed:district:tn_eastern",
			"United States District Court for the Eastern District of Tennessee",
			"did:web:fed:circuit:6th"),
		fedDistrict("did:web:fed:district:ca_central",
			"United States District Court for the Central District of California",
			"did:web:fed:circuit:9th"),
		fedDistrict("did:web:fed:district:ca_northern",
			"United States District Court for the Northern District of California",
			"did:web:fed:circuit:9th"),
	}
}

// fedCircuit is the per-Circuit-Court spec builder.
func fedCircuit(did, name, appealTo string) composer.Spec {
	return composer.Spec{
		DID:                 did,
		Name:                name,
		Tier:                composer.TierIntermediateAppellate,
		CourtTypes:          []composer.CourtType{composer.CourtTypeIntermediateAppellate},
		Jurisdiction:        composer.Jurisdiction{Federal: true},
		RequiredCredentials: []credentials.Credential{attorney.Fed_BarFor(did)},
		AppellatePath:       appealTo,
	}
}

// fedDistrict is the per-District-Court spec builder. Federal District
// Courts have general federal trial jurisdiction (civil + criminal).
func fedDistrict(did, name, appealTo string) composer.Spec {
	return composer.Spec{
		DID:                 did,
		Name:                name,
		Tier:                composer.TierTrial,
		CourtTypes:          []composer.CourtType{composer.CourtTypeDistrict},
		Jurisdiction:        composer.Jurisdiction{Federal: true},
		RequiredCredentials: []credentials.Credential{attorney.Fed_BarFor(did)},
		AppellatePath:       appealTo,
	}
}
