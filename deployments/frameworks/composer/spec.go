/*
FILE PATH: deployments/frameworks/composer/spec.go

DESCRIPTION:

	Spec — the declarative recipe a court bundle reduces to. The
	registry/ package owns lists of Specs (one per court / division);
	composer.Build(Spec) produces a jurisdiction.Bundle.

	A Spec describes WHAT a court IS, never HOW the framework realizes
	it. Adding a new state's courts means adding registry entries
	(data); the framework code stays untouched.

	# Tier vs CourtType

	  Tier         — vertical position (trial / intermediate appellate
	                 / supreme). Picks the base policy framework.
	  CourtType    — subject-matter capability the court exercises.
	                 Orthogonal to Tier; a trial court can be
	                 single-subject (Davidson Circuit only hears law
	                 matters), multi-subject (Knox Chancery hears
	                 equity + probate), or unified (CA Superior hears
	                 everything). An appellate court CourtType is
	                 typically IntermediateAppellate; a supreme court
	                 is Supreme.

	# Divisions

	A court with internal divisions (TN Davidson Circuit has 8) is
	modeled as one Spec PER DIVISION; each carries its own DID. The
	Division field is the human-readable label ("Division 7") and is
	embedded into the DID by the registry generators
	(did:web:state:tn:davidson:circuit:7). This makes per-division
	policy variation possible without rewriting the framework.
*/
package composer

import (
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
)

// Tier is the vertical position of a court in its jurisdiction's
// hierarchy. Picks which base framework (trial_base / appellate_base
// / supreme_base) the composer wraps.
type Tier int

const (
	// TierTrial — general-jurisdiction trial courts (TN Circuit /
	// Chancery / Criminal / GS / Juvenile / Probate; CA Superior;
	// federal District). They hear cases at first instance and
	// enter judgments.
	TierTrial Tier = iota

	// TierIntermediateAppellate — first-tier appellate courts (TN
	// COA + COCA; CA Court of Appeal; federal Circuit). They review
	// trial-court judgments; their cosignature mix and prerequisite
	// vocabulary differ from trial courts.
	TierIntermediateAppellate

	// TierSupreme — apex courts (TN Supreme Court; CA Supreme Court;
	// SCOTUS). They review intermediate-appellate judgments; some
	// also hear cases at first instance under specific
	// jurisdictional grants (original jurisdiction).
	TierSupreme
)

func (t Tier) String() string {
	switch t {
	case TierTrial:
		return "trial"
	case TierIntermediateAppellate:
		return "intermediate_appellate"
	case TierSupreme:
		return "supreme"
	default:
		return "unknown"
	}
}

// CourtType is a subject-matter capability the court exercises. A
// Spec.CourtTypes is the LIST of capabilities; a court with multiple
// capabilities (Knox Chancery hearing equity + probate) lists each.
// A "unified" court (CA Superior, federal District) lists CourtTypeUnified
// which the composer expands to "all subject matters".
type CourtType int

const (
	// CourtTypeCircuit — TN Circuit Court (civil law, some criminal).
	CourtTypeCircuit CourtType = iota

	// CourtTypeChancery — TN Chancery Court (equity).
	CourtTypeChancery

	// CourtTypeProbate — probate jurisdiction. May be a separate court
	// (Davidson) or a capability of another court (Knox Chancery).
	CourtTypeProbate

	// CourtTypeCriminal — separately-organized Criminal Court (TN
	// Davidson, Knox, Shelby). Distinct from a circuit court's
	// criminal docket.
	CourtTypeCriminal

	// CourtTypeGeneralSessions — TN General Sessions (limited
	// jurisdiction: small claims, misdemeanors, preliminary hearings).
	CourtTypeGeneralSessions

	// CourtTypeJuvenile — juvenile delinquency, dependency, and
	// neglect matters.
	CourtTypeJuvenile

	// CourtTypeUnifiedSuperior — CA-style unified trial court that
	// hears every subject matter in one organizational court. Composer
	// expands this to Circuit | Chancery | Probate | Criminal |
	// GeneralSessions | Juvenile rules.
	CourtTypeUnifiedSuperior

	// CourtTypeDistrict — federal trial court. Like UnifiedSuperior
	// in scope (general federal jurisdiction over civil and criminal)
	// but with federal-specific rule overlays (Federal Rules of Civil
	// / Criminal / Evidence).
	CourtTypeDistrict

	// CourtTypeIntermediateAppellate — TN COA + COCA, CA Court of
	// Appeal, federal Circuit. Distinct from a supreme court by
	// rules that allow discretionary review by a higher court.
	CourtTypeIntermediateAppellate

	// CourtTypeSupreme — apex court module. SCOTUS, TN SC, CA SC.
	CourtTypeSupreme
)

func (c CourtType) String() string {
	switch c {
	case CourtTypeCircuit:
		return "circuit"
	case CourtTypeChancery:
		return "chancery"
	case CourtTypeProbate:
		return "probate"
	case CourtTypeCriminal:
		return "criminal"
	case CourtTypeGeneralSessions:
		return "general_sessions"
	case CourtTypeJuvenile:
		return "juvenile"
	case CourtTypeUnifiedSuperior:
		return "unified_superior"
	case CourtTypeDistrict:
		return "district"
	case CourtTypeIntermediateAppellate:
		return "intermediate_appellate"
	case CourtTypeSupreme:
		return "supreme"
	default:
		return "unknown"
	}
}

// Jurisdiction scopes a court politically. Composer uses this to
// reject a credential whose jurisdiction doesn't match the court's.
type Jurisdiction struct {
	// State is the two-letter postal code ("TN", "CA"). Empty for
	// federal courts.
	State string

	// Federal is true for federal courts. Mutually exclusive with State.
	Federal bool

	// County, for trial-court entries that scope to a single county
	// (most TN + CA trial courts). Empty for state-wide or federal
	// courts.
	County string
}

// Spec is the declarative description of a single court (or court
// division). The composer reduces a Spec to a jurisdiction.Bundle at
// boot time; the registry/ package is a slice of these.
type Spec struct {
	// DID is the canonical institutional identifier. MUST be unique
	// across the entire registry; the composer's Build refuses
	// duplicates.
	DID string

	// Name is human-readable. Surfaced in audit trails and admission
	// errors. Example: "Davidson County Circuit Court, Division 7
	// (Probate Division)".
	Name string

	// Tier picks the base framework (trial / appellate / supreme).
	Tier Tier

	// CourtTypes are the subject-matter capabilities the court
	// exercises. ORDER does not matter; composer aggregates rules.
	// Empty is invalid — Build rejects.
	CourtTypes []CourtType

	// Jurisdiction scopes the court. Composer uses this to validate
	// every entry in RequiredCredentials.
	Jurisdiction Jurisdiction

	// Division is the optional human-readable division label
	// ("Division 7", "Part III"). Empty for non-divided courts. Used
	// only for the Name field formatting and audit-trail clarity;
	// the DID already carries divisional uniqueness.
	Division string

	// RequiredCredentials are credentials EVERY attorney filing in
	// this court MUST present. The composer threads each credential's
	// ID into the cosignature mix rules that demand it.
	//
	// Example: Davidson Circuit requires credentials.TN_BPR();
	// Riverside Superior requires credentials.CA_Bar(); 6th Circuit
	// requires credentials.SCOTUS_Bar (NB: federal court bar
	// admissions are per-court — see attorney.Fed_BarFor).
	RequiredCredentials []credentials.Credential

	// ConditionalCredentials map event_type → required credential(s).
	// Used for credentials demanded only on specific filings (expert
	// witness testimony, interpreted testimony). Empty map is the
	// common case.
	ConditionalCredentials map[string][]credentials.Credential

	// AppellatePath is the DID of the court that hears appeals from
	// this one. Empty for supreme courts. Used by the cross-reference
	// validation pass in the verification layer.
	AppellatePath string
}

// IsValid reports whether the Spec is internally consistent. The
// composer calls this before Build; misconfigured Specs surface at
// process start, not at first request.
func (s Spec) IsValid() error {
	if s.DID == "" {
		return &SpecError{Field: "DID", Reason: "must be non-empty"}
	}
	if s.Name == "" {
		return &SpecError{Field: "Name", Reason: "must be non-empty"}
	}
	if len(s.CourtTypes) == 0 {
		return &SpecError{Field: "CourtTypes", Reason: "must have at least one entry"}
	}
	if s.Jurisdiction.Federal && s.Jurisdiction.State != "" {
		return &SpecError{Field: "Jurisdiction", Reason: "Federal=true is mutually exclusive with State"}
	}
	if !s.Jurisdiction.Federal && s.Jurisdiction.State == "" {
		return &SpecError{Field: "Jurisdiction", Reason: "non-federal courts require State"}
	}
	courtJ := credentials.Jurisdiction{
		State:   s.Jurisdiction.State,
		Federal: s.Jurisdiction.Federal,
	}
	for _, c := range s.RequiredCredentials {
		if err := credentials.CheckAcceptable(c, courtJ); err != nil {
			return err
		}
	}
	for evt, creds := range s.ConditionalCredentials {
		for _, c := range creds {
			if err := credentials.CheckAcceptable(c, courtJ); err != nil {
				return &SpecError{
					Field:  "ConditionalCredentials[" + evt + "]",
					Reason: err.Error(),
				}
			}
		}
	}
	return nil
}

// SpecError is returned by Spec validation. Fail-loud at boot.
type SpecError struct {
	Field  string
	Reason string
}

func (e *SpecError) Error() string { return "spec." + e.Field + ": " + e.Reason }
