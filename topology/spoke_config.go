/*
FILE PATH: topology/spoke_config.go
DESCRIPTION: Three-log convention: officers, cases, parties. Maps log purpose
    to DID. Consumed by onboarding/provision.go and delegation/.
KEY ARCHITECTURAL DECISIONS: Pure data. No SDK imports.
OVERVIEW: SpokeConfig struct, LogPurpose enum, NewSpokeConfig constructor.
KEY DEPENDENCIES: none
*/
package topology

// LogPurpose identifies one of the three log types in the spoke convention.
type LogPurpose string

const (
	LogOfficers LogPurpose = "officers"
	LogCases    LogPurpose = "cases"
	LogParties  LogPurpose = "parties"
)

// SpokeConfig maps log purpose to DID for a single court deployment.
type SpokeConfig struct {
	CourtDID    string
	OfficersDID string
	CasesDID    string
	PartiesDID  string
	OperatorURL string
	ArtifactURL string
}

// LogDID returns the DID for a given log purpose.
func (s *SpokeConfig) LogDID(purpose LogPurpose) string {
	switch purpose {
	case LogOfficers:
		return s.OfficersDID
	case LogCases:
		return s.CasesDID
	case LogParties:
		return s.PartiesDID
	default:
		return ""
	}
}

// AllLogDIDs returns all three log DIDs.
func (s *SpokeConfig) AllLogDIDs() [3]string {
	return [3]string{s.OfficersDID, s.CasesDID, s.PartiesDID}
}

// NewSpokeConfig creates a spoke configuration. All fields required.
func NewSpokeConfig(courtDID, officersDID, casesDID, partiesDID string) *SpokeConfig {
	return &SpokeConfig{
		CourtDID:    courtDID,
		OfficersDID: officersDID,
		CasesDID:    casesDID,
		PartiesDID:  partiesDID,
	}
}
