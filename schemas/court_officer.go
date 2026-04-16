/*
FILE PATH: schemas/court_officer.go
DESCRIPTION: tn-court-officer-v1 delegation payload schema for Layer 3.
KEY ARCHITECTURAL DECISIONS: real_did, no artifact encryption, SDK-D6 opaque.
OVERVIEW: CourtOfficerPayload for delegation/judge.go, clerk.go, deputy.go.
KEY DEPENDENCIES: schemas/registry.go
*/
package schemas

import "encoding/json"

type CourtOfficerPayload struct {
	Role          string `json:"role"`
	Division      string `json:"division"`
	AppointedDate string `json:"appointed_date"`
	ScopeLimit    string `json:"scope_limit,omitempty"`
	Title         string `json:"title,omitempty"`
	BarNumber     string `json:"bar_number,omitempty"`
	OathDate      string `json:"oath_date,omitempty"`
	DelegatedBy   string `json:"delegated_by,omitempty"`
	MaxDepth      int    `json:"max_depth,omitempty"`
}

func DefaultCourtOfficerParams() []byte {
	params := map[string]interface{}{
		"identifier_scope":          "real_did",
		"override_requires_witness": false,
		"migration_policy":          "amendment",
	}
	b, _ := json.Marshal(params)
	return b
}

func SerializeCourtOfficerPayload(p *CourtOfficerPayload) ([]byte, error) { return json.Marshal(p) }

func DeserializeCourtOfficerPayload(data []byte) (*CourtOfficerPayload, error) {
	var p CourtOfficerPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func courtOfficerRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaCourtOfficerV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*CourtOfficerPayload)
			if !ok { return nil, ErrDeserialize }
			return SerializeCourtOfficerPayload(p)
		},
		Deserialize:     func(data []byte) (interface{}, error) { return DeserializeCourtOfficerPayload(data) },
		DefaultParams:   DefaultCourtOfficerParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
