/*
FILE PATH: schemas/sealing_order.go
DESCRIPTION: tn-sealing-order-v1. Path C enforcement schema for sealing/unsealing.
KEY ARCHITECTURAL DECISIONS:
    - Different SchemaParameters from case schemas: activation_delay=72h,
      cosignature_threshold=0 for sealing, 1 for unsealing.
    - No artifact encryption (enforcement entries carry no artifacts).
    - Juvenile auto-seal: activation_delay=0 per TCA 37-1-153.
OVERVIEW: SealingOrderPayload with order_type, authority, affected_artifacts.
KEY DEPENDENCIES: schemas/registry.go
*/
package schemas

import "encoding/json"

type SealingOrderPayload struct {
	ActivationDelay      int64  `json:"activation_delay,omitempty"`
	CosignatureThreshold int    `json:"cosignature_threshold,omitempty"`
	MigrationPolicy      string `json:"migration_policy,omitempty"`

	OrderType         string   `json:"order_type"`
	Authority         string   `json:"authority,omitempty"`
	CaseRef           string   `json:"case_ref,omitempty"`
	Reason            string   `json:"reason,omitempty"`
	AffectedArtifacts []string `json:"affected_artifacts,omitempty"`
}

func DefaultSealingOrderParams() []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"activation_delay":      259200,
		"cosignature_threshold": 0,
		"migration_policy":      "amendment",
	})
	return b
}

func SerializeSealingOrderPayload(p *SealingOrderPayload) ([]byte, error) { return json.Marshal(p) }

func DeserializeSealingOrderPayload(data []byte) (*SealingOrderPayload, error) {
	var p SealingOrderPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func sealingOrderRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaSealingOrderV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*SealingOrderPayload)
			if !ok { return nil, ErrDeserialize }
			return SerializeSealingOrderPayload(p)
		},
		Deserialize:     func(data []byte) (interface{}, error) { return DeserializeSealingOrderPayload(data) },
		DefaultParams:   DefaultSealingOrderParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
