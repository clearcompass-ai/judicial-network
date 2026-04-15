/*
FILE PATH:
    schemas/disclosure_order.go

DESCRIPTION:
    Defines tn-disclosure-order-v1 — a Path C enforcement entry signed by a
    judge that names specific recipients authorized to access specific artifacts.
    This is the judicial selective disclosure mechanism.

KEY ARCHITECTURAL DECISIONS:
    - Path C enforcement entry: requires signer in scope authority set (judge).
    - per_artifact vs case_wide scope: per_artifact names specific CIDs;
      case_wide authorizes recipients for ALL artifacts in the case.
    - retrieve.go scans the authority chain for these entries and merges
      authorized recipients from all matching orders.
    - The SDK never reads these payloads (SDK-D6). The judicial network
      extracts recipients; the SDK checks membership.

OVERVIEW:
    DisclosureOrderPayload carries order_type ("disclosure"|"revoke_disclosure"),
    scope ("per_artifact"|"case_wide"), authorized_recipients, authorized_artifact_cids.
    Helper functions: ExtractDisclosureRecipients, ExtractDisclosureArtifactCIDs,
    DisclosureOrderAppliesToArtifact — called by retrieve.go during authority
    chain scanning.

KEY DEPENDENCIES:
    - schemas/registry.go: SchemaRegistration type, ErrDeserialize sentinel
*/
package schemas

import "encoding/json"

// -------------------------------------------------------------------------------------------------
// 1) Disclosure order Domain Payload
// -------------------------------------------------------------------------------------------------

// DisclosureOrderPayload is the Domain Payload for entries governed
// by tn-disclosure-order-v1. Published as Path C enforcement entries.
type DisclosureOrderPayload struct {
	// ── SDK well-known fields ────────────────────────────────────────
	ActivationDelay int64  `json:"activation_delay,omitempty"`
	MigrationPolicy string `json:"migration_policy,omitempty"`

	// ── Order metadata ───────────────────────────────────────────────
	OrderType         string `json:"order_type"`
	Scope             string `json:"scope"`
	AuthorityCitation string `json:"authority_citation,omitempty"`
	EffectiveDate     string `json:"effective_date,omitempty"`
	ExpiryDate        string `json:"expiry_date,omitempty"`

	// ── Recipients ───────────────────────────────────────────────────
	AuthorizedRecipients []string `json:"authorized_recipients"`

	// ── Artifact scope ───────────────────────────────────────────────
	AuthorizedArtifactCIDs []string `json:"authorized_artifact_cids,omitempty"`

	// ── Conditions ───────────────────────────────────────────────────
	Conditions string `json:"conditions,omitempty"`
}

// -------------------------------------------------------------------------------------------------
// 2) Schema entry defaults
// -------------------------------------------------------------------------------------------------

func DefaultDisclosureOrderParams() []byte {
	params := map[string]interface{}{
		"activation_delay": 0,
		"migration_policy": "amendment",
	}
	b, _ := json.Marshal(params)
	return b
}

// -------------------------------------------------------------------------------------------------
// 3) Serialization
// -------------------------------------------------------------------------------------------------

func SerializeDisclosureOrderPayload(p *DisclosureOrderPayload) ([]byte, error) {
	return json.Marshal(p)
}

func DeserializeDisclosureOrderPayload(data []byte) (*DisclosureOrderPayload, error) {
	var p DisclosureOrderPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Payload extraction helpers (called by retrieve.go)
// -------------------------------------------------------------------------------------------------

// ExtractDisclosureRecipients reads the authorized_recipients from a
// disclosure order's Domain Payload. Returns nil if the payload is not
// a valid disclosure order.
func ExtractDisclosureRecipients(domainPayload []byte) ([]string, error) {
	var raw struct {
		OrderType            string   `json:"order_type"`
		AuthorizedRecipients []string `json:"authorized_recipients"`
	}
	if err := json.Unmarshal(domainPayload, &raw); err != nil {
		return nil, err
	}
	if raw.OrderType != "disclosure" {
		return nil, nil
	}
	return raw.AuthorizedRecipients, nil
}

// ExtractDisclosureArtifactCIDs reads the authorized_artifact_cids from
// a disclosure order. Returns nil for case_wide orders.
func ExtractDisclosureArtifactCIDs(domainPayload []byte) ([]string, error) {
	var raw struct {
		Scope                  string   `json:"scope"`
		AuthorizedArtifactCIDs []string `json:"authorized_artifact_cids"`
	}
	if err := json.Unmarshal(domainPayload, &raw); err != nil {
		return nil, err
	}
	if raw.Scope == "case_wide" {
		return nil, nil
	}
	return raw.AuthorizedArtifactCIDs, nil
}

// DisclosureOrderAppliesToArtifact checks whether a disclosure order
// authorizes access to a specific artifact CID.
func DisclosureOrderAppliesToArtifact(domainPayload []byte, artifactCID string) bool {
	cids, err := ExtractDisclosureArtifactCIDs(domainPayload)
	if err != nil {
		return false
	}
	if cids == nil {
		return true
	}
	for _, cid := range cids {
		if cid == artifactCID {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------------------------------------------
// 5) Registry registration
// -------------------------------------------------------------------------------------------------

func disclosureOrderRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaDisclosureOrderV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*DisclosureOrderPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeDisclosureOrderPayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return DeserializeDisclosureOrderPayload(data)
		},
		DefaultParams:   DefaultDisclosureOrderParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
