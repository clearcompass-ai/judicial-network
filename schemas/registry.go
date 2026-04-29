/*
FILE PATH: schemas/registry.go
DESCRIPTION: Central schema registry — 15 schemas (12 case/officer + 3 delegation).
KEY ARCHITECTURAL DECISIONS: Thread-safe. SDK JSONParameterExtractor.
OVERVIEW: NewRegistry() → 15 schemas. Appellate decisions use existing case
          schemas. judicial-delegation-v1, judicial-revocation-v1, and
          judicial-succession-v1 are the canonical authority-grant entries.
KEY DEPENDENCIES: ortholog-sdk/schema, ortholog-sdk/core/envelope, ortholog-sdk/types
*/
package schemas

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdkschema "github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

type ThresholdConfig struct {
	M int `json:"m"`
	N int `json:"n"`
}
type SchemaPosition struct {
	LogDID   string `json:"log_did"`
	Sequence uint64 `json:"sequence"`
}
type IdentifierScope string

const (
	IdentifierScopeRealDID        IdentifierScope = "real_did"
	IdentifierScopeVendorSpecific IdentifierScope = "vendor_specific"
)

type DisclosureScopeType string

const (
	DisclosureUnrestricted    DisclosureScopeType = "unrestricted"
	DisclosureProsecutionOnly DisclosureScopeType = "prosecution_only"
	DisclosureDefenseOnly     DisclosureScopeType = "defense_only"
	DisclosureCourtOnly       DisclosureScopeType = "court_only"
	DisclosureByOrder         DisclosureScopeType = "by_order"
)

const (
	SchemaCriminalCaseV1       = "tn-criminal-case-v1"
	SchemaCivilCaseV1          = "tn-civil-case-v1"
	SchemaFamilyCaseV1         = "tn-family-case-v1"
	SchemaJuvenileCaseV1       = "tn-juvenile-case-v1"
	SchemaEvidenceArtifactV1   = "tn-evidence-artifact-v1"
	SchemaDisclosureOrderV1    = "tn-disclosure-order-v1"
	SchemaCourtOfficerV1       = "tn-court-officer-v1"
	SchemaPartyBindingV1       = "tn-party-binding-v1"
	SchemaPartyBindingSealedV1 = "tn-party-binding-sealed-v1"
	SchemaSealingOrderV1       = "tn-sealing-order-v1"
	// SchemaKeyAttestationV1 is declared in schemas/key_attestation.go.
)

var (
	ErrSchemaNotRegistered = errors.New("schemas/registry: schema URI not registered")
	ErrDeserialize         = errors.New("schemas/registry: deserialization failed")
)

type PayloadSerializer func(payload interface{}) ([]byte, error)
type PayloadDeserializer func(data []byte) (interface{}, error)

type SchemaRegistration struct {
	URI             string
	Serialize       PayloadSerializer
	Deserialize     PayloadDeserializer
	DefaultParams   func() []byte
	IdentifierScope IdentifierScope
}

type Registry struct {
	mu      sync.RWMutex
	schemas map[string]*SchemaRegistration
	jsonExt *sdkschema.JSONParameterExtractor
}

func NewRegistry() *Registry {
	r := &Registry{
		schemas: make(map[string]*SchemaRegistration),
		jsonExt: sdkschema.NewJSONParameterExtractor(),
	}
	r.registerAll()
	return r
}

func (r *Registry) registerAll() {
	r.Register(criminalCaseRegistration())
	r.Register(civilCaseRegistration())
	r.Register(familyCaseRegistration())
	r.Register(juvenileCaseRegistration())
	r.Register(evidenceArtifactRegistration())
	r.Register(disclosureOrderRegistration())
	r.Register(courtOfficerRegistration())
	r.Register(shardGenesisRegistration())
	r.Register(partyBindingRegistration())
	r.Register(partyBindingSealedRegistration())
	r.Register(sealingOrderRegistration())
	r.Register(keyAttestationRegistration())
	r.Register(judicialDelegationRegistration())
	r.Register(judicialRevocationRegistration())
	r.Register(judicialSuccessionRegistration())
}

func (r *Registry) Register(reg *SchemaRegistration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.schemas[reg.URI] = reg
}

func (r *Registry) Lookup(uri string) (*SchemaRegistration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.schemas[uri]
	if !ok { return nil, fmt.Errorf("%w: %s", ErrSchemaNotRegistered, uri) }
	return reg, nil
}

func (r *Registry) Has(uri string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.schemas[uri]
	return ok
}

func (r *Registry) URIs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	uris := make([]string, 0, len(r.schemas))
	for uri := range r.schemas { uris = append(uris, uri) }
	return uris
}

func (r *Registry) SerializePayload(uri string, payload interface{}) ([]byte, error) {
	reg, err := r.Lookup(uri)
	if err != nil { return nil, err }
	return reg.Serialize(payload)
}

func (r *Registry) DeserializePayload(uri string, data []byte) (interface{}, error) {
	reg, err := r.Lookup(uri)
	if err != nil { return nil, err }
	return reg.Deserialize(data)
}

func (r *Registry) Extract(schemaEntry *envelope.Entry) (*types.SchemaParameters, error) {
	return r.jsonExt.Extract(schemaEntry)
}

func jsonSerializer(payload interface{}) ([]byte, error) { return json.Marshal(payload) }
