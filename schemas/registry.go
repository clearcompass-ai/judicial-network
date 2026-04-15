/*
FILE PATH:
    schemas/registry.go

DESCRIPTION:
    Central schema registry for the Tennessee judicial network domain.
    Maps schema URIs to Go serializers/deserializers. Implements the SDK's
    SchemaParameterExtractor interface by delegating to the SDK's JSON
    extractor for all well-known fields.

KEY ARCHITECTURAL DECISIONS:
    - Delegation to SDK JSONParameterExtractor: The SDK owns parsing of
      all well-known fields (artifact_encryption, grant_authorization_mode,
      etc.). The judicial network never reimplements extraction logic.
    - Thread-safe Registry: sync.RWMutex protects concurrent reads/writes.
      Schemas are registered at init, read on every entry path.
    - Shared types here: ThresholdConfig, DisclosureScopeType, IdentifierScope
      live in registry.go because they are consumed by multiple schema files.

OVERVIEW:
    NewRegistry() → pre-populates 6 schemas (criminal, civil, family,
    juvenile, evidence, disclosure_order). Each schema provides
    Serialize/Deserialize, DefaultParams, and IdentifierScope. The
    Registry.Extract() method delegates to the SDK for SchemaParameters
    extraction from any schema entry's Domain Payload.

KEY DEPENDENCIES:
    - ortholog-sdk/schema: JSONParameterExtractor for well-known field parsing
    - ortholog-sdk/core/envelope: Entry type for Extract() signature
    - ortholog-sdk/types: SchemaParameters return type
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

// -------------------------------------------------------------------------------------------------
// 1) Shared types used across schemas
// -------------------------------------------------------------------------------------------------

// ThresholdConfig specifies M-of-N parameters for re-encryption threshold.
type ThresholdConfig struct {
	M int `json:"m"`
	N int `json:"n"`
}

// SchemaPosition references a schema entry on a log.
type SchemaPosition struct {
	LogDID   string `json:"log_did"`
	Sequence uint64 `json:"sequence"`
}

// IdentifierScope declares whether entries use real or vendor-specific DIDs.
type IdentifierScope string

const (
	IdentifierScopeRealDID        IdentifierScope = "real_did"
	IdentifierScopeVendorSpecific IdentifierScope = "vendor_specific"
)

// DisclosureScopeType controls who may receive access grants for an artifact.
type DisclosureScopeType string

const (
	DisclosureUnrestricted    DisclosureScopeType = "unrestricted"
	DisclosureProsecutionOnly DisclosureScopeType = "prosecution_only"
	DisclosureDefenseOnly     DisclosureScopeType = "defense_only"
	DisclosureCourtOnly       DisclosureScopeType = "court_only"
	DisclosureByOrder         DisclosureScopeType = "by_order"
)

// -------------------------------------------------------------------------------------------------
// 2) Schema URI constants
// -------------------------------------------------------------------------------------------------

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
	SchemaAppellateDecisionV1  = "tn-appellate-decision-v1"
)

// -------------------------------------------------------------------------------------------------
// 3) Errors
// -------------------------------------------------------------------------------------------------

var (
	ErrSchemaNotRegistered = errors.New("schemas/registry: schema URI not registered")
	ErrDeserialize         = errors.New("schemas/registry: deserialization failed")
)

// -------------------------------------------------------------------------------------------------
// 4) Serializer / Deserializer interfaces
// -------------------------------------------------------------------------------------------------

// PayloadSerializer converts a typed payload struct to Domain Payload bytes.
type PayloadSerializer func(payload interface{}) ([]byte, error)

// PayloadDeserializer converts Domain Payload bytes to a typed struct.
type PayloadDeserializer func(data []byte) (interface{}, error)

// SchemaRegistration holds serializer/deserializer pair for a schema URI.
type SchemaRegistration struct {
	URI             string
	Serialize       PayloadSerializer
	Deserialize     PayloadDeserializer
	DefaultParams   func() []byte
	IdentifierScope IdentifierScope
}

// -------------------------------------------------------------------------------------------------
// 5) Registry
// -------------------------------------------------------------------------------------------------

// Registry maps schema URIs to their registrations. Thread-safe.
type Registry struct {
	mu      sync.RWMutex
	schemas map[string]*SchemaRegistration
	jsonExt *sdkschema.JSONParameterExtractor
}

// NewRegistry creates a registry pre-populated with all Tennessee judicial schemas.
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
}

// Register adds or replaces a schema registration.
func (r *Registry) Register(reg *SchemaRegistration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.schemas[reg.URI] = reg
}

// Lookup returns the registration for a schema URI.
func (r *Registry) Lookup(uri string) (*SchemaRegistration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.schemas[uri]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSchemaNotRegistered, uri)
	}
	return reg, nil
}

// Has returns true if the schema URI is registered.
func (r *Registry) Has(uri string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.schemas[uri]
	return ok
}

// URIs returns all registered schema URIs.
func (r *Registry) URIs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	uris := make([]string, 0, len(r.schemas))
	for uri := range r.schemas {
		uris = append(uris, uri)
	}
	return uris
}

// SerializePayload serializes a payload using the registered serializer.
func (r *Registry) SerializePayload(uri string, payload interface{}) ([]byte, error) {
	reg, err := r.Lookup(uri)
	if err != nil {
		return nil, err
	}
	return reg.Serialize(payload)
}

// DeserializePayload deserializes Domain Payload bytes.
func (r *Registry) DeserializePayload(uri string, data []byte) (interface{}, error) {
	reg, err := r.Lookup(uri)
	if err != nil {
		return nil, err
	}
	return reg.Deserialize(data)
}

// -------------------------------------------------------------------------------------------------
// 6) SchemaParameterExtractor implementation
// -------------------------------------------------------------------------------------------------

// Extract implements schema.SchemaParameterExtractor by delegating to the SDK's
// JSON parameter extractor. Reads all well-known fields:
//
//	activation_delay, cosignature_threshold, maturation_epoch,
//	credential_validity_period, override_requires_witness, migration_policy,
//	predecessor_schema, artifact_encryption, grant_entry_required,
//	re_encryption_threshold, grant_authorization_mode, grant_requires_audit_entry
//
// Judicial-specific fields (docket_number, charges, disclosure_scope, etc.)
// are silently ignored by the SDK extractor.
func (r *Registry) Extract(schemaEntry *envelope.Entry) (*types.SchemaParameters, error) {
	return r.jsonExt.Extract(schemaEntry)
}

// -------------------------------------------------------------------------------------------------
// 7) Generic JSON serializer helper
// -------------------------------------------------------------------------------------------------

func jsonSerializer(payload interface{}) ([]byte, error) {
	return json.Marshal(payload)
}
