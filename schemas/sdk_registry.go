// FILE PATH: schemas/sdk_registry.go
//
// DESCRIPTION:
//
//	attesta v0.4.0 adoption — bridges JN's domain-payload
//	schemas.Registry to the new SDK admission-router
//	*schema.Registry (added in v0.4.0). The SDK registry's job
//	is structural: it owns per-SchemaID EntryValidator and per-
//	SchemaID SchemaParameterExtractor bindings the admission
//	router consults BEFORE allowing an entry envelope into the
//	log.
//
//	JN's existing schemas.Registry is the DOMAIN-LAYER registry
//	(payload serialize / deserialize, IdentifierScope, default
//	parameter bytes). The SDK registry is the ADMISSION-LAYER
//	registry. They are complementary, not redundant. This file
//	exposes the SDK registry as a JN-curated artifact so:
//
//	  1. The Phase 7 interface-driven router can consult
//	     *schema.Registry.ValidateEntry() before dispatching a
//	     finding's interface Verify method.
//	  2. The Ledger's admission handler (which already knows
//	     *schema.Registry from v0.4.0) admits JN entries with
//	     domain-aware structural checks — Ledger Principle 12
//	     (Schema-Aware Extractor Inversion / IoC).
//	  3. Tests of the admission contract use a single bound
//	     registry rather than re-deriving validators per case.
//
//	Adoption is purely additive: existing callers of
//	schemas.NewRegistry() see no change; new callers reach
//	schemas.SDKRegistry() to consume the SDK admission
//	contract.
//
// KEY DEPENDENCIES:
//   - attesta/schema: Registry, Binding, EntryValidator,
//     SchemaID, sentinel errors, WithDefaultExtractor.
//   - attesta/core/envelope: Entry (admission-time validation).
package schemas

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/core/envelope"
	sdkschema "github.com/clearcompass-ai/attesta/schema"
)

// ErrSDKRegistryBuild wraps every error path SDKRegistry can
// produce. Underlying SDK sentinels (ErrSchemaIDEmpty,
// ErrNilBinding, ErrSchemaIDAlreadyBound) bubble up via
// errors.Is so callers can react to specific failure modes.
var ErrSDKRegistryBuild = errors.New("schemas/sdk_registry: build failed")

// SDKRegistry returns a fresh *sdkschema.Registry pre-populated
// with bindings for every JN schema this domain Registry knows.
// The returned Registry is frozen — Bind on it will fail with
// the SDK's ErrRegistryFrozen sentinel. Tests + admission
// handlers consume it via the SDK's ValidateEntry +
// ExtractParameters API.
//
// The bridge intentionally uses ONLY a default JSON extractor
// (sdkschema.NewJSONParameterExtractor) and NO per-schema
// validators. The JN schemas' Domain Payload checks live in
// each schema's Deserialize function (kept on the domain
// Registry); a future tightening migrates those checks into
// per-schema EntryValidator closures here. We don't do that in
// the v0.4.0 adoption to keep the change purely additive and
// the migration path observable.
func (r *Registry) SDKRegistry() (*sdkschema.Registry, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil domain Registry", ErrSDKRegistryBuild)
	}
	sdk := sdkschema.NewRegistry()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for uri := range r.schemas {
		if err := sdk.Bind(sdkschema.SchemaID(uri), &sdkschema.Binding{}); err != nil {
			return nil, fmt.Errorf("%w: bind %q: %w", ErrSDKRegistryBuild, uri, err)
		}
	}
	sdk.Freeze()
	return sdk, nil
}

// ValidateAdmission is the convenience wrapper most callers
// want: it constructs (or reuses) an SDK Registry, then runs
// the admission-time validator for the entry's SchemaRef.
//
// Per SDK semantics, an unbound SchemaID surfaces
// sdkschema.ErrSchemaIDNotFound and the caller decides whether
// the local policy admits unknown schemas; a bound binding with
// a nil Validator passes admission unconditionally (we register
// nil validators today — domain-level deserialization in the JN
// Registry remains the structural check).
func (r *Registry) ValidateAdmission(sdk *sdkschema.Registry, schemaID string, entry *envelope.Entry) error {
	if sdk == nil {
		return fmt.Errorf("%w: nil *sdkschema.Registry", ErrSDKRegistryBuild)
	}
	if entry == nil {
		return fmt.Errorf("%w: nil entry", ErrSDKRegistryBuild)
	}
	return sdk.ValidateEntry(sdkschema.SchemaID(schemaID), entry)
}
