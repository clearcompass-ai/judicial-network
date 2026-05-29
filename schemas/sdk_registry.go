// FILE PATH: schemas/sdk_registry.go
//
// DESCRIPTION:
//
//	attesta v0.4.0+ adoption — bridges JN's domain-payload
//	schemas.Registry to the SDK admission-router *schema.Registry.
//	The SDK registry is structural: it owns per-SchemaID
//	EntryValidator + SchemaParameterExtractor bindings the
//	admission router consults BEFORE allowing an entry envelope
//	into the log.
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
// D9 (PR-C tail) — Binding ENRICHMENT.
//
//	Pre-D9, every bind was &sdkschema.Binding{} (empty: no
//	validator, no extractor, no Domain tag, no version range).
//	The SDK admits the empty binding (additive surface contract;
//	HandlesVersion returns true for zero ranges as a back-compat
//	default), but the binding carries no JN-specific information
//	the SDK admission router can act on.
//
//	D9 wires the four fields the SDK exposes on Binding:
//
//	  - Validator     — per-schema closure that deserializes the
//	                    entry's DomainPayload via the domain
//	                    Registry's existing Deserialize. The SDK
//	                    admission router calls it BEFORE allowing
//	                    the entry; a deserialize failure is the
//	                    structural-shape check the JN already
//	                    enforces at read time, hoisted to
//	                    admission time.
//	  - Extractor     — explicit *sdkschema.JSONParameterExtractor
//	                    instead of relying on the SDK registry's
//	                    fallback. Identical behavior; makes the
//	                    binding self-documenting and ready for a
//	                    future per-schema custom extractor.
//	  - Domain        — JNDomain ("judicial-network") for the SDK's
//	                    LookupBySchemaID cross-domain dispatch
//	                    (plan §I.14).
//	  - Min/Max
//	    SchemaProtocolVersion — both = JNSchemaProtocolVersion (1).
//	                    Every JN schema URI in this codebase carries
//	                    a "-v1" suffix; binding the range explicitly
//	                    surfaces the version constraint to the
//	                    cross-domain dispatch + lets a future "-v2"
//	                    lift coexist with v1 under the same SchemaID
//	                    via a second bind.
//
// KEY DEPENDENCIES:
//   - attesta/schema: Registry, Binding, EntryValidator,
//     SchemaID, sentinel errors, NewJSONParameterExtractor.
//   - attesta/core/envelope: Entry (admission-time validation).
package schemas

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/core/envelope"
	sdkschema "github.com/clearcompass-ai/attesta/schema"
)

// JNDomain is the canonical Domain string every JN schema binding
// surfaces to the SDK admission router. SDK LookupBySchemaID
// returns this string so a cross-domain verifier (federated
// recording network, future credentialing-v1, etc.) can resolve
// "which domain owns this schema?" without typing the URI.
const JNDomain = "judicial-network"

// JNSchemaProtocolVersion is the schema-protocol-version every JN
// schema currently binds at. Every URI in this codebase carries a
// "-v1" suffix; the binding's [Min, Max] range pins that
// invariant at the SDK admission boundary so a future "-v2" lift
// can register a SECOND binding at version 2 under the same
// SchemaID without quietly shadowing v1.
const JNSchemaProtocolVersion uint16 = 1

// ErrSDKRegistryBuild wraps every error path SDKRegistry can
// produce. Underlying SDK sentinels (ErrSchemaIDEmpty,
// ErrNilBinding, ErrSchemaIDAlreadyBound) bubble up via
// errors.Is so callers can react to specific failure modes.
var ErrSDKRegistryBuild = errors.New("schemas/sdk_registry: build failed")

// ErrAdmissionValidator wraps every error a JN admission-time
// EntryValidator surfaces. The wrapped error is the
// Deserialize-side failure verbatim so callers can errors.Is
// against schema-specific sentinels (e.g., ErrDeserialize) the
// domain Registry already returns.
var ErrAdmissionValidator = errors.New("schemas/sdk_registry: admission validator")

// SDKRegistry returns a fresh *sdkschema.Registry pre-populated
// with FULLY-WIRED bindings for every JN schema this domain
// Registry knows. The returned Registry is frozen — Bind on it
// will fail with the SDK's ErrRegistryFrozen sentinel.
//
// Each binding carries (D9):
//   - Validator: a closure that calls reg.Deserialize on
//     entry.DomainPayload; a deserialize failure becomes the
//     SDK's structural admission rejection.
//   - Extractor: the shared *sdkschema.JSONParameterExtractor.
//   - Domain: JNDomain.
//   - Min/MaxSchemaProtocolVersion: JNSchemaProtocolVersion (1).
//
// Pre-D9 callers (which were getting empty bindings) get the
// SAME post-D9 result for any entry whose DomainPayload
// deserializes cleanly — the new Validator is a strict superset
// of the empty no-op. Entries with malformed DomainPayload that
// previously slipped through admission (and would have failed
// later at read time) now fail at admission, which is the
// invariant the SDK admission contract assumes.
func (r *Registry) SDKRegistry() (*sdkschema.Registry, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil domain Registry", ErrSDKRegistryBuild)
	}
	sdk := sdkschema.NewRegistry()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for uri, reg := range r.schemas {
		binding := &sdkschema.Binding{
			Validator:                makeSDKValidator(uri, reg.Deserialize),
			Extractor:                r.jsonExt,
			Domain:                   JNDomain,
			MinSchemaProtocolVersion: JNSchemaProtocolVersion,
			MaxSchemaProtocolVersion: JNSchemaProtocolVersion,
		}
		if err := sdk.Bind(sdkschema.SchemaID(uri), binding); err != nil {
			return nil, fmt.Errorf("%w: bind %q: %w", ErrSDKRegistryBuild, uri, err)
		}
	}
	sdk.Freeze()
	return sdk, nil
}

// makeSDKValidator captures the per-schema Deserialize closure and
// returns the sdkschema.EntryValidator the admission router calls.
//
// CONTRACT (Principle 7 — Strict Commit Hot-Path Isolation): the
// returned validator is PURE CPU — it does no I/O, takes no
// locks, and never panics. JN's Deserialize closures are all
// json.Unmarshal-based and satisfy this contract by construction.
//
// A nil deserialize is rejected at build time (every JN
// SchemaRegistration carries a non-nil Deserialize by construction
// in registerAll()); a nil entry is rejected at call time
// (defense-in-depth — the SDK's ValidateEntry already rejects
// nil entries before the validator is invoked).
func makeSDKValidator(uri string, deserialize PayloadDeserializer) sdkschema.EntryValidator {
	return func(entry *envelope.Entry) error {
		if entry == nil {
			return fmt.Errorf("%w: %q: nil entry", ErrAdmissionValidator, uri)
		}
		if _, err := deserialize(entry.DomainPayload); err != nil {
			return fmt.Errorf("%w: %q: %w", ErrAdmissionValidator, uri, err)
		}
		return nil
	}
}

// ValidateAdmission is the convenience wrapper most callers want:
// it runs the admission-time validator for the entry's SchemaRef
// against the supplied SDK Registry.
//
// Per SDK semantics, an unbound SchemaID surfaces
// sdkschema.ErrSchemaIDNotFound and the caller decides whether
// the local policy admits unknown schemas; a bound binding's
// Validator surfaces its error verbatim (post-D9, that's
// ErrAdmissionValidator-wrapped Deserialize failures).
func (r *Registry) ValidateAdmission(sdk *sdkschema.Registry, schemaID string, entry *envelope.Entry) error {
	if sdk == nil {
		return fmt.Errorf("%w: nil *sdkschema.Registry", ErrSDKRegistryBuild)
	}
	if entry == nil {
		return fmt.Errorf("%w: nil entry", ErrSDKRegistryBuild)
	}
	return sdk.ValidateEntry(sdkschema.SchemaID(schemaID), entry)
}
