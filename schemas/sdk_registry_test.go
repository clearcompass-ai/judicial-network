// FILE PATH: schemas/sdk_registry_test.go
//
// Tests for the SDKRegistry bridge.
//
// Pre-D9 coverage (preserved):
//
//  1. SDKRegistry on a nil receiver returns ErrSDKRegistryBuild.
//  2. SDKRegistry returns a non-nil, frozen *sdkschema.Registry
//     populated with every JN schema URI.
//  3. The returned Registry has IsFrozen() == true (admission
//     wiring is order-independent — no late binds).
//  4. ValidateAdmission on a nil sdk / nil entry / unbound
//     SchemaID returns the expected sentinels.
//
// D9 coverage (new):
//
//  5. Every bound Binding carries the four enriched fields:
//     non-nil Validator, non-nil Extractor (the shared JSON
//     extractor), Domain=JNDomain, MinSchemaProtocolVersion=
//     MaxSchemaProtocolVersion=1.
//  6. The Validator accepts an entry whose DomainPayload
//     deserializes cleanly under the schema's domain-Registry
//     Deserialize closure.
//  7. The Validator rejects an entry with a malformed
//     DomainPayload, surfacing ErrAdmissionValidator.
//  8. The Validator rejects an empty / zero-valued Entry — the
//     pre-D9 "bound nil-validator admits any entry" path is
//     replaced by "bound enriched validator runs Deserialize."
//  9. LookupBySchemaID surfaces the Domain string verbatim
//     (cross-domain dispatch contract — plan §I.14).
//  10. HandlesVersion accepts v=1 (the JN binding range) and
//      rejects v=2 / v=0 (out-of-range), pinning the explicit
//      version-gating that the empty pre-D9 binding got via
//      back-compat "Min=0 Max=0 = any" semantics.
package schemas

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	sdkschema "github.com/clearcompass-ai/attesta/schema"
)

func TestSDKRegistry_NilReceiver(t *testing.T) {
	var r *Registry
	_, err := r.SDKRegistry()
	if !errors.Is(err, ErrSDKRegistryBuild) {
		t.Fatalf("want ErrSDKRegistryBuild, got %v", err)
	}
}

func TestSDKRegistry_PopulatedAndFrozen(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	if sdk == nil {
		t.Fatal("SDKRegistry returned nil")
	}
	if !sdk.IsFrozen() {
		t.Fatal("returned Registry must be frozen (admission wiring is order-independent)")
	}
	for _, uri := range r.URIs() {
		if !sdk.Has(sdkschema.SchemaID(uri)) {
			t.Errorf("SDK Registry missing binding for %q", uri)
		}
	}
}

func TestSDKRegistry_Frozen_BindRejected(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	err = sdk.Bind(sdkschema.SchemaID("late-comer-v1"), &sdkschema.Binding{})
	if err == nil {
		t.Fatal("Bind after Freeze should fail")
	}
}

func TestValidateAdmission_NilSDKRegistry(t *testing.T) {
	r := NewRegistry()
	err := r.ValidateAdmission(nil, "tn-criminal-case-v1", &envelope.Entry{})
	if !errors.Is(err, ErrSDKRegistryBuild) {
		t.Fatalf("want ErrSDKRegistryBuild, got %v", err)
	}
}

func TestValidateAdmission_NilEntry(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	err = r.ValidateAdmission(sdk, "tn-criminal-case-v1", nil)
	if !errors.Is(err, ErrSDKRegistryBuild) {
		t.Fatalf("want ErrSDKRegistryBuild, got %v", err)
	}
}

func TestValidateAdmission_UnboundSchemaID(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	err = r.ValidateAdmission(sdk, "definitely-not-a-real-schema-v9", &envelope.Entry{})
	if !errors.Is(err, sdkschema.ErrSchemaIDNotFound) {
		t.Fatalf("want ErrSchemaIDNotFound, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// D9 — Binding enrichment
// ─────────────────────────────────────────────────────────────────

// TestSDKRegistry_BindingFieldsPopulated pins that every bound
// Binding carries the four enriched fields. The pre-D9 empty
// binding (Validator=nil, Extractor=nil, Domain="", versions=0)
// is replaced by the JN-curated quartet.
func TestSDKRegistry_BindingFieldsPopulated(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	for _, uri := range r.URIs() {
		b, domain, ok := sdk.LookupBySchemaID(sdkschema.SchemaID(uri))
		if !ok {
			t.Errorf("LookupBySchemaID(%q): not found", uri)
			continue
		}
		if b.Validator == nil {
			t.Errorf("binding %q: Validator is nil (D9 requires per-schema validator)", uri)
		}
		if b.Extractor == nil {
			t.Errorf("binding %q: Extractor is nil (D9 requires explicit JSON extractor)", uri)
		}
		if domain != JNDomain {
			t.Errorf("binding %q: Domain = %q, want %q", uri, domain, JNDomain)
		}
		if b.MinSchemaProtocolVersion != JNSchemaProtocolVersion {
			t.Errorf("binding %q: MinSchemaProtocolVersion = %d, want %d", uri, b.MinSchemaProtocolVersion, JNSchemaProtocolVersion)
		}
		if b.MaxSchemaProtocolVersion != JNSchemaProtocolVersion {
			t.Errorf("binding %q: MaxSchemaProtocolVersion = %d, want %d", uri, b.MaxSchemaProtocolVersion, JNSchemaProtocolVersion)
		}
	}
}

// TestSDKRegistry_LookupBySchemaID_SurfacesJNDomain pins the
// SDK's cross-domain dispatch contract: every JN binding
// surfaces "judicial-network" so a foreign-domain verifier can
// route by Domain without typing the URI.
func TestSDKRegistry_LookupBySchemaID_SurfacesJNDomain(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	// Spot-check a domain-payload schema (criminal-case) and the
	// shard-genesis schema (which wraps an SDK payload type).
	for _, uri := range []string{"tn-criminal-case-v1", "AT-ENTRY-SCHEMA-SHARD-GENESIS-V1"} {
		if !sdk.Has(sdkschema.SchemaID(uri)) {
			t.Skipf("schema %q not registered — skipping", uri)
		}
		_, domain, _ := sdk.LookupBySchemaID(sdkschema.SchemaID(uri))
		if domain != JNDomain {
			t.Errorf("%s: Domain = %q, want %q", uri, domain, JNDomain)
		}
	}
}

// TestSDKRegistry_HandlesVersion pins the binding's version-gating
// surface: v=1 in range, v=2 / v=0 out of range. Pre-D9, the empty
// binding (Min=Max=0) returned true for every v via the back-compat
// "any version" semantics. Post-D9, the explicit [1,1] range
// rejects everything else.
func TestSDKRegistry_HandlesVersion(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	b, _, ok := sdk.LookupBySchemaID(sdkschema.SchemaID("tn-criminal-case-v1"))
	if !ok {
		t.Fatal("tn-criminal-case-v1 not bound")
	}
	if !b.HandlesVersion(1) {
		t.Error("HandlesVersion(1) = false, want true (JN's v1 schemas)")
	}
	if b.HandlesVersion(2) {
		t.Error("HandlesVersion(2) = true, want false (v2 reserved for a future lift)")
	}
	if b.HandlesVersion(0) {
		t.Error("HandlesVersion(0) = true, want false (v0 below the JN floor)")
	}
}

// TestValidateAdmission_ValidPayload_Admitted pins the happy path
// for the post-D9 enriched validator: an entry whose DomainPayload
// deserializes cleanly under the domain Registry's Deserialize is
// admitted. Replaces the pre-D9 TestValidateAdmission_BoundNil
// Validator_AdmitsAny test (which was a no-op since every binding
// was nil-validator).
func TestValidateAdmission_ValidPayload_Admitted(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	// Serialize a structurally-valid criminal-case payload through
	// the domain Registry's own Serialize closure, so the bytes are
	// guaranteed to round-trip through Deserialize.
	payload := &CriminalCasePayload{}
	body, err := r.SerializePayload("tn-criminal-case-v1", payload)
	if err != nil {
		t.Fatalf("SerializePayload: %v", err)
	}
	entry := &envelope.Entry{DomainPayload: body}
	if err := r.ValidateAdmission(sdk, "tn-criminal-case-v1", entry); err != nil {
		t.Errorf("valid payload rejected: %v", err)
	}
}

// TestValidateAdmission_MalformedPayload_Rejected pins fail-closed:
// an entry whose DomainPayload is malformed surfaces
// ErrAdmissionValidator. This is the substantive shift from
// pre-D9 (where the empty binding admitted everything) to post-D9
// (where the bound Deserialize closure runs at admission time).
func TestValidateAdmission_MalformedPayload_Rejected(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	entry := &envelope.Entry{DomainPayload: []byte("{not valid json")}
	err = r.ValidateAdmission(sdk, "tn-criminal-case-v1", entry)
	if !errors.Is(err, ErrAdmissionValidator) {
		t.Errorf("malformed DomainPayload should surface ErrAdmissionValidator; got %v", err)
	}
}

// TestValidateAdmission_EmptyPayload_Rejected pins that an entry
// with a zero-length DomainPayload is rejected — json.Unmarshal
// on nil fails with "unexpected end of JSON input." This is the
// CHANGED behavior vs the pre-D9 "bound nil-validator admits any
// entry" test (which is deleted; the entire premise no longer
// holds because every binding now carries a non-nil Validator).
func TestValidateAdmission_EmptyPayload_Rejected(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	// Empty Entry{} → DomainPayload nil → Deserialize fails.
	err = r.ValidateAdmission(sdk, "tn-criminal-case-v1", &envelope.Entry{})
	if !errors.Is(err, ErrAdmissionValidator) {
		t.Errorf("empty entry should surface ErrAdmissionValidator; got %v", err)
	}
}
