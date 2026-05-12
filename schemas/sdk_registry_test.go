// FILE PATH: schemas/sdk_registry_test.go
//
// Tests for the attesta v0.4.0 SDKRegistry bridge. Verifies:
//
//  1. SDKRegistry on a nil receiver returns ErrSDKRegistryBuild.
//  2. SDKRegistry returns a non-nil, frozen *sdkschema.Registry
//     populated with every JN schema URI.
//  3. The returned Registry has IsFrozen() == true (admission
//     wiring is order-independent — no late binds).
//  4. Every JN schema URI is reachable via Has().
//  5. ValidateAdmission on a nil sdk returns ErrSDKRegistryBuild.
//  6. ValidateAdmission on a nil entry returns ErrSDKRegistryBuild.
//  7. ValidateAdmission on an unbound SchemaID returns the SDK's
//     ErrSchemaIDNotFound (errors.Is-detectable).
//  8. ValidateAdmission on a bound nil-validator binding admits
//     any entry (the JN binding pattern in v0.4.0 — domain-level
//     deserialization stays on the domain Registry).
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
	// Every URI the JN domain Registry knows must be bound on
	// the SDK Registry.
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
	// SDK exports ErrRegistryFrozen; we don't import it here
	// (would couple this test to an SDK sentinel name change).
	// errors.Is reachability is exercised by attesta's own
	// schema/registry_test.go.
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

func TestValidateAdmission_BoundNilValidator_AdmitsAny(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	// Every JN schema is bound with a nil-Validator Binding (the
	// v0.4.0 adoption pattern). An entry with that SchemaID
	// passes admission because the SDK treats nil-Validator as
	// "no admission-time check required."
	err = r.ValidateAdmission(sdk, "tn-criminal-case-v1", &envelope.Entry{})
	if err != nil {
		t.Fatalf("bound nil-validator schema should admit any entry, got %v", err)
	}
}
