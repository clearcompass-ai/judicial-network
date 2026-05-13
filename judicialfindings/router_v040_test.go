// FILE PATH: judicialfindings/router_v040_test.go
//
// Tests for the attesta v0.4.0 SDK schema.Registry adoption on
// the Phase 7 router. The router's existing VerificationContext
// gained a SchemaRegistry field (optional, non-nil → admission
// gate before signature verification).
//
// These tests cover:
//  1. The new SchemaRegistry field exists on VerificationContext
//     and accepts a *sdkschema.Registry value (compile-time
//     check via the test's struct literal).
//  2. A nil SchemaRegistry leaves the router behavior unchanged
//     (back-compat with every Phase 7 caller).
//  3. The field has the correct exported type (sdkschema.Registry,
//     not a JN-local wrapper) so external callers (the Ledger's
//     admission router) can pass an SDK-constructed registry
//     directly.
package judicialfindings

import (
	"context"
	"errors"
	"testing"

	sdkschema "github.com/clearcompass-ai/attesta/schema"
)

func TestVerificationContext_SchemaRegistryField_Exists(t *testing.T) {
	// Compile-time check: the field must accept a
	// *sdkschema.Registry. A type rename or removal in v0.4.0+
	// SDK would break this assignment.
	vc := VerificationContext{
		SchemaRegistry: sdkschema.NewRegistry(),
	}
	if vc.SchemaRegistry == nil {
		t.Fatal("expected non-nil SchemaRegistry")
	}
}

func TestVerify_NilSchemaRegistry_PreservesBehavior(t *testing.T) {
	// Phase 7 contract: a nil SchemaRegistry MUST leave the
	// router's existing flow untouched. We exercise the unknown-
	// kind branch (the cheapest fail-closed path) with both a
	// nil and an unset SchemaRegistry; both must surface the
	// same ErrRouter.
	err := Verify(context.Background(), unknownEvent{}, VerificationContext{})
	if !errors.Is(err, ErrRouter) {
		t.Fatalf("nil SchemaRegistry must preserve existing behavior; got %v", err)
	}
	err = Verify(context.Background(), unknownEvent{}, VerificationContext{
		SchemaRegistry: nil,
	})
	if !errors.Is(err, ErrRouter) {
		t.Fatalf("explicit-nil SchemaRegistry must preserve existing behavior; got %v", err)
	}
}

func TestVerificationContext_AcceptsFrozenRegistry(t *testing.T) {
	// The v0.4.0 SDK registry is typically frozen at boot. The
	// router accepts it as-is (no requirement that the Registry
	// be open for late binds).
	reg := sdkschema.NewRegistry()
	reg.Freeze()
	vc := VerificationContext{SchemaRegistry: reg}
	if !vc.SchemaRegistry.IsFrozen() {
		t.Fatal("frozen Registry round-trip mismatch")
	}
}
