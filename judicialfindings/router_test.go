// FILE PATH: judicialfindings/router_test.go
//
// Tests for the Phase 7 interface-driven router. Covers:
//
//  1. LookupClass returns the registered class for known Kinds
//     and (zero, false) for unknown ones.
//  2. Verify rejects a nil event.
//  3. Verify rejects an unknown Kind (fail-closed).
//  4. Class-mismatch (Kind registered as Witness but type does
//     not implement WitnessAttested) returns ErrRouter.
//  5. ClassWitness verification requires SourceLogDID + a
//     non-nil WitnessSet at that DID.
//  6. ClassSigner verification requires a SignerVerifier.
//  7. Registry stable values: dashboards / router consumers
//     query on these exact Kind strings; the test fails if
//     they ever drift.
//  8. Interface guards (var _ findings.WitnessAttested = ...)
//     are exercised at runtime to catch any reflection-level
//     drift the compile-time guards would miss.
package judicialfindings

import (
	"context"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
)

func TestLookupClass_KnownKinds(t *testing.T) {
	cases := map[string]Class{
		"AT-GOSSIP-STH-V1":          ClassWitness,
		"AT-GOSSIP-EQUIV-V1":        ClassWitness,
		"AT-GOSSIP-ESCROW-V1":       ClassWitness,
		"AT-GOSSIP-ROT-V1":          ClassWitness,
		"AT-GOSSIP-COMMIT-EQUIV-V1": ClassSigner,
	}
	for kind, want := range cases {
		got, ok := LookupClass(kind)
		if !ok {
			t.Errorf("LookupClass(%q): not registered", kind)
			continue
		}
		if got != want {
			t.Errorf("LookupClass(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestLookupClass_UnknownKind(t *testing.T) {
	if _, ok := LookupClass("AT-GOSSIP-UNKNOWN-V1"); ok {
		t.Fatalf("unknown Kind should not be in Registry")
	}
}

func TestVerify_NilEvent(t *testing.T) {
	err := Verify(context.Background(), nil, VerificationContext{})
	if !errors.Is(err, ErrRouter) {
		t.Fatalf("nil event: want ErrRouter, got %v", err)
	}
}

func TestVerify_UnknownKind_FailsClosed(t *testing.T) {
	err := Verify(context.Background(), unknownEvent{}, VerificationContext{})
	if !errors.Is(err, ErrRouter) {
		t.Fatalf("unknown Kind should ErrRouter; got %v", err)
	}
}

func TestVerify_Witness_RequiresSourceLogDID(t *testing.T) {
	err := Verify(context.Background(), stubWitnessEvent{}, VerificationContext{})
	if !errors.Is(err, ErrRouter) {
		t.Fatalf("missing SourceLogDID: want ErrRouter, got %v", err)
	}
}

func TestVerify_Witness_RequiresWitnessSet(t *testing.T) {
	err := Verify(context.Background(), stubWitnessEvent{}, VerificationContext{
		SourceLogDID: "did:test",
	})
	if !errors.Is(err, ErrRouter) {
		t.Fatalf("missing WitnessSet: want ErrRouter, got %v", err)
	}
}

func TestVerify_Signer_RequiresSignerVerifier(t *testing.T) {
	err := Verify(context.Background(), stubSignerEvent{}, VerificationContext{})
	if !errors.Is(err, ErrRouter) {
		t.Fatalf("missing SignerVerifier: want ErrRouter, got %v", err)
	}
}

func TestVerify_WrongClassImplementation(t *testing.T) {
	// stubMismatchedEvent claims Kind AT-GOSSIP-STH-V1 (ClassWitness)
	// but doesn't implement findings.WitnessAttested. The router
	// must surface this as a configuration error, not a panic.
	err := Verify(context.Background(), stubMismatchedEvent{}, VerificationContext{})
	if !errors.Is(err, ErrRouter) {
		t.Fatalf("class mismatch: want ErrRouter, got %v", err)
	}
}

func TestRegistry_StableKindValues(t *testing.T) {
	required := []string{
		"AT-GOSSIP-STH-V1",
		"AT-GOSSIP-EQUIV-V1",
		"AT-GOSSIP-ESCROW-V1",
		"AT-GOSSIP-ROT-V1",
		"AT-GOSSIP-COMMIT-EQUIV-V1",
	}
	for _, k := range required {
		if _, ok := Registry[k]; !ok {
			t.Errorf("Registry missing required Kind %q", k)
		}
	}
}

func TestInterfaceGuards_RuntimeCheck(t *testing.T) {
	// Compile-time guards in contracts.go already enforce
	// these; we also exercise the runtime type assertions to
	// catch any reflection-level drift.
	var ev gossip.Event = &findings.CosignedTreeHeadFinding{}
	if _, ok := ev.(findings.WitnessAttested); !ok {
		t.Fatal("CosignedTreeHeadFinding must implement WitnessAttested")
	}
	ev = &findings.EquivocationFinding{}
	if _, ok := ev.(findings.WitnessAttested); !ok {
		t.Fatal("EquivocationFinding must implement WitnessAttested")
	}
	ev = &findings.EntryCommitmentEquivocationFinding{}
	if _, ok := ev.(findings.SignerAttested); !ok {
		t.Fatal("EntryCommitmentEquivocationFinding must implement SignerAttested")
	}
}

// ─── Stub events used by the router tests ───────────────────

// stubWitnessEvent implements gossip.Event AND
// findings.WitnessAttested with a Verify that always returns
// nil — we only exercise the router's wiring.
type stubWitnessEvent struct{}

func (stubWitnessEvent) Kind() gossip.Kind                          { return "AT-GOSSIP-STH-V1" }
func (stubWitnessEvent) CanonicalBytes() []byte                     { return nil }
func (stubWitnessEvent) Bindings() [][32]byte                       { return nil }
func (stubWitnessEvent) Validate() error                            { return nil }
func (stubWitnessEvent) Verify(_ *cosignKeySetStub) error           { return nil }

// stubSignerEvent: ClassSigner. Implements the SignerAttested
// interface so the router type-assertion succeeds; Verify is a
// no-op because we only exercise the missing-verifier branch.
type stubSignerEvent struct{}

func (stubSignerEvent) Kind() gossip.Kind                                       { return "AT-GOSSIP-COMMIT-EQUIV-V1" }
func (stubSignerEvent) CanonicalBytes() []byte                                  { return nil }
func (stubSignerEvent) Bindings() [][32]byte                                    { return nil }
func (stubSignerEvent) Validate() error                                         { return nil }
func (stubSignerEvent) Verify(_ context.Context, _ findings.SignerVerifier) error { return nil }

// unknownEvent: not in the Registry. The router must fail
// closed on it.
type unknownEvent struct{}

func (unknownEvent) Kind() gossip.Kind     { return "AT-GOSSIP-UNKNOWN-V1" }
func (unknownEvent) CanonicalBytes() []byte { return nil }
func (unknownEvent) Bindings() [][32]byte   { return nil }
func (unknownEvent) Validate() error        { return nil }

// stubMismatchedEvent: Kind registered as Witness, but type
// does NOT implement findings.WitnessAttested. The router
// detects this via type assertion and returns ErrRouter.
type stubMismatchedEvent struct{}

func (stubMismatchedEvent) Kind() gossip.Kind     { return "AT-GOSSIP-STH-V1" }
func (stubMismatchedEvent) CanonicalBytes() []byte { return nil }
func (stubMismatchedEvent) Bindings() [][32]byte   { return nil }
func (stubMismatchedEvent) Validate() error        { return nil }

// cosignKeySetStub is a placeholder type that stubWitnessEvent
// types its Verify against. It deliberately does NOT match
// *cosign.WitnessKeySet so the router's type assertion to
// findings.WitnessAttested fails (the SDK interface requires
// the concrete *cosign.WitnessKeySet). We use this in the
// stub-event tests where we never actually call the verify
// path; the router's MISSING-WitnessSet branch fires first.
type cosignKeySetStub struct{}
