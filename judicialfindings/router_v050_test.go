// FILE PATH: judicialfindings/router_v050_test.go
//
// Tests for the attesta v0.5.0 ghost-leaf adoption. Phase 7's
// router now classifies KindGhostLeaf as ClassSelfAttested:
// the gossip envelope's own cosign signature is the authority,
// so the router runs only the SDK Event's structural Validate()
// and returns nil.
//
// Tests pinned in this file:
//
//   1. Registry["AT-GOSSIP-GHOST-V1"] == ClassSelfAttested.
//   2. A well-formed GhostLeafFinding routes through
//      Verify(ctx, event, vc) without requiring SignerVerifier
//      or WitnessSets in the VerificationContext.
//   3. A structurally-invalid GhostLeafFinding (e.g. ghost_seq
//      <= canonical_seq) surfaces ErrRouter wrapping the SDK's
//      Validate error.
//   4. The compile-time pin var _ gossip.Event =
//      (*findings.GhostLeafFinding)(nil) still holds at runtime.
package judicialfindings

import (
	"context"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
)

// ghostFixture returns a structurally-valid GhostLeafFinding.
// Field values mirror the SDK's own ghost_leaf_test.go fixture
// shape (ghost_seq > canonical_seq, non-zero hash, non-empty
// LogDID, non-zero ObservedAtUnixNano).
func ghostFixture(t *testing.T) *findings.GhostLeafFinding {
	t.Helper()
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	f, err := findings.NewGhostLeafFinding(
		/* ghostSeq     */ 101,
		/* canonicalSeq */ 42,
		/* canonicalHash */ hash,
		/* logDID       */ "did:web:state:tn:davidson:ledger",
		/* observedAtUnixNano */ 1_758_000_000_000_000_000,
	)
	if err != nil {
		t.Fatalf("NewGhostLeafFinding fixture: %v", err)
	}
	return f
}

func TestRegistry_GhostLeaf_IsSelfAttested(t *testing.T) {
	got, ok := LookupClass("AT-GOSSIP-GHOST-V1")
	if !ok {
		t.Fatal("KindGhostLeaf MUST be registered (attesta v0.5.0+)")
	}
	if got != ClassSelfAttested {
		t.Errorf("KindGhostLeaf Class = %q, want %q", got, ClassSelfAttested)
	}
}

func TestVerify_GhostLeaf_HappyPath(t *testing.T) {
	// Self-attested events do NOT require SignerVerifier or
	// WitnessSets. An empty VerificationContext MUST suffice —
	// dashboards and auditors call the router uniformly without
	// branching on Class.
	err := Verify(context.Background(), ghostFixture(t), VerificationContext{})
	if err != nil {
		t.Fatalf("well-formed GhostLeafFinding MUST verify; got %v", err)
	}
}

func TestVerify_GhostLeaf_RejectsStructuralInvariantBreak(t *testing.T) {
	// The SDK's Validate() rejects ghost_seq <= canonical_seq
	// (the structural signature of a ghost leaf is that the
	// duplicate Tessera sequence comes AFTER the canonical one).
	// We synthesise an invalid event by hand-rolling the struct
	// and ensure the router wraps the failure in ErrRouter.
	bad := &findings.GhostLeafFinding{}
	err := Verify(context.Background(), bad, VerificationContext{})
	if err == nil {
		t.Fatal("zero-value GhostLeafFinding MUST surface a router error")
	}
	if !errors.Is(err, ErrRouter) {
		t.Errorf("Validate failure MUST wrap ErrRouter; got %v", err)
	}
}

// TestGhostLeaf_RuntimeInterfaceContract pins the runtime
// counterpart of contracts.go's compile-time guard. A reflection
// drift in a future SDK that strips Validate / Kind / Bindings /
// CanonicalBytes from GhostLeafFinding fails here.
func TestGhostLeaf_RuntimeInterfaceContract(t *testing.T) {
	var ev gossip.Event = ghostFixture(t)
	if ev.Kind() != "AT-GOSSIP-GHOST-V1" {
		t.Errorf("Kind drift: got %q", ev.Kind())
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("fixture must be valid: %v", err)
	}
	// Bindings include the canonical_hash for O(1)
	// /v1/gossip/by-binding/{hash} lookup. The router never
	// inspects them, but a regression here would break the
	// auditor surface, so we pin a non-empty result.
	if len(ev.Bindings()) == 0 {
		t.Error("Bindings must surface the canonical_hash for auditors")
	}
}
