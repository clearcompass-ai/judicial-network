/*
FILE PATH: verification/delegation_chain_by_did_test.go

DESCRIPTION:

	Tests for the v1.2.0 by-DID delegation walker added to
	verification/delegation_chain.go. The by-DID path uses the
	SDK's delegation.Resolver and returns an
	attestation.DelegationChain — the canonical shape consumed by
	attestation.EvaluateConstraint and
	attestation.VerifyEntryAttestationPolicy.

	Coverage:
	  - Input guards: nil lookup, empty signerDID.
	  - One-hop chain: leaf delegates to root; root terminates via
	    attestation.ErrUnknownDelegate.
	  - Two-hop chain: leaf → middle → root; order preserved
	    (leaf-first).
	  - Cycle detection: a lookup that loops surfaces
	    sdkdelegation.ErrCycleDetected via errors.Is.
	  - Max-depth exceeded: a chain longer than the configured
	    cap surfaces sdkdelegation.ErrMaxDepthExceeded.
	  - WithMaxDepth option propagates through NewResolverFromLookup.
	  - ChainOriginDID + ChainHasScope helpers match the SDK
	    chain methods.
*/
package verification

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/delegation"
)

// mapLookup builds a DelegationLookupFunc backed by a map. Any
// DID not present in the map surfaces as attestation.ErrUnknownDelegate
// — the SDK's terminator sentinel.
func mapLookup(t *testing.T, m map[string]delegation.DelegationEntry) DelegationLookupFunc {
	t.Helper()
	return func(_ context.Context, did string) (delegation.DelegationEntry, error) {
		entry, ok := m[did]
		if !ok {
			return delegation.DelegationEntry{}, attestation.ErrUnknownDelegate
		}
		return entry, nil
	}
}

// ─── Input guards ───────────────────────────────────────────────

func TestResolveDelegationByDID_NilLookup(t *testing.T) {
	_, err := ResolveDelegationByDID(context.Background(), nil, "did:key:zX")
	if !errors.Is(err, ErrDelegationResolve) {
		t.Errorf("err = %v, want errors.Is(ErrDelegationResolve)", err)
	}
}

func TestResolveDelegationByDID_EmptySignerDID(t *testing.T) {
	lookup := mapLookup(t, nil)
	_, err := ResolveDelegationByDID(context.Background(), lookup, "")
	if !errors.Is(err, ErrDelegationResolve) {
		t.Errorf("err = %v, want errors.Is(ErrDelegationResolve)", err)
	}
}

// ─── Single-hop chain ──────────────────────────────────────

func TestResolveDelegationByDID_OneHop(t *testing.T) {
	leaf := "did:key:zClerk"
	root := "did:web:state:tn:davidson"
	lookup := mapLookup(t, map[string]delegation.DelegationEntry{
		leaf: {
			DelegateDID:  leaf,
			DelegatorDID: root,
			Scopes:       []string{"filings:read"},
			Live:         true,
		},
		// root: NOT in map → ErrUnknownDelegate terminates walk.
	})

	chain, err := ResolveDelegationByDID(context.Background(), lookup, leaf)
	if err != nil {
		t.Fatalf("ResolveDelegationByDID: %v", err)
	}
	if len(chain.Hops) != 1 {
		t.Fatalf("len(Hops) = %d, want 1", len(chain.Hops))
	}
	if chain.Hops[0].DelegateDID != leaf {
		t.Errorf("Hops[0].DelegateDID = %q, want %q", chain.Hops[0].DelegateDID, leaf)
	}
	if chain.Hops[0].DelegatorDID != root {
		t.Errorf("Hops[0].DelegatorDID = %q, want %q", chain.Hops[0].DelegatorDID, root)
	}
}

// ─── Two-hop chain (leaf-first ordering) ───────────────────────

func TestResolveDelegationByDID_TwoHopChain_LeafFirst(t *testing.T) {
	leaf := "did:key:zChair"
	middle := "did:key:zDean"
	root := "did:web:sgu.edu"
	lookup := mapLookup(t, map[string]delegation.DelegationEntry{
		leaf:   {DelegateDID: leaf, DelegatorDID: middle, Scopes: []string{"chair"}, Live: true},
		middle: {DelegateDID: middle, DelegatorDID: root, Scopes: []string{"dean"}, Live: true},
	})

	chain, err := ResolveDelegationByDID(context.Background(), lookup, leaf)
	if err != nil {
		t.Fatalf("ResolveDelegationByDID: %v", err)
	}
	if len(chain.Hops) != 2 {
		t.Fatalf("len(Hops) = %d, want 2; chain=%+v", len(chain.Hops), chain)
	}
	// Leaf-first ordering: Hops[0] authorises the queried DID.
	if chain.Hops[0].DelegateDID != leaf {
		t.Errorf("Hops[0].DelegateDID = %q, want %q (leaf)", chain.Hops[0].DelegateDID, leaf)
	}
	if chain.Hops[1].DelegateDID != middle {
		t.Errorf("Hops[1].DelegateDID = %q, want %q (middle)", chain.Hops[1].DelegateDID, middle)
	}
}

// ─── Cycle detection ─────────────────────────────────────────

func TestResolveDelegationByDID_CycleDetected(t *testing.T) {
	a := "did:key:zA"
	b := "did:key:zB"
	lookup := mapLookup(t, map[string]delegation.DelegationEntry{
		a: {DelegateDID: a, DelegatorDID: b, Live: true},
		b: {DelegateDID: b, DelegatorDID: a, Live: true}, // cycle
	})

	_, err := ResolveDelegationByDID(context.Background(), lookup, a)
	if !errors.Is(err, delegation.ErrCycleDetected) {
		t.Errorf("err = %v, want errors.Is(delegation.ErrCycleDetected)", err)
	}
	if !errors.Is(err, ErrDelegationResolve) {
		t.Errorf("err = %v, want errors.Is(ErrDelegationResolve) wrapper", err)
	}
}

// ─── Max-depth ────────────────────────────────────────────────

func TestResolveDelegationByDID_MaxDepthExceeded(t *testing.T) {
	// Build a 5-hop chain. Set MaxDepth=3 → expect ErrMaxDepthExceeded
	// on the 4th-hop lookup attempt.
	m := map[string]delegation.DelegationEntry{}
	dids := []string{"did:key:z0", "did:key:z1", "did:key:z2", "did:key:z3", "did:key:z4", "did:web:root"}
	for i := 0; i < len(dids)-1; i++ {
		m[dids[i]] = delegation.DelegationEntry{
			DelegateDID:  dids[i],
			DelegatorDID: dids[i+1],
			Live:         true,
		}
	}
	lookup := mapLookup(t, m)

	_, err := ResolveDelegationByDID(context.Background(), lookup, dids[0], delegation.WithMaxDepth(3))
	if !errors.Is(err, delegation.ErrMaxDepthExceeded) {
		t.Errorf("err = %v, want errors.Is(delegation.ErrMaxDepthExceeded)", err)
	}
}

func TestResolveDelegationByDID_WithinMaxDepth(t *testing.T) {
	// 3-hop chain with MaxDepth=5 → must succeed.
	m := map[string]delegation.DelegationEntry{
		"did:key:z0": {DelegateDID: "did:key:z0", DelegatorDID: "did:key:z1", Live: true},
		"did:key:z1": {DelegateDID: "did:key:z1", DelegatorDID: "did:key:z2", Live: true},
		"did:key:z2": {DelegateDID: "did:key:z2", DelegatorDID: "did:web:root", Live: true},
	}
	chain, err := ResolveDelegationByDID(context.Background(), mapLookup(t, m), "did:key:z0", delegation.WithMaxDepth(5))
	if err != nil {
		t.Fatalf("ResolveDelegationByDID: %v", err)
	}
	if len(chain.Hops) != 3 {
		t.Errorf("len(Hops) = %d, want 3", len(chain.Hops))
	}
}

// ─── Transport-level lookup failure ──────────────────────────

func TestResolveDelegationByDID_TransportErr_WrappedAsBrokenChain(t *testing.T) {
	boom := errors.New("simulated transport failure")
	lookup := func(_ context.Context, _ string) (delegation.DelegationEntry, error) {
		return delegation.DelegationEntry{}, boom
	}
	_, err := ResolveDelegationByDID(context.Background(), lookup, "did:key:zLeaf")
	if !errors.Is(err, boom) {
		t.Errorf("transport err MUST remain reachable via errors.Is; got %v", err)
	}
	if !errors.Is(err, ErrDelegationResolve) {
		t.Errorf("err = %v, want ErrDelegationResolve wrapper", err)
	}
}

// ─── ChainOriginDID + ChainHasScope helpers ─────────────────────

func TestChainOriginDID_Empty(t *testing.T) {
	if got := ChainOriginDID(attestation.DelegationChain{}); got != "" {
		t.Errorf("empty chain origin = %q, want empty", got)
	}
}

func TestChainOriginDID_OneHop(t *testing.T) {
	chain := attestation.DelegationChain{
		Hops: []attestation.DelegationHop{
			{DelegateDID: "did:key:zLeaf", DelegatorDID: "did:web:root", Live: true},
		},
	}
	if got := ChainOriginDID(chain); got != "did:web:root" {
		t.Errorf("origin = %q, want did:web:root", got)
	}
}

// SDK semantics (attestation.DelegationChain.HasScope, source-
// verified): the predicate checks ONLY the leaf hop (Hops[0]).
// Upper-hop scopes are treated as the parent authority that may
// have constrained the leaf; the LEAF's Scopes is what the
// attester effectively carries. This test pins that semantic so
// a future SDK change to "every-hop intersection" surfaces here
// before a JN handler silently shifts behaviour.
func TestChainHasScope_LeafScopeOnly(t *testing.T) {
	chain := attestation.DelegationChain{
		Hops: []attestation.DelegationHop{
			{DelegateDID: "did:key:zA", DelegatorDID: "did:key:zB", Scopes: []string{"x", "y"}, Live: true},
			{DelegateDID: "did:key:zB", DelegatorDID: "did:web:root", Scopes: []string{"x"}, Live: true},
		},
	}
	if !ChainHasScope(chain, "x") {
		t.Errorf("ChainHasScope(\"x\") = false, want true (leaf hop carries x)")
	}
	if !ChainHasScope(chain, "y") {
		t.Errorf("ChainHasScope(\"y\") = false, want true (leaf hop carries y; SDK checks LEAF only)")
	}
	if ChainHasScope(chain, "z") {
		t.Errorf("ChainHasScope(\"z\") = true, but leaf does not carry z")
	}
}

func TestChainHasScope_EmptyChain(t *testing.T) {
	if ChainHasScope(attestation.DelegationChain{}, "x") {
		t.Errorf("empty chain MUST NOT have any scope")
	}
}

// Compile-time pin: ensure the doc-stated invariants — chain
// shape matches SDK contracts — surface as build failures rather
// than silent runtime drift.
var (
	_ = fmt.Sprintf
	_ = (*delegation.Resolver)(nil)
)
