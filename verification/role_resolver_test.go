/*
FILE PATH: verification/role_resolver_test.go

DESCRIPTION:
    Tests for RoleResolver + MapRoleResolver. The interface is the
    seam the cosignature verifier uses to map cosigner DIDs to
    their (role, exchange) — replacing the deleted
    directory.OfficerRegistry per the v1.6 "no registries" design.
*/
package verification

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// ─── interface satisfaction ─────────────────────────────────────────

func TestMapRoleResolver_SatisfiesInterface(t *testing.T) {
	var _ RoleResolver = NewMapRoleResolver()
}

// ─── basic lookup ───────────────────────────────────────────────────

func TestMapRoleResolver_BindAndLookup(t *testing.T) {
	r := NewMapRoleResolver().
		Bind("did:key:zQ3shCLERK", "court_clerk", "did:web:state:tn:davidson").
		Bind("did:key:zQ3shJUDGE", "judge", "did:web:state:tn:davidson")

	clerk, err := r.LookupRole("did:key:zQ3shCLERK")
	if err != nil {
		t.Fatalf("clerk: %v", err)
	}
	if clerk.Role != "court_clerk" {
		t.Errorf("role drift: %q", clerk.Role)
	}
	if clerk.Exchange != "did:web:state:tn:davidson" {
		t.Errorf("exchange drift: %q", clerk.Exchange)
	}

	judge, err := r.LookupRole("did:key:zQ3shJUDGE")
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if judge.Role != "judge" {
		t.Errorf("role drift: %q", judge.Role)
	}
}

func TestMapRoleResolver_UnknownReturnsSentinel(t *testing.T) {
	r := NewMapRoleResolver()
	_, err := r.LookupRole("did:key:zQ3shGHOST")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrSignerUnknown) {
		t.Errorf("expected ErrSignerUnknown, got: %v", err)
	}
	if !strings.Contains(err.Error(), "did:key:zQ3shGHOST") {
		t.Errorf("err should mention DID: %v", err)
	}
}

// ─── chained Bind ───────────────────────────────────────────────────

func TestMapRoleResolver_BindReturnsResolver(t *testing.T) {
	r := NewMapRoleResolver().Bind("a", "judge", "x")
	if r == nil {
		t.Fatal("Bind should return resolver")
	}
	if _, err := r.LookupRole("a"); err != nil {
		t.Errorf("after Bind: %v", err)
	}
}

// ─── multi-exchange (the v1.6 explicit invariant) ──────────────────

// TestMapRoleResolver_MultipleExchanges pins the network/exchange
// hierarchy: a single resolver may carry Signers from multiple
// exchanges. The IntraExchangeOnly gate in the cosignature rule
// determines whether a cross-exchange cosigner counts.
func TestMapRoleResolver_MultipleExchanges(t *testing.T) {
	const (
		davidsonClerk = "did:key:zQ3shCLERK_DA"
		davidsonJudge = "did:key:zQ3shJUDGE_DA"
		shelbyClerk   = "did:key:zQ3shCLERK_SH"
		shelbyJudge   = "did:key:zQ3shJUDGE_SH"
		davidsonExch  = "did:web:state:tn:davidson"
		shelbyExch    = "did:web:state:tn:shelby"
	)
	r := NewMapRoleResolver().
		Bind(davidsonClerk, "court_clerk", davidsonExch).
		Bind(davidsonJudge, "judge", davidsonExch).
		Bind(shelbyClerk, "court_clerk", shelbyExch).
		Bind(shelbyJudge, "judge", shelbyExch)

	cases := []struct {
		did, wantExchange string
	}{
		{davidsonClerk, davidsonExch},
		{davidsonJudge, davidsonExch},
		{shelbyClerk, shelbyExch},
		{shelbyJudge, shelbyExch},
	}
	for _, tc := range cases {
		got, err := r.LookupRole(tc.did)
		if err != nil {
			t.Errorf("%s: %v", tc.did, err)
			continue
		}
		if got.Exchange != tc.wantExchange {
			t.Errorf("%s exchange: got %q want %q",
				tc.did, got.Exchange, tc.wantExchange)
		}
	}
}

// ─── overwrite + nil-DID safety ────────────────────────────────────

func TestMapRoleResolver_BindOverwrites(t *testing.T) {
	r := NewMapRoleResolver().
		Bind("did:key:zQ3shA", "judge", "ex1").
		Bind("did:key:zQ3shA", "court_clerk", "ex2")

	got, _ := r.LookupRole("did:key:zQ3shA")
	if got.Role != "court_clerk" || got.Exchange != "ex2" {
		t.Errorf("overwrite failed: %+v", got)
	}
}

func TestMapRoleResolver_EmptyDIDLookup(t *testing.T) {
	r := NewMapRoleResolver()
	_, err := r.LookupRole("")
	if !errors.Is(err, ErrSignerUnknown) {
		t.Errorf("empty DID: %v", err)
	}
}

// ─── concurrency ───────────────────────────────────────────────────

func TestMapRoleResolver_ConcurrentReadsSafe(t *testing.T) {
	r := NewMapRoleResolver()
	for i := 0; i < 16; i++ {
		r.Bind("did:key:zQ3sh"+string(rune('A'+i)), "judge", "did:web:test")
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = r.LookupRole("did:key:zQ3shA")
				_, _ = r.LookupRole("did:key:zQ3shGHOST")
			}
		}()
	}
	wg.Wait()
}

// ─── concurrent reads + writes ─────────────────────────────────────

// TestMapRoleResolver_ConcurrentBindAndLookup pins thread-safety
// with concurrent writes — the resolver may be initialized
// asynchronously in production wiring (e.g., a goroutine that
// hydrates capacities from on-log entries while the verifier
// starts servicing).
func TestMapRoleResolver_ConcurrentBindAndLookup(t *testing.T) {
	r := NewMapRoleResolver()
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			r.Bind("did:key:zQ3sh"+string(rune('A'+i%26)), "judge", "did:web:test")
		}
	}()

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = r.LookupRole("did:key:zQ3shA")
			}
		}()
	}
	wg.Wait()
}
