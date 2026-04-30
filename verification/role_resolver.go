/*
FILE PATH: verification/role_resolver.go

DESCRIPTION:
    RoleResolver — the seam the cosignature verifier uses to find
    a Signer's role + exchange given their DID. Replaces the
    deleted directory.OfficerRegistry. Per the v1.6 design, the
    on-log truth is canonical; off-log mutable registries are
    forbidden.

    Two implementations ship here:

      MapRoleResolver — test/fixture stub. The test wires up a
                        fixed (DID → role + exchange) map. Used
                        only by tests; carries no off-log state
                        the network depends on.

      ChainRoleResolver — Phase 3D.signed-by production
                          implementation that reads
                          payload.signed_by_capacities and walks
                          each cosigner's delegation chain via
                          AuthorityResolver. Self-describing,
                          on-log truth, no registry. (Stubbed
                          here; populated in Phase 3D.signed-by.)

    The seam keeps cleanup-1 small: drop the registry, swap in a
    one-method interface, leave the production wiring for the
    capacity-symmetry pass.

OVERVIEW:
    RoleResolver       — interface (LookupRole).
    MapRoleResolver    — in-memory map for tests.
    ResolverEntry      — the (Role, Exchange) tuple returned.
    Sentinels.

KEY DEPENDENCIES:
    None — this file is the leaf of the role-lookup surface.
*/
package verification

import (
	"errors"
	"fmt"
	"sync"
)

// ResolverEntry is the (Role, Exchange) tuple a RoleResolver
// returns. Exchange equals the institutional DID of the exchange
// the Signer belongs to (used by the IntraExchangeOnly gate).
type ResolverEntry struct {
	Role     string
	Exchange string
}

// RoleResolver maps a Signer DID to their role and exchange. The
// cosignature verifier calls this per cosigner DID to enforce
// rule.RequiredSignerRoles + rule.IntraExchangeOnly.
//
// Implementations:
//   - MapRoleResolver  (tests; in this file)
//   - ChainRoleResolver (Phase 3D.signed-by; reads payload
//                        signed_by_capacities + walks chain)
type RoleResolver interface {
	// LookupRole returns the (role, exchange) for did. Returns
	// ErrSignerUnknown when the DID is not a Signer (or not yet
	// declared in this entry's signed_by_capacities). The
	// verifier treats unknown cosigner DIDs as "not in
	// AllowedSet" — they are surfaced in the SignerCosigners
	// detail list but do NOT count toward the threshold.
	LookupRole(did string) (ResolverEntry, error)
}

// ErrSignerUnknown signals that the resolver has no record of did.
// Used by both MapRoleResolver (DID not in the test map) and the
// future ChainRoleResolver (DID not in payload.signed_by_capacities).
var ErrSignerUnknown = errors.New("verification/role_resolver: signer DID unknown")

// ─── MapRoleResolver (test fixture) ─────────────────────────────────

// MapRoleResolver is a fixed in-memory (DID → ResolverEntry) map.
// Test-only — production code uses ChainRoleResolver which derives
// the entry from on-log signed_by_capacities + the delegation chain.
//
// The map carries ONLY (role, exchange). No status, no aliases, no
// timestamps — i.e., NOT a registry. Tests construct one inline:
//
//   r := NewMapRoleResolver().
//        Bind("did:key:zQ3shCLERK", "court_clerk", "did:web:da:davidson-tn").
//        Bind("did:key:zQ3shJUDGE", "judge",       "did:web:da:davidson-tn")
type MapRoleResolver struct {
	mu sync.RWMutex
	m  map[string]ResolverEntry
}

// NewMapRoleResolver constructs an empty resolver.
func NewMapRoleResolver() *MapRoleResolver {
	return &MapRoleResolver{m: make(map[string]ResolverEntry)}
}

// Bind associates a DID with its (role, exchange) pair. Returns
// the resolver so calls chain.
func (r *MapRoleResolver) Bind(did, role, exchange string) *MapRoleResolver {
	r.mu.Lock()
	r.m[did] = ResolverEntry{Role: role, Exchange: exchange}
	r.mu.Unlock()
	return r
}

// LookupRole satisfies RoleResolver.
func (r *MapRoleResolver) LookupRole(did string) (ResolverEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.m[did]
	if !ok {
		return ResolverEntry{}, fmt.Errorf("%w: did=%s", ErrSignerUnknown, did)
	}
	return e, nil
}

// Static check.
var _ RoleResolver = (*MapRoleResolver)(nil)
