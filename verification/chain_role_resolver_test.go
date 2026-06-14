/*
FILE PATH: verification/chain_role_resolver_test.go

G19 proof: the VERIFYING resolver admits only chain-backed role claims.
A self-asserted judge (claims "judge" with no backing chain, or whose
chain backs a different role) is dropped → ErrSignerUnknown → not
counted toward the cosignature threshold → the entry dies at the gate.
*/
package verification

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/baseproof/baseproof/attestation"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// fakeAuthority is a 1-method jurisdiction.AuthorityChainResolver stub:
// it returns the role a cosigner's chain resolves to, keyed by DID. A
// DID absent from the map (or a zero delegation_ref) resolves to
// OK=false — the "unbacked" case the resolver must drop.
type fakeAuthority struct {
	byDID map[string]string
}

func (f fakeAuthority) Resolve(_ context.Context, req jurisdiction.AuthorityRequest) jurisdiction.AuthorityVerdict {
	role, ok := f.byDID[req.SignerDID]
	if !ok || req.DelegationRef.IsZero() {
		return jurisdiction.AuthorityVerdict{OK: false, SignerDID: req.SignerDID, Rejection: "unbacked"}
	}
	return jurisdiction.AuthorityVerdict{OK: true, SignerDID: req.SignerDID, Role: role}
}

func davidsonRef(seq uint64) *schemas.LogPositionRef {
	return &schemas.LogPositionRef{LogDID: "did:web:state:tn:davidson", Sequence: seq}
}

func cap(did, role string, ref *schemas.LogPositionRef) schemas.SignedByCapacity {
	return schemas.SignedByCapacity{
		DID:           did,
		Role:          role,
		Exchange:      "did:web:state:tn:davidson",
		DelegationRef: ref,
	}
}

// TestChainRoleResolver_SelfAssertedJudgeDropped is the G19 gate proof.
func TestChainRoleResolver_SelfAssertedJudgeDropped(t *testing.T) {
	authority := fakeAuthority{byDID: map[string]string{
		"did:key:zBACKED":  "judge",       // chain resolves to judge
		"did:key:zCLERK":   "court_clerk", // chain resolves to clerk
		"did:key:zMISMATCH": "court_clerk", // chain backs clerk, but claims judge
	}}
	caps := []schemas.SignedByCapacity{
		cap("did:key:zBACKED", "judge", davidsonRef(10)),         // backed → admitted
		cap("did:key:zSELF", "judge", davidsonRef(11)),           // self-asserted, no backing → dropped
		cap("did:key:zMISMATCH", "judge", davidsonRef(12)),       // claims judge, chain backs clerk → dropped
		cap("did:key:zCLERK", "court_clerk", davidsonRef(13)),    // backed → admitted
		cap("did:key:zNOREF", "judge", nil),                      // no delegation_ref → dropped
	}

	r, err := NewChainRoleResolverFrom(context.Background(), caps, authority)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	// Chain-backed claims resolve to their verified role.
	if e, err := r.LookupRole("did:key:zBACKED"); err != nil || e.Role != "judge" {
		t.Fatalf("backed judge: got (%+v, %v), want role=judge", e, err)
	}
	if e, err := r.LookupRole("did:key:zCLERK"); err != nil || e.Role != "court_clerk" {
		t.Fatalf("backed clerk: got (%+v, %v), want role=court_clerk", e, err)
	}

	// Every unbacked / mismatched / ref-less claim is ErrSignerUnknown.
	for _, did := range []string{"did:key:zSELF", "did:key:zMISMATCH", "did:key:zNOREF"} {
		if _, err := r.LookupRole(did); !errors.Is(err, ErrSignerUnknown) {
			t.Fatalf("%s must be dropped (ErrSignerUnknown), got %v", did, err)
		}
	}
}

// TestChainRoleResolver_NoCapacities: a payload with no
// signed_by_capacities yields a lookup-fails-everywhere resolver (no
// Tier-1 cosigners), matching PayloadRoleResolver's posture.
func TestChainRoleResolver_NoCapacities(t *testing.T) {
	r, err := NewChainRoleResolver(context.Background(), []byte(`{"event_type":"x"}`), fakeAuthority{})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if _, err := r.LookupRole("did:key:zANY"); !errors.Is(err, ErrSignerUnknown) {
		t.Fatalf("empty resolver must return ErrSignerUnknown, got %v", err)
	}
}

// TestChainRoleResolver_BoundCosigners: a capacity list over
// MaxCosigners is refused at construction (DoS cap), wrapping the SDK
// sentinel so callers route it.
func TestChainRoleResolver_BoundCosigners(t *testing.T) {
	caps := make([]schemas.SignedByCapacity, attestation.MaxCosigners+1)
	for i := range caps {
		caps[i] = cap(fmt.Sprintf("did:key:z%d", i), "judge", davidsonRef(uint64(i)))
	}
	_, err := NewChainRoleResolverFrom(context.Background(), caps, fakeAuthority{})
	if !errors.Is(err, attestation.ErrTooManyCosigners) {
		t.Fatalf("over-MaxCosigners must refuse with ErrTooManyCosigners, got %v", err)
	}
}

// TestChainRoleResolver_NilAuthority: a nil resolver is a programming
// error surfaced at construction, not a silent fail-open.
func TestChainRoleResolver_NilAuthority(t *testing.T) {
	caps := []schemas.SignedByCapacity{cap("did:key:zX", "judge", davidsonRef(1))}
	if _, err := NewChainRoleResolverFrom(context.Background(), caps, nil); err == nil {
		t.Fatal("nil AuthorityChainResolver must fail construction")
	}
}

// TestChainRoleResolver_MalformedCapacity: a structurally-invalid cap
// (missing role) fails construction so the gate rejects the entry.
func TestChainRoleResolver_MalformedCapacity(t *testing.T) {
	caps := []schemas.SignedByCapacity{{DID: "did:key:zX", Exchange: "did:web:state:tn:davidson", DelegationRef: davidsonRef(1)}}
	if _, err := NewChainRoleResolverFrom(context.Background(), caps, fakeAuthority{}); err == nil {
		t.Fatal("malformed capacity (no role) must fail construction")
	}
}

// Static check: the verifying resolver satisfies RoleResolver, so it
// drops into CheckCosignature exactly where PayloadRoleResolver does.
var _ RoleResolver = (*ChainRoleResolver)(nil)
