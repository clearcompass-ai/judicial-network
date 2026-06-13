/*
verification/platform_kind_vocab_test.go — rc10: platform kinds are
first-class cosignature-policy vocabulary (the PRE-4a re-home ruling).

Locks the extractEventType kind-fallback at its consumer: CheckCosignature
must (a) key the policy lookup by the `kind` discriminator when a payload
carries no `event_type`, (b) enforce the domain-injected mix on it (the
clerk-cosigned retire), and (c) refuse unknown kinds with the SAME
closed-set taxonomy as any stranger event.
*/
package verification

import (
	"testing"

	"github.com/baseproof/baseproof/kinds"
	trial "github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
)

func TestCheck_PlatformKind_RetireMixEnforced(t *testing.T) {
	pol := trial.MustCosignaturePolicy()
	const clerk2 = "did:web:clerk-two.davidson.example"
	res := NewMapRoleResolver().
		Bind(clerkDID, "court_clerk", exchangeA).
		Bind(cosigJudge, "court_clerk", exchangeA).
		Bind(clerk2, "court_clerk", exchangeA) // retire wants TWO clerk cosigners

	// Mix-PASSING retire: two clerk cosigners, intra-exchange.
	ok := buildEntry(clerkDID, map[string]any{
		"kind":            kinds.EntryDestinationRetireV1,
		"destination_ref": "tn/davidson/circuit-1",
		"exchange_did":    exchangeA,
	}, cosigJudge, clerk2)
	if v := CheckCosignature(ok, pol, res, exchangeA); !v.OK {
		t.Fatalf("a two-clerk retire must pass the kind-keyed mix: %s %s", v.Rejection, v.Reason)
	}

	// Mix-VIOLATING retire: one clerk only (MinSignerCosigners=2 unmet).
	bad := buildEntry(clerkDID, map[string]any{
		"kind":            kinds.EntryDestinationRetireV1,
		"destination_ref": "tn/davidson/circuit-1",
		"exchange_did":    exchangeA,
	})
	if v := CheckCosignature(bad, pol, res, exchangeA); v.OK {
		t.Fatal("a single-clerk retire must REFUSE (the W2 mix)")
	}
}

func TestCheck_PlatformKind_UnknownKindRefusedClosedSet(t *testing.T) {
	pol := trial.MustCosignaturePolicy()
	res := NewMapRoleResolver().Bind(clerkDID, "court_clerk", exchangeA)
	e := buildEntry(clerkDID, map[string]any{"kind": "BP-ENTRY-NOT-A-REAL-KIND-V1"})
	v := CheckCosignature(e, pol, res, exchangeA)
	if v.OK || v.Rejection != CosigRejectUnknownEventType {
		t.Fatalf("an unknown kind must refuse with the closed-set taxonomy: %+v", v)
	}
}

func TestCheck_NoEventTypeNoKind_StillRefused(t *testing.T) {
	pol := trial.MustCosignaturePolicy()
	res := NewMapRoleResolver().Bind(clerkDID, "court_clerk", exchangeA)
	e := buildEntry(clerkDID, map[string]any{"something": "else"})
	v := CheckCosignature(e, pol, res, exchangeA)
	if v.OK || v.Rejection != CosigRejectMissingEventType {
		t.Fatalf("a payload with neither event_type nor kind must refuse missing-event-type: %+v", v)
	}
}
