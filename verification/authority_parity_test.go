/*
FILE PATH: verification/authority_parity_test.go

PRE-13b #181 step 4 — the PARITY LOCK TEST. It gates the retire (steps 5-6):
nothing may delete AuthorityResolver until the index-walk adapter provably
produces the SAME verdict over the SAME real artifacts.

Prove-Boundaries / no hand-assembly: every fixture is built through the real
codecs (MarshalJudicialDelegationPayload / Revocation / Succession +
canonicalEntry), then represented BOTH ways — the position-fetch inputs
AuthorityResolver consumes (signerRef + granter_delegation_ref pointers inside
the entries) AND the by-DID index the LedgerDelegationResolver consumes — over
ONE shared fetcher. Both engines walk the identical bytes; the test asserts they
AGREE across role / scope / revocation / succession / expiry.

Lane note: LeafReader is nil (the gate lane), so AuthorityResolver's
EvaluateOrigin (SMT) is skipped and revocation is detected via classifyTip —
exactly the index-surfaced case (#120) the index-walk covers with
newest-grant-wins. The SMT-authenticated EvaluateOrigin path is the external
auditor's, a different consumer, and is not part of this gate parity.
*/
package verification

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/baseproof/types"

	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// makeSuccession builds a real succession entry's canonical bytes (the codec
// validates Inheritance ∈ {full,narrowed,clean_slate} + required fields).
func makeSuccession(t *testing.T, signerDID, successorDID string, target schemas.LogPositionRef) []byte {
	t.Helper()
	p := &schemas.JudicialSuccessionPayload{
		SchemaID:         schemas.SchemaJudicialSuccessionV1,
		TargetDelegation: target,
		SuccessorDID:     successorDID,
		Reason:           "death_in_office",
		Inheritance:      schemas.InheritanceFull,
		EffectiveAt:      time.Now().UTC().Format(time.RFC3339Nano),
	}
	by, err := schemas.MarshalJudicialSuccessionPayload(p)
	if err != nil {
		t.Fatalf("marshal succession: %v", err)
	}
	return canonicalEntry(t, signerDID, by)
}

// parityFixture holds a chain represented both ways over one shared fetcher.
type parityFixture struct {
	logDID    string
	signerDID string
	signerRef schemas.LogPositionRef
	fetcher   *fakeFetcher
	querier   *fakeDelegateQuerier
}

func newParityFixture(logDID, signerDID string) *parityFixture {
	return &parityFixture{
		logDID:    logDID,
		signerDID: signerDID,
		fetcher:   newFakeFetcher(),
		querier:   &fakeDelegateQuerier{byDID: map[string][]types.EntryWithMetadata{}},
	}
}

// add registers entryBytes at pos in the shared fetcher AND prepends pos as the
// NEWEST by-DID row for grantee (the index walk reads entries[0]). Returns the
// ref the position-fetch walk uses.
func (fx *parityFixture) add(pos types.LogPosition, grantee string, entryBytes []byte) schemas.LogPositionRef {
	fx.fetcher.put(pos, entryBytes)
	fx.querier.byDID[grantee] = append([]types.EntryWithMetadata{{Position: pos}}, fx.querier.byDID[grantee]...)
	return schemas.LogPositionRef{LogDID: pos.LogDID, Sequence: pos.Sequence}
}

// runBoth runs both engines WALK-ONLY (requestedAction="") over the fixture.
func (fx *parityFixture) runBoth(t *testing.T) (*Authority, jurisdiction.AuthorityVerdict) {
	t.Helper()
	auth := &AuthorityResolver{Fetcher: fx.fetcher, Catalog: trial.MustRoleCatalog()}
	a := auth.Resolve(context.Background(), fx.signerDID, fx.signerRef, "")

	idx, err := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: fx.querier, Fetcher: fx.fetcher, LogDID: fx.logDID,
		Role: JudicialHopRole, Scope: JudicialHopScope, Expiry: JudicialHopExpiry,
	})
	if err != nil {
		t.Fatalf("index resolver ctor: %v", err)
	}
	v := idx.Resolve(context.Background(), jurisdiction.AuthorityRequest{
		SignerDID:     fx.signerDID,
		DelegationRef: jurisdiction.DelegationRef{LogDID: fx.signerRef.LogDID, Sequence: fx.signerRef.Sequence},
	})
	return a, v
}

// assertParity is the lock. OK and the Rejection token must match ALWAYS; Role
// and EffectiveScope must match on SUCCESS (the gate reads them only when OK —
// AuthorityResolver leaves Role unset on a mid-walk rejection, so role/scope on
// a rejected verdict are don't-cares).
func assertParity(t *testing.T, name string, a *Authority, v jurisdiction.AuthorityVerdict) {
	t.Helper()
	if a.OK != v.OK {
		t.Errorf("%s: OK mismatch — authority=%v index=%v (a.rej=%q v.rej=%q)", name, a.OK, v.OK, a.Rejection, v.Rejection)
	}
	if string(a.Rejection) != v.Rejection {
		t.Errorf("%s: Rejection mismatch — authority=%q index=%q", name, a.Rejection, v.Rejection)
	}
	if a.OK {
		if a.Role != v.Role {
			t.Errorf("%s: Role mismatch on success — authority=%q index=%q", name, a.Role, v.Role)
		}
		if !equalScope(a.EffectiveScope, v.EffectiveScope) {
			t.Errorf("%s: EffectiveScope mismatch on success — authority=%v index=%v", name, a.EffectiveScope, v.EffectiveScope)
		}
	}
}

func equalScope(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

const (
	parLog  = "did:web:l"
	parRoot = "did:web:root"
	parAuth = "did:web:authority"
	parJ    = "did:web:judge"
)

func TestParity_IndexWalk_Equals_AuthorityResolver(t *testing.T) {
	// LIVE two-hop: judge ← authority ← root. Distinct tip role + a scope that
	// narrows up the chain, so role-at-tip and scope intersection are both
	// non-trivial.
	t.Run("live_two_hop", func(t *testing.T) {
		fx := newParityFixture(parLog, parJ)
		_, authBytes := makeDelegation(t,
			types.LogPosition{LogDID: parLog, Sequence: 50},
			parRoot, parAuth, "presiding", []string{"civil", "criminal"}, nil, time.Hour)
		authRef := fx.add(types.LogPosition{LogDID: parLog, Sequence: 50}, parAuth, authBytes)
		_, judgeBytes := makeDelegation(t,
			types.LogPosition{LogDID: parLog, Sequence: 100},
			parAuth, parJ, "officer", []string{"civil", "criminal", "family"}, &authRef, time.Hour)
		fx.signerRef = fx.add(types.LogPosition{LogDID: parLog, Sequence: 100}, parJ, judgeBytes)

		a, v := fx.runBoth(t)
		assertParity(t, "live_two_hop", a, v)
		if !v.OK || v.Role != "officer" || !equalScope(v.EffectiveScope, []string{"civil", "criminal"}) {
			t.Fatalf("live chain must resolve OK with tip role + intersected scope: OK=%v role=%q scope=%v rej=%q",
				v.OK, v.Role, v.EffectiveScope, v.Rejection)
		}
	})

	// REVOCATION tip: the newest by-DID row for judge is a revocation; the
	// position-fetch walk fetches it at signerRef. Both ⇒ RejectRevoked.
	t.Run("revocation_tip", func(t *testing.T) {
		fx := newParityFixture(parLog, parJ)
		_, judgeBytes := makeDelegation(t,
			types.LogPosition{LogDID: parLog, Sequence: 100},
			parAuth, parJ, "officer", []string{"civil"}, nil, time.Hour)
		judgeRef := fx.add(types.LogPosition{LogDID: parLog, Sequence: 100}, parJ, judgeBytes)
		revBytes := makeRevocation(t, parAuth, judgeRef)
		fx.signerRef = fx.add(types.LogPosition{LogDID: parLog, Sequence: 200}, parJ, revBytes)

		a, v := fx.runBoth(t)
		assertParity(t, "revocation_tip", a, v)
		if v.OK || v.Rejection != string(RejectRevoked) {
			t.Fatalf("revocation tip must reject with RejectRevoked: OK=%v rej=%q", v.OK, v.Rejection)
		}
	})

	// SUCCESSION tip: the newest by-DID row is a succession. AuthorityResolver
	// routes succession to RejectRevoked; the index marks it not-live. Parity.
	t.Run("succession_tip", func(t *testing.T) {
		fx := newParityFixture(parLog, parJ)
		_, judgeBytes := makeDelegation(t,
			types.LogPosition{LogDID: parLog, Sequence: 100},
			parAuth, parJ, "officer", []string{"civil"}, nil, time.Hour)
		judgeRef := fx.add(types.LogPosition{LogDID: parLog, Sequence: 100}, parJ, judgeBytes)
		succBytes := makeSuccession(t, parAuth, "did:web:successor", judgeRef)
		fx.signerRef = fx.add(types.LogPosition{LogDID: parLog, Sequence: 300}, parJ, succBytes)

		a, v := fx.runBoth(t)
		assertParity(t, "succession_tip", a, v)
		if v.OK || v.Rejection != string(RejectRevoked) {
			t.Fatalf("succession tip must reject with RejectRevoked: OK=%v rej=%q", v.OK, v.Rejection)
		}
	})

	// EXPIRED tip: a live grant whose expires_at is in the past. Both engines
	// reject with RejectExpired.
	t.Run("expired_tip", func(t *testing.T) {
		fx := newParityFixture(parLog, parJ)
		_, authBytes := makeDelegation(t,
			types.LogPosition{LogDID: parLog, Sequence: 50},
			parRoot, parAuth, "presiding", []string{"civil"}, nil, time.Hour)
		authRef := fx.add(types.LogPosition{LogDID: parLog, Sequence: 50}, parAuth, authBytes)
		_, judgeBytes := makeDelegation(t,
			types.LogPosition{LogDID: parLog, Sequence: 100},
			parAuth, parJ, "officer", []string{"civil"}, &authRef, -time.Hour)
		fx.signerRef = fx.add(types.LogPosition{LogDID: parLog, Sequence: 100}, parJ, judgeBytes)

		a, v := fx.runBoth(t)
		assertParity(t, "expired_tip", a, v)
		if v.OK || v.Rejection != string(RejectExpired) {
			t.Fatalf("expired tip must reject with RejectExpired: OK=%v rej=%q", v.OK, v.Rejection)
		}
	})

	// NO DELEGATION: signer has no incoming grant. Both reject (the index uses
	// RejectMissingChainTip — the same token AuthorityResolver uses for an
	// absent chain tip).
	t.Run("no_delegation", func(t *testing.T) {
		fx := newParityFixture(parLog, "did:web:nobody")
		// signerRef left zero — AuthorityResolver: missing_chain_tip.
		a, v := fx.runBoth(t)
		assertParity(t, "no_delegation", a, v)
		if v.OK {
			t.Fatalf("a signer with no delegation must not resolve OK")
		}
	})
}
