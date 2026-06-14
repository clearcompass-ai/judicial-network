package verification

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── Test helpers ────────────────────────────────────────────

// signedEntryWithPayload builds + signs an entry whose Header.SignerDID ==
// signer, carrying the given domain payload. Returns canonical bytes ready to
// be returned by a fake EntryFetcher.
func signedEntryWithPayload(t *testing.T, signer string, payload []byte) []byte {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     signer,
		Destination:   "did:web:dst",
		AuthorityPath: &auth,
	}, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hash := sha256.Sum256(envelope.SigningPayload(unsigned))
	sigBytes, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	signed, err := envelope.NewEntry(unsigned.Header, unsigned.DomainPayload, []envelope.Signature{
		{SignerDID: signer, AlgoID: envelope.SigAlgoECDSA, Bytes: sigBytes},
	})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	raw, err := envelope.Serialize(signed)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return raw
}

// signedDelegationBytes is a minimal live delegation grant (no schema_id, so
// classifyTip reads it as a normal grant — live).
func signedDelegationBytes(t *testing.T, delegator string) []byte {
	t.Helper()
	return signedEntryWithPayload(t, delegator, []byte(`{"role":"judicial"}`))
}

// signedRevocationBytes is a revocation tip — the newest-grant-wins signal the
// delegate_did index surfaces (#120). classifyTip routes it to RejectRevoked,
// so the resolver must mark the hop not-live.
func signedRevocationBytes(t *testing.T, signer string) []byte {
	t.Helper()
	return signedEntryWithPayload(t, signer,
		[]byte(fmt.Sprintf(`{"schema_id":%q}`, schemas.SchemaJudicialRevocationV1)))
}

// fakeDelegateQuerier returns a fixed (did → entries) mapping. The
// per-did entries are returned newest-first (DESC by sequence).
type fakeDelegateQuerier struct {
	byDID map[string][]types.EntryWithMetadata
	calls int
	err   error
}

func (f *fakeDelegateQuerier) QueryByDelegateDID(_ context.Context, did string) ([]types.EntryWithMetadata, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.byDID[did], nil
}

// delegFakeFetcher hydrates by mapping LogPosition.Sequence to bytes.
// Distinct from fakeFetcher in authority_resolver_helpers_test.go.
type delegFakeFetcher struct {
	bySeq map[uint64][]byte
	calls int
	err   error
}

func (f *delegFakeFetcher) Fetch(_ context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.bySeq[pos.Sequence]
	if !ok {
		return nil, fmt.Errorf("fake fetcher: no entry at %d", pos.Sequence)
	}
	return &types.EntryWithMetadata{
		Position:       pos,
		CanonicalBytes: b,
		LogTime:        time.Unix(1700000000, 0).UTC(),
	}, nil
}

// ─── Tests ─────────────────────────────────────────────────

func TestLedgerDelegationResolver_TwoHopChain(t *testing.T) {
	// Chain: did:web:judge --(delegated by)--> did:web:authority -->
	// did:web:root. Each hop's signer is the next-level delegator.
	rootBytes := signedDelegationBytes(t, "did:web:root")
	authBytes := signedDelegationBytes(t, "did:web:authority")

	delegate := &fakeDelegateQuerier{
		byDID: map[string][]types.EntryWithMetadata{
			"did:web:judge": {
				{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 100}},
			},
			"did:web:authority": {
				{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 50}},
			},
			// did:web:root has no incoming delegation — chain ends.
		},
	}
	fetcher := &delegFakeFetcher{bySeq: map[uint64][]byte{
		100: authBytes, // judge's delegation is signed by authority
		50:  rootBytes, // authority's delegation is signed by root
	}}

	r, err := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: delegate, Fetcher: fetcher, LogDID: "did:web:l",
	})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	chain, err := r.ResolveChain(context.Background(), "did:web:judge")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(chain.Hops) != 2 {
		t.Fatalf("Hops = %d, want 2", len(chain.Hops))
	}
	if chain.Hops[0].DelegateDID != "did:web:judge" {
		t.Errorf("Hops[0].DelegateDID = %q", chain.Hops[0].DelegateDID)
	}
	if chain.Hops[0].DelegatorDID != "did:web:authority" {
		t.Errorf("Hops[0].DelegatorDID = %q", chain.Hops[0].DelegatorDID)
	}
	if chain.Hops[1].DelegateDID != "did:web:authority" {
		t.Errorf("Hops[1].DelegateDID = %q", chain.Hops[1].DelegateDID)
	}
	if chain.Hops[1].DelegatorDID != "did:web:root" {
		t.Errorf("Hops[1].DelegatorDID = %q", chain.Hops[1].DelegatorDID)
	}
	for i, h := range chain.Hops {
		if !h.Live {
			t.Errorf("Hops[%d].Live = false, want true", i)
		}
	}
	if chain.OriginDID() != "did:web:root" {
		t.Errorf("OriginDID = %q, want did:web:root", chain.OriginDID())
	}
}

func TestLedgerDelegationResolver_RootHasNoIncoming(t *testing.T) {
	delegate := &fakeDelegateQuerier{byDID: map[string][]types.EntryWithMetadata{
		// did:web:root has no delegation entry — empty result
	}}
	fetcher := &delegFakeFetcher{bySeq: map[uint64][]byte{}}

	r, _ := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: delegate, Fetcher: fetcher, LogDID: "did:web:l",
	})
	chain, err := r.ResolveChain(context.Background(), "did:web:root")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(chain.Hops) != 0 {
		t.Errorf("Hops = %d, want 0 (root)", len(chain.Hops))
	}
}

func TestLedgerDelegationResolver_EmptyDID(t *testing.T) {
	r, _ := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: &fakeDelegateQuerier{},
		Fetcher:  &delegFakeFetcher{},
		LogDID:   "did:web:l",
	})
	chain, err := r.ResolveChain(context.Background(), "")
	if err != nil {
		t.Errorf("empty did should not error, got %v", err)
	}
	if len(chain.Hops) != 0 {
		t.Errorf("Hops = %d, want 0", len(chain.Hops))
	}
}

func TestLedgerDelegationResolver_Cycle(t *testing.T) {
	// A → B → A (cycle). Resolver must stop after one revisit.
	bBytes := signedDelegationBytes(t, "did:web:B")
	aBytes := signedDelegationBytes(t, "did:web:A")
	delegate := &fakeDelegateQuerier{byDID: map[string][]types.EntryWithMetadata{
		"did:web:A": {{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 1}}},
		"did:web:B": {{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 2}}},
	}}
	fetcher := &delegFakeFetcher{bySeq: map[uint64][]byte{
		1: bBytes, // A's delegation signed by B
		2: aBytes, // B's delegation signed by A → cycle
	}}
	r, _ := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: delegate, Fetcher: fetcher, LogDID: "did:web:l",
		MaxDepth: 10, // generous; cycle detection kicks in first
	})
	chain, err := r.ResolveChain(context.Background(), "did:web:A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Cycle: A's chain visits A then B then bumps into A again →
	// 2 hops emitted, then the cycle guard breaks the loop.
	if len(chain.Hops) != 2 {
		t.Errorf("Hops = %d, want 2 (cycle short-circuit)", len(chain.Hops))
	}
}

func TestLedgerDelegationResolver_DepthBound(t *testing.T) {
	// Chain: 0 → 1 → 2 → ... (never terminates). MaxDepth=3 should
	// cut at 3 hops.
	delegate := &fakeDelegateQuerier{byDID: map[string][]types.EntryWithMetadata{}}
	fetcher := &delegFakeFetcher{bySeq: map[uint64][]byte{}}
	for i := 0; i < 10; i++ {
		did := fmt.Sprintf("did:web:n%d", i)
		next := fmt.Sprintf("did:web:n%d", i+1)
		delegate.byDID[did] = []types.EntryWithMetadata{
			{Position: types.LogPosition{LogDID: "did:web:l", Sequence: uint64(i + 1)}},
		}
		fetcher.bySeq[uint64(i+1)] = signedDelegationBytes(t, next)
	}
	r, _ := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: delegate, Fetcher: fetcher, LogDID: "did:web:l",
		MaxDepth: 3,
	})
	chain, err := r.ResolveChain(context.Background(), "did:web:n0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(chain.Hops) != 3 {
		t.Errorf("Hops = %d, want 3 (depth bound)", len(chain.Hops))
	}
}

func TestLedgerDelegationResolver_CacheHit(t *testing.T) {
	// One hop: judge ← root at seq 1. The per-hop cache skips the HYDRATE
	// (fetcher) on an unchanged per-DID watermark, while the cheap
	// QueryByDelegateDID revalidation seek still runs every resolve — so the
	// walk is always current-to-commit, never a stale whole-chain hit.
	rootBytes := signedDelegationBytes(t, "did:web:root")
	delegate := &fakeDelegateQuerier{byDID: map[string][]types.EntryWithMetadata{
		"did:web:judge": {{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 1}}},
	}}
	fetcher := &delegFakeFetcher{bySeq: map[uint64][]byte{1: rootBytes}}
	r, _ := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: delegate, Fetcher: fetcher, LogDID: "did:web:l",
	})

	if _, err := r.ResolveChain(context.Background(), "did:web:judge"); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	fetchAfterFirst := fetcher.calls
	queriesAfterFirst := delegate.calls

	// Watermark unchanged → hydration SKIPPED (cache hit), but the
	// revalidation query still happens.
	if _, err := r.ResolveChain(context.Background(), "did:web:judge"); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if fetcher.calls != fetchAfterFirst {
		t.Errorf("unchanged watermark must skip hydration: fetcher calls grew %d→%d",
			fetchAfterFirst, fetcher.calls)
	}
	if delegate.calls <= queriesAfterFirst {
		t.Errorf("every resolve must re-query for revalidation: queries %d→%d",
			queriesAfterFirst, delegate.calls)
	}

	// Watermark advances (a new grant at seq 2 supersedes) → re-hydrate.
	delegate.byDID["did:web:judge"] = []types.EntryWithMetadata{
		{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 2}},
	}
	fetcher.bySeq[2] = signedDelegationBytes(t, "did:web:root2")
	if _, err := r.ResolveChain(context.Background(), "did:web:judge"); err != nil {
		t.Fatalf("post-change Resolve: %v", err)
	}
	if fetcher.calls <= fetchAfterFirst {
		t.Errorf("a moved watermark must re-hydrate: fetcher calls=%d, want > %d",
			fetcher.calls, fetchAfterFirst)
	}
}

// TestLedgerDelegationResolver_NewestGrantWins pins the no-fallback liveness:
// when the newest delegate_did row for a DID is a revocation (the index
// surfaces it, #120), the hop is NOT live and the chain ends there — without
// any SMT read. This is the fix for the old hardcoded Live:true fail-open.
func TestLedgerDelegationResolver_NewestGrantWins(t *testing.T) {
	revBytes := signedRevocationBytes(t, "did:web:authority")
	delegate := &fakeDelegateQuerier{byDID: map[string][]types.EntryWithMetadata{
		"did:web:judge": {{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 5}}},
	}}
	fetcher := &delegFakeFetcher{bySeq: map[uint64][]byte{5: revBytes}}
	r, _ := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: delegate, Fetcher: fetcher, LogDID: "did:web:l",
	})
	chain, err := r.ResolveChain(context.Background(), "did:web:judge")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(chain.Hops) != 1 {
		t.Fatalf("Hops = %d, want 1 (the revoked hop, chain ends)", len(chain.Hops))
	}
	if chain.Hops[0].Live {
		t.Error("a revocation tip must yield a NOT-live hop (newest-grant-wins, no SMT)")
	}
}

func TestLedgerDelegationResolver_DelegateErrorPropagates(t *testing.T) {
	delegate := &fakeDelegateQuerier{err: errors.New("ledger down")}
	r, _ := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: delegate, Fetcher: &delegFakeFetcher{}, LogDID: "did:web:l",
	})
	_, err := r.ResolveChain(context.Background(), "did:web:judge")
	if !errors.Is(err, ErrLedgerDelegationResolver) {
		t.Errorf("err should wrap ErrLedgerDelegationResolver, got %v", err)
	}
}

func TestLedgerDelegationResolver_ScopeExtractor(t *testing.T) {
	rootBytes := signedDelegationBytes(t, "did:web:root")
	delegate := &fakeDelegateQuerier{byDID: map[string][]types.EntryWithMetadata{
		"did:web:judge": {{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 1}}},
	}}
	fetcher := &delegFakeFetcher{bySeq: map[uint64][]byte{1: rootBytes}}
	r, _ := NewLedgerDelegationResolver(LedgerDelegationResolverConfig{
		Delegate: delegate, Fetcher: fetcher, LogDID: "did:web:l",
		Scope: func(_ *envelope.Entry) []string { return []string{"civil", "criminal"} },
	})
	chain, err := r.ResolveChain(context.Background(), "did:web:judge")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(chain.Hops) != 1 {
		t.Fatalf("Hops = %d, want 1", len(chain.Hops))
	}
	want := []string{"civil", "criminal"}
	if len(chain.Hops[0].Scopes) != 2 || chain.Hops[0].Scopes[0] != want[0] || chain.Hops[0].Scopes[1] != want[1] {
		t.Errorf("Scopes = %v, want %v", chain.Hops[0].Scopes, want)
	}
}

func TestLedgerDelegationResolver_CtorValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  LedgerDelegationResolverConfig
	}{
		{"missing delegate", LedgerDelegationResolverConfig{Fetcher: &delegFakeFetcher{}, LogDID: "x"}},
		{"missing fetcher", LedgerDelegationResolverConfig{Delegate: &fakeDelegateQuerier{}, LogDID: "x"}},
		{"missing logDID", LedgerDelegationResolverConfig{Delegate: &fakeDelegateQuerier{}, Fetcher: &delegFakeFetcher{}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewLedgerDelegationResolver(c.cfg)
			if !errors.Is(err, ErrLedgerDelegationResolver) {
				t.Errorf("err = %v, want errors.Is(ErrLedgerDelegationResolver)", err)
			}
		})
	}
}
