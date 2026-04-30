/*
FILE PATH: tests/contracts/delegation_helpers_test.go

DESCRIPTION:
    Shared fixture for the Phase 2C delegation-flow contract tests.
    Wires the unified judicial-delegation-v1 schema, the
    IdentityProvider stub, the role catalog, the AuthorityResolver,
    the Issue / Revoke / Succeed builders, and the OfficerRegistry
    into one test harness so the integration tests below can exercise
    the full hierarchy / succession / revocation lifecycles end-to-end.

OVERVIEW:
    operatorBackend  — both an OperatorSubmitter (delegation/builders)
                       and a types.EntryFetcher (verification),
                       sharing one in-memory store so submitted bytes
                       round-trip through the resolver.
    leafBackend      — synthetic smt.LeafReader that surfaces
                       OriginTip per leaf for succession / revocation
                       tests.
    contractFixture  — the bag of dependencies a test grabs in one
                       call.

KEY DEPENDENCIES:
    - api/exchange/identity (StubProvider).
    - schemas (RoleCatalog).
    - delegation (BuildContext, Issue/Revoke/Succeed).
    - directory (OfficerRegistry).
    - verification (AuthorityResolver).
*/
package contracts

import (
	"context"
	"sync"
	"testing"

	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
	"github.com/clearcompass-ai/judicial-network/delegation"
	davidson "github.com/clearcompass-ai/judicial-network/deployments/davidson_county/rules"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/verification"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ─── operatorBackend: Submitter + Fetcher in one ────────────────────

type operatorBackend struct {
	mu      sync.RWMutex
	logDID  string
	bySeq   map[uint64][]byte
	nextSeq uint64
}

func newOperatorBackend(logDID string) *operatorBackend {
	return &operatorBackend{
		logDID: logDID,
		bySeq:  make(map[uint64][]byte),
	}
}

// SubmitCanonical assigns a sequence and stores the canonical bytes.
func (b *operatorBackend) SubmitCanonical(ctx context.Context, canonical []byte) (schemas.LogPositionRef, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextSeq++
	stored := append([]byte(nil), canonical...)
	b.bySeq[b.nextSeq] = stored
	return schemas.LogPositionRef{LogDID: b.logDID, Sequence: b.nextSeq}, nil
}

// Fetch returns the EntryWithMetadata for an earlier-submitted
// position. Returns (nil, nil) on miss per the SDK contract.
func (b *operatorBackend) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if pos.LogDID != b.logDID {
		return nil, nil
	}
	by, ok := b.bySeq[pos.Sequence]
	if !ok {
		return nil, nil
	}
	return &types.EntryWithMetadata{CanonicalBytes: by}, nil
}

// ─── leafBackend: synthetic LeafReader ──────────────────────────────

type leafBackend struct {
	mu  sync.RWMutex
	tip map[[32]byte]types.LogPosition
}

func newLeafBackend() *leafBackend {
	return &leafBackend{tip: make(map[[32]byte]types.LogPosition)}
}

func (l *leafBackend) setTip(forPos types.LogPosition, tip types.LogPosition) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tip[smt.DeriveKey(forPos)] = tip
}

func (l *leafBackend) Get(key [32]byte) (*types.SMTLeaf, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	t, ok := l.tip[key]
	if !ok {
		return nil, nil
	}
	return &types.SMTLeaf{OriginTip: t}, nil
}

// ─── contractFixture ────────────────────────────────────────────────

// contractFixture wires the full Phase 2C dependency graph in one
// place. Each test grabs one via newFixture(t), drives Issue calls,
// and then asks the resolver to verify or rejects.
type contractFixture struct {
	logDID           string
	exchangeDID      string
	institutionalDID string

	identity     *identity.StubProvider
	operator     *operatorBackend
	leafs        *leafBackend
	catalog      schemas.RoleCatalog
	roleResolver *verification.MapRoleResolver
	resolver     *verification.AuthorityResolver
	buildCtx     *delegation.BuildContext

	// keys maps a DID to the secp256k1 key bound on the stub.
	// Tests can re-use these; the helper provisionKey makes more.
	keys map[string]*secp256k1.PrivateKey
}

func newFixture(t *testing.T) *contractFixture {
	t.Helper()
	const (
		logDID           = "did:web:da:davidson-tn"
		exchangeDID      = "did:web:da:davidson-tn"
		institutionalDID = "did:web:da:davidson-tn"
	)

	sp := identity.NewStubProvider()
	op := newOperatorBackend(logDID)
	lb := newLeafBackend()
	cat := davidson.MustRoleCatalog()

	bc := &delegation.BuildContext{
		Identity:         sp,
		Submitter:        op,
		Catalog:          cat,
		ExchangeDID:      exchangeDID,
		InstitutionalDID: institutionalDID,
	}
	res := &verification.AuthorityResolver{
		Fetcher:    op,
		LeafReader: lb,
		Catalog:    cat,
	}
	return &contractFixture{
		logDID:           logDID,
		exchangeDID:      exchangeDID,
		institutionalDID: institutionalDID,
		identity:         sp,
		operator:         op,
		leafs:            lb,
		catalog:          cat,
		roleResolver:     verification.NewMapRoleResolver(),
		resolver:         res,
		buildCtx:         bc,
		keys:             make(map[string]*secp256k1.PrivateKey),
	}
}

// provisionKey generates a secp256k1 key, binds it on the
// IdentityProvider stub, and remembers it for later assertions.
// Returns the bound DID.
func (f *contractFixture) provisionKey(t *testing.T, did string) string {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	f.keys[did] = priv
	f.identity.BindKey(did, priv)
	return did
}

// issue is a thin wrapper that drives delegation.Issue and binds
// the new grantee in the role resolver so cosignature checks can
// look them up by DID. Returns the assigned LogPositionRef.
func (f *contractFixture) issue(t *testing.T, req delegation.IssueRequest) schemas.LogPositionRef {
	t.Helper()
	res, err := delegation.Issue(context.Background(), f.buildCtx, req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	f.roleResolver.Bind(req.GranteeDID, req.GranteeRole, f.institutionalDID)
	return res.Position
}

// resolve is a thin wrapper around verification.AuthorityResolver.Resolve
// for assertion clarity in tests.
func (f *contractFixture) resolve(signerDID string, ref schemas.LogPositionRef, action string) *verification.Authority {
	return f.resolver.Resolve(signerDID, ref, action)
}

// envelopeAt fetches and deserializes the entry at pos. Used by
// tests that want to inspect on-log structure (signer, target_root).
func (f *contractFixture) envelopeAt(t *testing.T, pos schemas.LogPositionRef) *envelope.Entry {
	t.Helper()
	meta, err := f.operator.Fetch(types.LogPosition{LogDID: pos.LogDID, Sequence: pos.Sequence})
	if err != nil {
		t.Fatalf("operator.Fetch: %v", err)
	}
	if meta == nil {
		t.Fatalf("no entry at %s#%d", pos.LogDID, pos.Sequence)
	}
	e, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	return e
}
