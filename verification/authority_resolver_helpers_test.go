/*
FILE PATH: verification/authority_resolver_helpers_test.go

DESCRIPTION:
    Shared test helpers for the AuthorityResolver test package:
    fakeFetcher, position keys, canonical envelope builders, and
    delegation/revocation payload factories. Pulled out of
    authority_resolver_test.go so the test files can stay under the
    source-file line cap.
*/
package verification

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─── fakes ──────────────────────────────────────────────────────────

type fakeFetcher struct {
	entries map[string][]byte // keyed by "logDID|seq" → canonical bytes
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{entries: make(map[string][]byte)}
}

func (f *fakeFetcher) put(pos types.LogPosition, canonical []byte) {
	f.entries[posKey(pos)] = canonical
}

func (f *fakeFetcher) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	by, ok := f.entries[posKey(pos)]
	if !ok {
		return nil, nil
	}
	return &types.EntryWithMetadata{CanonicalBytes: by}, nil
}

func posKey(pos types.LogPosition) string {
	return pos.LogDID + "|" + intToStr(pos.Sequence)
}

func intToStr(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// ─── envelope + payload builders ────────────────────────────────────

// canonicalEntry wraps the given DomainPayload in a valid SDK envelope
// with a single (synthetic) signature so envelope.Serialize produces
// canonical bytes the resolver's deserialize path accepts.
func canonicalEntry(t *testing.T, signerDID string, payload []byte) []byte {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	header := envelope.ControlHeader{
		Destination:   "did:web:test.exchange",
		SignerDID:     signerDID,
		AuthorityPath: &auth,
	}
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: signerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry validate: %v", err)
	}
	return envelope.Serialize(entry)
}

// canonicalEntryWithTarget is canonicalEntry with TargetRoot set,
// used to build envelopes EvaluateOrigin classifies as Revoked
// (target points to a different entity than the leaf's key).
func canonicalEntryWithTarget(t *testing.T, signerDID string, payload []byte, target *types.LogPosition) []byte {
	t.Helper()
	auth := envelope.AuthorityScopeAuthority
	priorAuth := types.LogPosition{LogDID: signerDID, Sequence: 0}
	header := envelope.ControlHeader{
		Destination:    "did:web:test.exchange",
		SignerDID:      signerDID,
		AuthorityPath:  &auth,
		TargetRoot:     target,
		PriorAuthority: &priorAuth,
	}
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry (with target): %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: signerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry validate (with target): %v", err)
	}
	return envelope.Serialize(entry)
}

// makeDelegation creates a delegation entry's canonical bytes at the
// given position and returns the LogPositionRef the next hop refers
// back to. Negative expiresIn skips the issued<expires Validate gate
// (used by the expiration test); the resolver still rejects on its
// own clock-based check.
func makeDelegation(
	t *testing.T,
	pos types.LogPosition,
	granter, grantee, role string,
	scope []string,
	parent *schemas.LogPositionRef,
	expiresIn time.Duration,
) (schemas.LogPositionRef, []byte) {
	t.Helper()
	now := time.Now().UTC()
	issued := now
	if expiresIn <= 0 {
		// Pre-date issued so payload Validate passes; the resolver
		// then sees an expires_at in the past relative to its clock.
		issued = now.Add(2 * expiresIn)
	}
	p := &schemas.JudicialDelegationPayload{
		SchemaID:             schemas.SchemaJudicialDelegationV1,
		GranterDID:           granter,
		GranteeDID:           grantee,
		Role:                 role,
		Scope:                scope,
		ExpiresAt:            now.Add(expiresIn).Format(time.RFC3339Nano),
		IssuedAt:             issued.Format(time.RFC3339Nano),
		GranterDelegationRef: parent,
	}
	by, err := schemas.MarshalJudicialDelegationPayload(p)
	if err != nil {
		t.Fatalf("marshal delegation: %v", err)
	}
	return schemas.LogPositionRef{LogDID: pos.LogDID, Sequence: pos.Sequence}, canonicalEntry(t, granter, by)
}

// makeRevocation creates a revocation entry's canonical bytes.
func makeRevocation(t *testing.T, signerDID string, target schemas.LogPositionRef) []byte {
	t.Helper()
	return canonicalEntry(t, signerDID, makeRevocationPayload(t, target))
}

// makeRevocationPayload returns just the JSON payload for a
// revocation entry — used by tests that need to embed the payload
// in a non-default envelope (e.g. with a TargetRoot for origin
// evaluation tests).
func makeRevocationPayload(t *testing.T, target schemas.LogPositionRef) []byte {
	t.Helper()
	p := &schemas.JudicialRevocationPayload{
		SchemaID:         schemas.SchemaJudicialRevocationV1,
		TargetDelegation: target,
		Reason:           "performance",
		RevokedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	by, err := schemas.MarshalJudicialRevocationPayload(p)
	if err != nil {
		t.Fatalf("marshal revocation: %v", err)
	}
	return by
}
