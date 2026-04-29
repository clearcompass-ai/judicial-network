/*
FILE PATH: verification/delegation_chain_test.go

COVERAGE:
    Two-phase verification — cryptographic (Phase 1) and semantic
    (Phase 2). Tests cover: empty chain, dead delegation surfaces in
    FirstDead, optional ScopeEnforcer (nil keeps Phase-1-only),
    semantic scope violation surfaces in ScopeViolation, and the
    short-circuit that prevents Phase 2 from running when Phase 1
    fails.
*/
package verification

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/internal/testutil"
)

// ─── In-memory stub LeafReader (returns OriginTip equal to position
// so the SDK's liveness check passes) ───────────────────────────────

type liveLeafReader struct{}

func (liveLeafReader) Get(key [32]byte) (*types.SMTLeaf, error) {
	// Return a leaf whose OriginTip equals the position the SMT
	// derives the key from. Since smt.DeriveKey(pos) is what the SDK
	// uses, returning a leaf with OriginTip=anyPos here is enough
	// for the SDK's "OriginTip == pos" liveness check IF callers
	// derive keys from the same positions. The stub returns nil for
	// unknown keys, which the SDK treats as "not live."
	return nil, nil
}

// liveSMTFor returns a LeafReader that reports every supplied
// position as live (OriginTip == position).
func liveSMTFor(positions ...types.LogPosition) smt.LeafReader {
	store := smt.NewInMemoryLeafStore()
	for _, p := range positions {
		key := smt.DeriveKey(p)
		_ = store.Set(key, types.SMTLeaf{OriginTip: p, AuthorityTip: p})
	}
	return store
}

// deadSMTFor reports the first position as live but the second as
// revoked (OriginTip != position).
func deadSMTFor(live, dead types.LogPosition) smt.LeafReader {
	store := smt.NewInMemoryLeafStore()
	_ = store.Set(smt.DeriveKey(live), types.SMTLeaf{OriginTip: live, AuthorityTip: live})
	// Dead leaf: OriginTip points elsewhere — different sequence — to
	// signal revocation/supersession.
	supersededTo := types.LogPosition{LogDID: dead.LogDID, Sequence: dead.Sequence + 100}
	_ = store.Set(smt.DeriveKey(dead), types.SMTLeaf{
		OriginTip:    supersededTo,
		AuthorityTip: supersededTo,
	})
	return store
}

// fetcherFromEntries fetches by exact LogPosition match.
type fetcherFromEntries map[types.LogPosition]*types.EntryWithMetadata

func (f fetcherFromEntries) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	if e, ok := f[pos]; ok {
		return e, nil
	}
	return nil, nil
}

func mkDelegation(t *testing.T, signerDID, delegateDID, scopeJSON string) *envelope.Entry {
	t.Helper()
	entry, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   signerDID,
		DelegateDID: delegateDID,
		Payload:     []byte(scopeJSON),
	})
	if err != nil {
		t.Fatalf("BuildDelegation: %v", err)
	}
	return entry
}

// ─── Phase 1: empty chain ───────────────────────────────────────────

func TestVerifyFilingDelegation_EmptyChain_AllPhasesOK(t *testing.T) {
	res, err := VerifyFilingDelegation(nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.AllLive {
		t.Error("AllLive must be true for empty chain")
	}
	if res.Depth != 0 {
		t.Errorf("Depth = %d, want 0", res.Depth)
	}
}

func TestVerifyFilingDelegation_EmptyChain_WithEnforcer_ReportsScopeChecked(t *testing.T) {
	enf := &ScopeEnforcer{}
	target := &envelope.Entry{Header: envelope.ControlHeader{}}
	res, err := VerifyFilingDelegation(nil, nil, nil, enf, target)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.ScopeChecked || !res.ScopeOK {
		t.Errorf("expected scope vacuously OK on empty chain: %+v", res)
	}
}

// ─── Phase 1 short-circuit when leafReader is unhappy ───────────────

func TestVerifyFilingDelegation_NoEnforcer_OnlyPhase1Runs(t *testing.T) {
	// Build a valid delegation chain of depth 1.
	courtDID := "did:web:courts.test.gov"
	delegate := "did:web:judge"
	delEntry := mkDelegation(t, courtDID, delegate, `{}`)
	signed := testutil.SignEntry(t, delEntry, testutil.GenerateSigningKey(t))
	delPos := types.LogPosition{LogDID: "did:web:l", Sequence: 50}

	fetcher := fetcherFromEntries{
		delPos: {Position: delPos, CanonicalBytes: envelope.Serialize(signed)},
	}
	reader := liveSMTFor(delPos)

	res, err := VerifyFilingDelegation([]types.LogPosition{delPos}, fetcher, reader, nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.ScopeChecked {
		t.Error("ScopeChecked must be false when no enforcer is supplied")
	}
}

// ─── Phase 1 + Phase 2 happy path ───────────────────────────────────

func TestVerifyFilingDelegation_BothPhases_HappyPath(t *testing.T) {
	courtDID := "did:web:courts.test.gov"
	delegate := "did:web:judge"
	delEntry := mkDelegation(t, courtDID, delegate, `{"scope_limit":["tn-criminal-case-v1"]}`)
	signed := testutil.SignEntry(t, delEntry, testutil.GenerateSigningKey(t))
	delPos := types.LogPosition{LogDID: "did:web:l", Sequence: 50}
	schemaPos := types.LogPosition{LogDID: "did:web:l", Sequence: 99}

	fetcher := fetcherFromEntries{
		delPos: {Position: delPos, CanonicalBytes: envelope.Serialize(signed)},
	}
	reader := liveSMTFor(delPos)

	target := &envelope.Entry{Header: envelope.ControlHeader{
		SchemaRef:          &schemaPos,
		DelegationPointers: []types.LogPosition{delPos},
	}}
	enf := &ScopeEnforcer{
		Fetcher:        fetcher,
		SchemaResolver: func(types.LogPosition) (string, error) { return "tn-criminal-case-v1", nil },
	}
	res, err := VerifyFilingDelegation([]types.LogPosition{delPos}, fetcher, reader, enf, target)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.AllLive {
		t.Errorf("AllLive false: hops=%+v", res.Hops)
	}
	if !res.ScopeChecked || !res.ScopeOK {
		t.Errorf("scope phase failed: %+v", res)
	}
}

// ─── Phase 2 surfaces *ScopeViolation rather than error ─────────────

func TestVerifyFilingDelegation_ScopeViolation_ReturnsViolationFlag(t *testing.T) {
	courtDID := "did:web:courts.test.gov"
	delegate := "did:web:exchange:scheduler"
	delEntry := mkDelegation(t, courtDID, delegate, `{"scope_limit":["daily_assignment"]}`)
	signed := testutil.SignEntry(t, delEntry, testutil.GenerateSigningKey(t))
	delPos := types.LogPosition{LogDID: "did:web:l", Sequence: 51}
	schemaPos := types.LogPosition{LogDID: "did:web:l", Sequence: 100}

	fetcher := fetcherFromEntries{
		delPos: {Position: delPos, CanonicalBytes: envelope.Serialize(signed)},
	}
	reader := liveSMTFor(delPos)

	target := &envelope.Entry{Header: envelope.ControlHeader{
		SchemaRef:          &schemaPos,
		DelegationPointers: []types.LogPosition{delPos},
	}}
	enf := &ScopeEnforcer{
		Fetcher:        fetcher,
		SchemaResolver: func(types.LogPosition) (string, error) { return "tn-sealing-order-v1", nil },
	}
	res, err := VerifyFilingDelegation([]types.LogPosition{delPos}, fetcher, reader, enf, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.ScopeChecked {
		t.Error("ScopeChecked should be true")
	}
	if res.ScopeOK {
		t.Error("ScopeOK should be false")
	}
	if res.ScopeViolation == nil {
		t.Fatal("ScopeViolation must be populated")
	}
	if res.ScopeViolation.DelegateDID != delegate {
		t.Errorf("DelegateDID = %q", res.ScopeViolation.DelegateDID)
	}
}

// ─── Phase 1 short-circuits Phase 2 when chain is dead ──────────────

func TestVerifyFilingDelegation_DeadHop_Phase2Skipped(t *testing.T) {
	courtDID := "did:web:courts.test.gov"
	delegate := "did:web:judge"
	delEntry := mkDelegation(t, courtDID, delegate, `{"scope_limit":["x"]}`) // would violate if reached
	signed := testutil.SignEntry(t, delEntry, testutil.GenerateSigningKey(t))
	delPos := types.LogPosition{LogDID: "did:web:l", Sequence: 50}
	schemaPos := types.LogPosition{LogDID: "did:web:l", Sequence: 99}

	fetcher := fetcherFromEntries{
		delPos: {Position: delPos, CanonicalBytes: envelope.Serialize(signed)},
	}
	// Dead reader: pretend the leaf is revoked (OriginTip != delPos).
	reader := deadSMTFor(types.LogPosition{LogDID: "did:web:l", Sequence: 1}, delPos)

	target := &envelope.Entry{Header: envelope.ControlHeader{
		SchemaRef:          &schemaPos,
		DelegationPointers: []types.LogPosition{delPos},
	}}
	enf := &ScopeEnforcer{
		Fetcher:        fetcher,
		SchemaResolver: func(types.LogPosition) (string, error) { return "tn-criminal-case-v1", nil },
	}
	res, err := VerifyFilingDelegation([]types.LogPosition{delPos}, fetcher, reader, enf, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.AllLive {
		t.Error("AllLive must be false (dead hop)")
	}
	if res.ScopeChecked {
		t.Error("ScopeChecked must be false (Phase 2 short-circuited)")
	}
	if res.FirstDead == nil {
		t.Error("FirstDead must be populated when AllLive is false")
	}
}

// errFetcher returns an error on every Fetch. The SDK's
// VerifyDelegationProvenance, at the pinned commit, swallows fetcher
// errors and reports IsLive=false on the affected hop rather than
// surfacing them as a return error. The test confirms our wrapper
// degrades to AllLive=false rather than panicking or hanging.
type errFetcher struct{ msg string }

func (e errFetcher) Fetch(types.LogPosition) (*types.EntryWithMetadata, error) {
	return nil, errors.New(e.msg)
}

func TestVerifyFilingDelegation_Phase1FetcherError_DegradesToDead(t *testing.T) {
	reader := liveSMTFor()
	res, err := VerifyFilingDelegation(
		[]types.LogPosition{{LogDID: "did:web:l", Sequence: 1}},
		errFetcher{msg: "infra down"}, reader, nil, nil,
	)
	if err != nil {
		t.Fatalf("unexpected wrapper error: %v", err)
	}
	if res.AllLive {
		t.Error("AllLive must be false when every fetch errors")
	}
}

// ─── Phase 2 unwrapped error (non-ScopeViolation) propagates ────────

func TestVerifyFilingDelegation_Phase2InfraError_Returned(t *testing.T) {
	courtDID := "did:web:courts.test.gov"
	delegate := "did:web:judge"
	delEntry := mkDelegation(t, courtDID, delegate, `{}`)
	signed := testutil.SignEntry(t, delEntry, testutil.GenerateSigningKey(t))
	delPos := types.LogPosition{LogDID: "did:web:l", Sequence: 50}
	schemaPos := types.LogPosition{LogDID: "did:web:l", Sequence: 99}

	fetcher := fetcherFromEntries{
		delPos: {Position: delPos, CanonicalBytes: envelope.Serialize(signed)},
	}
	reader := liveSMTFor(delPos)

	target := &envelope.Entry{Header: envelope.ControlHeader{
		SchemaRef:          &schemaPos,
		DelegationPointers: []types.LogPosition{delPos},
	}}
	// Resolver returns infra error → Phase 2 wraps and bubbles.
	enf := &ScopeEnforcer{
		Fetcher:        fetcher,
		SchemaResolver: func(types.LogPosition) (string, error) { return "", errors.New("registry down") },
	}
	_, err := VerifyFilingDelegation([]types.LogPosition{delPos}, fetcher, reader, enf, target)
	if err == nil {
		t.Fatal("expected error from infra failure")
	}
}
