/*
FILE PATH: verification/scope_enforcement_test.go

COVERAGE:
    All branches in scope_enforcement.go: empty chain, missing
    SchemaRef, fetcher errors, malformed delegation payload, both
    scope_limit shapes (array + CSV string), unrestricted scope,
    multi-hop chain with narrowing, case insensitivity, and the
    *ScopeViolation rich error path.
*/
package verification

import (
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/internal/testutil"
)

// ─── Stub fetcher ───────────────────────────────────────────────────

type stubFetcher struct {
	entries map[types.LogPosition]*types.EntryWithMetadata
	err     error
}

func (s *stubFetcher) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.entries[pos], nil
}

func mustSerialize(t *testing.T, entry *envelope.Entry) []byte {
	t.Helper()
	// Sign the entry once via the testutil to satisfy v7.75
	// "no Serialize on unsigned entries". The signing key here is
	// throwaway; chain semantics don't depend on signer identity.
	signed := testutil.SignEntry(t, entry, testutil.GenerateSigningKey(t))
	return envelope.Serialize(signed)
}

// ─── Tests ──────────────────────────────────────────────────────────

func TestVerifyDelegationScope_NoChain_ReturnsNil(t *testing.T) {
	enf := &ScopeEnforcer{Fetcher: &stubFetcher{}}
	target := &envelope.Entry{Header: envelope.ControlHeader{}}
	if err := enf.VerifyDelegationScope(target); err != nil {
		t.Errorf("no chain should pass: %v", err)
	}
}

func TestVerifyDelegationScope_NilFetcher_Errors(t *testing.T) {
	enf := &ScopeEnforcer{}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			DelegationPointers: []types.LogPosition{{LogDID: "did:web:l", Sequence: 1}},
		},
	}
	if err := enf.VerifyDelegationScope(target); !errors.Is(err, ErrScopeFetcherNil) {
		t.Errorf("err = %v, want ErrScopeFetcherNil", err)
	}
}

func TestVerifyDelegationScope_NilTarget_Errors(t *testing.T) {
	enf := &ScopeEnforcer{Fetcher: &stubFetcher{}}
	if err := enf.VerifyDelegationScope(nil); err == nil {
		t.Error("nil target must error")
	}
}

func TestVerifyDelegationScope_NoSchemaRef_RejectsClosed(t *testing.T) {
	enf := &ScopeEnforcer{Fetcher: &stubFetcher{}}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			DelegationPointers: []types.LogPosition{{LogDID: "did:web:l", Sequence: 1}},
		},
	}
	if err := enf.VerifyDelegationScope(target); !errors.Is(err, ErrScopeNoSchemaRef) {
		t.Errorf("err = %v, want ErrScopeNoSchemaRef", err)
	}
}

func TestVerifyDelegationScope_NilResolver_Errors(t *testing.T) {
	pos := types.LogPosition{LogDID: "did:web:l", Sequence: 1}
	enf := &ScopeEnforcer{Fetcher: &stubFetcher{}}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			SchemaRef:          &pos,
			DelegationPointers: []types.LogPosition{{LogDID: "did:web:l", Sequence: 2}},
		},
	}
	if err := enf.VerifyDelegationScope(target); err == nil ||
		!strings.Contains(err.Error(), "nil schema resolver") {
		t.Errorf("err = %v, want nil resolver error", err)
	}
}

func TestVerifyDelegationScope_ResolverError_Wraps(t *testing.T) {
	pos := types.LogPosition{LogDID: "did:web:l", Sequence: 1}
	enf := &ScopeEnforcer{
		Fetcher:        &stubFetcher{},
		SchemaResolver: func(types.LogPosition) (string, error) { return "", errors.New("boom") },
	}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			SchemaRef:          &pos,
			DelegationPointers: []types.LogPosition{{LogDID: "did:web:l", Sequence: 99}},
		},
	}
	err := enf.VerifyDelegationScope(target)
	if err == nil || !strings.Contains(err.Error(), "resolve target schema") {
		t.Errorf("err = %v, want resolve-error wrap", err)
	}
}

func TestVerifyDelegationScope_DeserializeError_Sentinel(t *testing.T) {
	delPos := types.LogPosition{LogDID: "did:web:l", Sequence: 7}
	enf := &ScopeEnforcer{
		Fetcher: &stubFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
			delPos: {Position: delPos, CanonicalBytes: []byte("not a valid serialized entry")},
		}},
		SchemaResolver: func(types.LogPosition) (string, error) { return "tn-criminal-case-v1", nil },
	}
	pos := types.LogPosition{LogDID: "did:web:l", Sequence: 1}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			SchemaRef:          &pos,
			DelegationPointers: []types.LogPosition{delPos},
		},
	}
	err := enf.VerifyDelegationScope(target)
	if !errors.Is(err, ErrScopeDelegationMalformed) {
		t.Errorf("err = %v, want ErrScopeDelegationMalformed (deserialize fail)", err)
	}
}

func TestVerifyDelegationScope_FetchError_WrapsSentinel(t *testing.T) {
	pos := types.LogPosition{LogDID: "did:web:l", Sequence: 1}
	enf := &ScopeEnforcer{
		Fetcher:        &stubFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{}},
		SchemaResolver: func(types.LogPosition) (string, error) { return "tn-criminal-case-v1", nil },
	}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			SchemaRef:          &pos,
			DelegationPointers: []types.LogPosition{{LogDID: "did:web:l", Sequence: 99}},
		},
	}
	err := enf.VerifyDelegationScope(target)
	if !errors.Is(err, ErrScopeDelegationFetchFailed) {
		t.Errorf("err = %v, want ErrScopeDelegationFetchFailed", err)
	}
}

func TestVerifyDelegationScope_MalformedDelegationPayload_Sentinel(t *testing.T) {
	delPos := types.LogPosition{LogDID: "did:web:l", Sequence: 7}
	dest := "did:web:exchange.test"
	delegate := "did:web:judge"
	delEntry, _ := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:web:court",
		Destination: dest,
		DelegateDID: &delegate,
	}, []byte("not json"))

	pos := types.LogPosition{LogDID: "did:web:l", Sequence: 1}
	enf := &ScopeEnforcer{
		Fetcher: &stubFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
			delPos: {Position: delPos, CanonicalBytes: mustSerialize(t, delEntry)},
		}},
		SchemaResolver: func(types.LogPosition) (string, error) { return "tn-criminal-case-v1", nil },
	}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			SchemaRef:          &pos,
			DelegationPointers: []types.LogPosition{delPos},
		},
	}
	err := enf.VerifyDelegationScope(target)
	if !errors.Is(err, ErrScopeDelegationMalformed) {
		t.Errorf("err = %v, want ErrScopeDelegationMalformed", err)
	}
}

func TestVerifyDelegationScope_UnrestrictedDelegation_Permits(t *testing.T) {
	delPos := types.LogPosition{LogDID: "did:web:l", Sequence: 7}
	delegate := "did:web:judge"
	delEntry, _ := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:web:court",
		Destination: "did:web:exchange.test",
		DelegateDID: &delegate,
	}, []byte(`{"role":"judge"}`)) // no scope_limit → unrestricted

	pos := types.LogPosition{LogDID: "did:web:l", Sequence: 1}
	enf := &ScopeEnforcer{
		Fetcher: &stubFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
			delPos: {Position: delPos, CanonicalBytes: mustSerialize(t, delEntry)},
		}},
		SchemaResolver: func(types.LogPosition) (string, error) { return "tn-criminal-case-v1", nil },
	}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			SchemaRef:          &pos,
			DelegationPointers: []types.LogPosition{delPos},
		},
	}
	if err := enf.VerifyDelegationScope(target); err != nil {
		t.Errorf("unrestricted scope must permit any schema: %v", err)
	}
}

func TestVerifyDelegationScope_ArrayShape_PermitsListed(t *testing.T) {
	delPos := types.LogPosition{LogDID: "did:web:l", Sequence: 7}
	delegate := "did:web:judge"
	payload := []byte(`{"scope_limit":["case_filing","tn-criminal-case-v1"]}`)
	delEntry, _ := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:web:court",
		Destination: "did:web:exchange.test",
		DelegateDID: &delegate,
	}, payload)

	pos := types.LogPosition{LogDID: "did:web:l", Sequence: 1}
	enf := &ScopeEnforcer{
		Fetcher: &stubFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
			delPos: {Position: delPos, CanonicalBytes: mustSerialize(t, delEntry)},
		}},
		SchemaResolver: func(types.LogPosition) (string, error) { return "tn-criminal-case-v1", nil },
	}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			SchemaRef:          &pos,
			DelegationPointers: []types.LogPosition{delPos},
		},
	}
	if err := enf.VerifyDelegationScope(target); err != nil {
		t.Errorf("listed schema must permit: %v", err)
	}
}

func TestVerifyDelegationScope_CSVShape_PermitsListed(t *testing.T) {
	delPos := types.LogPosition{LogDID: "did:web:l", Sequence: 7}
	delegate := "did:web:judge"
	payload := []byte(`{"scope_limit":"case_filing, tn-criminal-case-v1 "}`) // CSV with whitespace
	delEntry, _ := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:web:court",
		Destination: "did:web:exchange.test",
		DelegateDID: &delegate,
	}, payload)

	pos := types.LogPosition{LogDID: "did:web:l", Sequence: 1}
	enf := &ScopeEnforcer{
		Fetcher: &stubFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
			delPos: {Position: delPos, CanonicalBytes: mustSerialize(t, delEntry)},
		}},
		SchemaResolver: func(types.LogPosition) (string, error) { return "tn-criminal-case-v1", nil },
	}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			SchemaRef:          &pos,
			DelegationPointers: []types.LogPosition{delPos},
		},
	}
	if err := enf.VerifyDelegationScope(target); err != nil {
		t.Errorf("CSV scope must permit: %v", err)
	}
}

func TestVerifyDelegationScope_SchemaNotInScope_Violation(t *testing.T) {
	delPos := types.LogPosition{LogDID: "did:web:l", Sequence: 7}
	delegate := "did:web:exchange:scheduler"
	payload := []byte(`{"scope_limit":["daily_assignment"]}`)
	delEntry, _ := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:web:court",
		Destination: "did:web:exchange.test",
		DelegateDID: &delegate,
	}, payload)

	pos := types.LogPosition{LogDID: "did:web:l", Sequence: 1}
	enf := &ScopeEnforcer{
		Fetcher: &stubFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
			delPos: {Position: delPos, CanonicalBytes: mustSerialize(t, delEntry)},
		}},
		SchemaResolver: func(types.LogPosition) (string, error) { return "tn-sealing-order-v1", nil },
	}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			SchemaRef:          &pos,
			DelegationPointers: []types.LogPosition{delPos},
		},
	}

	err := enf.VerifyDelegationScope(target)
	if !errors.Is(err, ErrScopeViolation) {
		t.Fatalf("err = %v, want ErrScopeViolation", err)
	}
	var v *ScopeViolation
	if !errors.As(err, &v) {
		t.Fatal("error must be *ScopeViolation")
	}
	if v.Hop != 0 {
		t.Errorf("Hop = %d, want 0", v.Hop)
	}
	if v.DelegateDID != delegate {
		t.Errorf("DelegateDID = %q, want %q", v.DelegateDID, delegate)
	}
	if v.TargetSchema != "tn-sealing-order-v1" {
		t.Errorf("TargetSchema = %q", v.TargetSchema)
	}
	if len(v.PermittedSet) != 1 || v.PermittedSet[0] != "daily_assignment" {
		t.Errorf("PermittedSet = %v", v.PermittedSet)
	}
}

func TestVerifyDelegationScope_NarrowingChain_RejectsAtNarrowestHop(t *testing.T) {
	// Court permits everything; Judge narrows to [case_filing, order];
	// Clerk narrows further to [filings_only]. Target = order should
	// be rejected at the Clerk hop (hop 2), not Judge (hop 1).
	mkDel := func(seq uint64, delegateDID, scopePayload string) (types.LogPosition, *types.EntryWithMetadata) {
		pos := types.LogPosition{LogDID: "did:web:l", Sequence: seq}
		entry, _ := envelope.NewUnsignedEntry(envelope.ControlHeader{
			SignerDID:   "did:web:court",
			Destination: "did:web:exchange.test",
			DelegateDID: &delegateDID,
		}, []byte(scopePayload))
		return pos, &types.EntryWithMetadata{Position: pos, CanonicalBytes: mustSerialize(t, entry)}
	}
	courtPos, courtMeta := mkDel(10, "did:web:judge", `{}`)
	judgePos, judgeMeta := mkDel(20, "did:web:clerk", `{"scope_limit":["case_filing","order"]}`)
	clerkPos, clerkMeta := mkDel(30, "did:web:deputy", `{"scope_limit":["filings_only"]}`)

	pos := types.LogPosition{LogDID: "did:web:l", Sequence: 1}
	enf := &ScopeEnforcer{
		Fetcher: &stubFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
			courtPos: courtMeta, judgePos: judgeMeta, clerkPos: clerkMeta,
		}},
		SchemaResolver: func(types.LogPosition) (string, error) { return "order", nil },
	}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			SchemaRef:          &pos,
			DelegationPointers: []types.LogPosition{courtPos, judgePos, clerkPos},
		},
	}
	err := enf.VerifyDelegationScope(target)
	var v *ScopeViolation
	if !errors.As(err, &v) {
		t.Fatalf("expected *ScopeViolation, got %v", err)
	}
	if v.Hop != 2 {
		t.Errorf("Hop = %d, want 2 (clerk hop is narrowest)", v.Hop)
	}
	if v.DelegateDID != "did:web:deputy" {
		t.Errorf("DelegateDID = %q, want did:web:deputy", v.DelegateDID)
	}
}

func TestVerifyDelegationScope_CaseInsensitive(t *testing.T) {
	delPos := types.LogPosition{LogDID: "did:web:l", Sequence: 7}
	delegate := "did:web:judge"
	payload := []byte(`{"scope_limit":["TN-Criminal-Case-V1"]}`)
	delEntry, _ := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:web:court",
		Destination: "did:web:exchange.test",
		DelegateDID: &delegate,
	}, payload)

	pos := types.LogPosition{LogDID: "did:web:l", Sequence: 1}
	enf := &ScopeEnforcer{
		Fetcher: &stubFetcher{entries: map[types.LogPosition]*types.EntryWithMetadata{
			delPos: {Position: delPos, CanonicalBytes: mustSerialize(t, delEntry)},
		}},
		SchemaResolver: func(types.LogPosition) (string, error) { return "tn-criminal-case-v1", nil },
	}
	target := &envelope.Entry{
		Header: envelope.ControlHeader{
			SchemaRef:          &pos,
			DelegationPointers: []types.LogPosition{delPos},
		},
	}
	if err := enf.VerifyDelegationScope(target); err != nil {
		t.Errorf("case-insensitive match must pass: %v", err)
	}
}

// ─── Pure helpers ───────────────────────────────────────────────────

func TestNormalizeSchemaName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"tn-criminal-case-v1", "tn-criminal-case-v1"},
		{"  tn-Criminal-CASE-v1 ", "tn-criminal-case-v1"},
		{"did:web:state.tn.gov/schemas/tn-criminal-case-v1", "tn-criminal-case-v1"},
		{"did:web:state:schemas:tn-criminal-case-v1", "tn-criminal-case-v1"},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizeSchemaName(c.in); got != c.want {
			t.Errorf("NormalizeSchemaName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExtractScopeLimit_AllShapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty payload", "", nil},
		{"missing field", `{"role":"judge"}`, nil},
		{"empty array", `{"scope_limit":[]}`, []string{}},
		{"empty string", `{"scope_limit":""}`, []string{}},
		{"array two", `{"scope_limit":["a","b"]}`, []string{"a", "b"}},
		{"csv two", `{"scope_limit":"a,b"}`, []string{"a", "b"}},
		{"csv whitespace", `{"scope_limit":" a , b "}`, []string{"a", "b"}},
		{"array dedupe", `{"scope_limit":["a","A","a"]}`, []string{"a"}},
		{"mixed empty entries", `{"scope_limit":["a","","b"]}`, []string{"a", "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ExtractScopeLimit([]byte(c.in))
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("len = %d, want %d (got=%v)", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestExtractScopeLimit_NotJSON_Errors(t *testing.T) {
	if _, err := ExtractScopeLimit([]byte("not json")); err == nil {
		t.Error("expected error for non-JSON")
	}
}

func TestExtractScopeLimit_WrongType_Errors(t *testing.T) {
	if _, err := ExtractScopeLimit([]byte(`{"scope_limit":42}`)); err == nil {
		t.Error("expected error for numeric scope_limit")
	}
}

func TestPermitsAll(t *testing.T) {
	if !PermitsAll(nil) {
		t.Error("nil must permit all")
	}
	if !PermitsAll([]string{}) {
		t.Error("empty must permit all")
	}
	if PermitsAll([]string{"a"}) {
		t.Error("non-empty must NOT permit all")
	}
}

func TestScopePermits(t *testing.T) {
	if !ScopePermits([]string{"a", "b"}, "a") {
		t.Error("'a' should be in {a,b}")
	}
	if ScopePermits([]string{"a", "b"}, "c") {
		t.Error("'c' should NOT be in {a,b}")
	}
	if ScopePermits(nil, "a") {
		t.Error("empty permitted set should not match anything (caller must PermitsAll first)")
	}
}

func TestScopeViolation_IsAndAs(t *testing.T) {
	v := &ScopeViolation{Hop: 1, DelegateDID: "did:web:x", TargetSchema: "s", PermittedSet: []string{"y"}}
	if !errors.Is(v, ErrScopeViolation) {
		t.Error("Is(ErrScopeViolation) must hold")
	}
	wrapped := errors.New("outer: " + v.Error())
	_ = wrapped
	// errors.As against the typed wrapper directly:
	var got *ScopeViolation
	if !errors.As(v, &got) || got.Hop != 1 || got.DelegateDID != "did:web:x" {
		t.Errorf("As failed or fields lost: %+v", got)
	}
}
