/*
FILE PATH: verification/delegation_source_test.go

DESCRIPTION:

	Tests for the JN delegation.EntrySource adapter.

	Coverage:
	  - FuncEntrySource satisfies delegation.EntrySource at
	    compile-time AND propagates the SDK's ErrUnknownDelegate
	    sentinel through to attestation.ErrUnknownDelegate.
	  - EntryFromJudicialDelegation correctly extracts DelegateDID
	    / DelegatorDID / Scopes from a JudicialDelegationPayload-
	    carrying envelope.Entry.
	  - NewFuncEntrySource and NewResolverFromLookup refuse a nil
	    lookup function — programming error caught at construction.
	  - *delegation.Resolver satisfies attestation.DelegationResolver
	    (the seam the SDK's attestation policy verifier requires).
*/
package verification

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/delegation"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── FuncEntrySource ──────────────────────────────────

func TestFuncEntrySource_HappyPath(t *testing.T) {
	want := delegation.DelegationEntry{
		DelegateDID:  "did:key:zChild",
		DelegatorDID: "did:key:zParent",
		Scopes:       []string{"docket:read", "docket:write"},
		Live:         true,
	}
	src, err := NewFuncEntrySource(func(_ context.Context, did string) (delegation.DelegationEntry, error) {
		if did != "did:key:zChild" {
			t.Fatalf("unexpected lookup arg: %q", did)
		}
		return want, nil
	})
	if err != nil {
		t.Fatalf("NewFuncEntrySource: %v", err)
	}
	got, err := src.DelegationOf(context.Background(), "did:key:zChild")
	if err != nil {
		t.Fatalf("DelegationOf: %v", err)
	}
	if got.DelegateDID != want.DelegateDID || got.DelegatorDID != want.DelegatorDID || got.Live != want.Live {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if len(got.Scopes) != len(want.Scopes) {
		t.Errorf("Scopes len=%d, want %d", len(got.Scopes), len(want.Scopes))
	}
}

func TestFuncEntrySource_NilLookup_RefusedAtConstruction(t *testing.T) {
	_, err := NewFuncEntrySource(nil)
	if !errors.Is(err, ErrDelegationSource) {
		t.Fatalf("err = %v, want ErrDelegationSource", err)
	}
}

func TestFuncEntrySource_PropagatesUnknownDelegateSentinel(t *testing.T) {
	src, err := NewFuncEntrySource(func(_ context.Context, _ string) (delegation.DelegationEntry, error) {
		return delegation.DelegationEntry{}, attestation.ErrUnknownDelegate
	})
	if err != nil {
		t.Fatalf("NewFuncEntrySource: %v", err)
	}
	_, err = src.DelegationOf(context.Background(), "did:key:zMissing")
	if !errors.Is(err, attestation.ErrUnknownDelegate) {
		t.Errorf("err = %v, want errors.Is(ErrUnknownDelegate)", err)
	}
}

func TestFuncEntrySource_SatisfiesEntrySourceInterface(t *testing.T) {
	// Compile-time check; included so a missing-method break
	// surfaces with this test's name in the failure log.
	var _ delegation.EntrySource = (*FuncEntrySource)(nil)
}

// ─── EntryFromJudicialDelegation ───────────────────────

func makeDelegationEntry(t *testing.T, granterDID, granteeDID string, scopes []string) *envelope.Entry {
	t.Helper()
	payload, err := json.Marshal(schemas.JudicialDelegationPayload{
		GranterDID: granterDID,
		GranteeDID: granteeDID,
		Scope:      scopes,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	delegate := granteeDID
	auth := envelope.AuthoritySameSigner
	header := envelope.ControlHeader{
		SignerDID:     granterDID,
		Destination:   "did:web:state:tn:davidson",
		AuthorityPath: &auth,
		DelegateDID:   &delegate,
	}
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return entry
}

func TestEntryFromJudicialDelegation_HappyPath(t *testing.T) {
	entry := makeDelegationEntry(t, "did:key:zJudge", "did:key:zClerk", []string{"filings:read"})
	got, err := EntryFromJudicialDelegation(entry, true)
	if err != nil {
		t.Fatalf("EntryFromJudicialDelegation: %v", err)
	}
	if got.DelegateDID != "did:key:zClerk" {
		t.Errorf("DelegateDID = %q, want did:key:zClerk", got.DelegateDID)
	}
	if got.DelegatorDID != "did:key:zJudge" {
		t.Errorf("DelegatorDID = %q, want did:key:zJudge", got.DelegatorDID)
	}
	if !got.Live {
		t.Errorf("Live = false, want true")
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "filings:read" {
		t.Errorf("Scopes = %v, want [filings:read]", got.Scopes)
	}
}

func TestEntryFromJudicialDelegation_LiveFlagPropagates(t *testing.T) {
	entry := makeDelegationEntry(t, "did:key:zJudge", "did:key:zClerk", nil)
	got, err := EntryFromJudicialDelegation(entry, false)
	if err != nil {
		t.Fatalf("EntryFromJudicialDelegation: %v", err)
	}
	if got.Live {
		t.Errorf("Live = true, want false (revoked entry)")
	}
}

func TestEntryFromJudicialDelegation_NilEntry(t *testing.T) {
	_, err := EntryFromJudicialDelegation(nil, true)
	if !errors.Is(err, ErrDelegationSource) {
		t.Fatalf("err = %v, want ErrDelegationSource", err)
	}
}

func TestEntryFromJudicialDelegation_NoDelegateDID(t *testing.T) {
	auth := envelope.AuthoritySameSigner
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     "did:key:zSigner",
		Destination:   "did:web:dst",
		AuthorityPath: &auth,
	}, []byte("{}"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	_, err = EntryFromJudicialDelegation(entry, true)
	if !errors.Is(err, ErrNoDelegateDID) {
		t.Errorf("err = %v, want errors.Is(ErrNoDelegateDID)", err)
	}
}

func TestEntryFromJudicialDelegation_PayloadInconsistent(t *testing.T) {
	// Header.DelegateDID says "zA"; payload says GranteeDID="zB".
	// This is the wire-level fraud signal the helper rejects.
	payload, err := json.Marshal(schemas.JudicialDelegationPayload{
		GranterDID: "did:key:zJudge",
		GranteeDID: "did:key:zB",
		Scope:      []string{"x"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	delegate := "did:key:zA"
	auth := envelope.AuthoritySameSigner
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     "did:key:zJudge",
		Destination:   "did:web:dst",
		AuthorityPath: &auth,
		DelegateDID:   &delegate,
	}, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	_, err = EntryFromJudicialDelegation(entry, true)
	if !errors.Is(err, ErrPayloadInconsistent) {
		t.Errorf("err = %v, want errors.Is(ErrPayloadInconsistent)", err)
	}
}

func TestEntryFromJudicialDelegation_MalformedPayload(t *testing.T) {
	delegate := "did:key:zClerk"
	auth := envelope.AuthoritySameSigner
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     "did:key:zJudge",
		Destination:   "did:web:dst",
		AuthorityPath: &auth,
		DelegateDID:   &delegate,
	}, []byte("{not valid json"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	_, err = EntryFromJudicialDelegation(entry, true)
	if !errors.Is(err, ErrDelegationSource) {
		t.Errorf("err = %v, want errors.Is(ErrDelegationSource)", err)
	}
}

// ─── NewResolverFromLookup ────────────────────────────

func TestNewResolverFromLookup_NilLookup(t *testing.T) {
	_, err := NewResolverFromLookup(nil)
	if !errors.Is(err, ErrDelegationSource) {
		t.Fatalf("err = %v, want errors.Is(ErrDelegationSource)", err)
	}
}

func TestNewResolverFromLookup_ProducesAttestationResolver(t *testing.T) {
	resolver, err := NewResolverFromLookup(func(_ context.Context, _ string) (delegation.DelegationEntry, error) {
		return delegation.DelegationEntry{}, attestation.ErrUnknownDelegate
	})
	if err != nil {
		t.Fatalf("NewResolverFromLookup: %v", err)
	}
	// Compile-time check via assignment: *delegation.Resolver
	// satisfies attestation.DelegationResolver.
	var sdkSeam attestation.DelegationResolver = resolver
	if sdkSeam == nil {
		t.Fatal("resolver nil")
	}
}
