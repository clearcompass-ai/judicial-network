/*
FILE PATH: verification/attestation_policy_resolver_test.go

DESCRIPTION:

	Tests for the v1.3.0 attestation policy resolver. Pins:
	  - nil entry / nil SchemaParameters → ErrAttestationPolicyResolve
	  - entry.Header.AttestationPolicyName nil → ErrPolicyNotAdopted
	  - entry.Header.AttestationPolicyName empty string → ErrPolicyNotAdopted
	  - name set, schema has no matching policy → ErrPolicyNameNotFound
	  - name set, schema has matching policy → returns &policy, nil
	  - VerifyEntryAttestationPolicyFromSchema short-circuits to
	    (nil, nil) when the entry adopts no policy
*/
package verification

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
)

// makeEntryWithPolicyName builds an unsigned entry whose
// Header.AttestationPolicyName is set to `name`. When name == nil
// the field is omitted (the "entry adopts no policy" case).
func makeEntryWithPolicyName(t *testing.T, name *string) *envelope.Entry {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:             "did:key:zPrimary",
		Destination:           "did:web:dst",
		AuthorityPath:         &auth,
		AttestationPolicyName: name,
	}, []byte(`{"k":"v"}`))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return entry
}

// ─── ResolveEntryAttestationPolicy input guards ──────────────

func TestResolveEntryAttestationPolicy_NilEntry(t *testing.T) {
	_, err := ResolveEntryAttestationPolicy(nil, &types.SchemaParameters{})
	if !errors.Is(err, ErrAttestationPolicyResolve) {
		t.Errorf("err = %v, want errors.Is(ErrAttestationPolicyResolve)", err)
	}
}

func TestResolveEntryAttestationPolicy_NilSchemaParams(t *testing.T) {
	name := "concurring-1"
	entry := makeEntryWithPolicyName(t, &name)
	_, err := ResolveEntryAttestationPolicy(entry, nil)
	if !errors.Is(err, ErrNilSchemaParameters) {
		t.Errorf("err = %v, want errors.Is(ErrNilSchemaParameters)", err)
	}
}

// ─── ErrPolicyNotAdopted paths ─────────────────────────────

func TestResolveEntryAttestationPolicy_NilName_NotAdopted(t *testing.T) {
	entry := makeEntryWithPolicyName(t, nil)
	_, err := ResolveEntryAttestationPolicy(entry, &types.SchemaParameters{})
	if !errors.Is(err, ErrPolicyNotAdopted) {
		t.Errorf("err = %v, want errors.Is(ErrPolicyNotAdopted)", err)
	}
}

func TestResolveEntryAttestationPolicy_EmptyName_NotAdopted(t *testing.T) {
	empty := ""
	entry := makeEntryWithPolicyName(t, &empty)
	_, err := ResolveEntryAttestationPolicy(entry, &types.SchemaParameters{})
	if !errors.Is(err, ErrPolicyNotAdopted) {
		t.Errorf("err = %v, want errors.Is(ErrPolicyNotAdopted) on empty name", err)
	}
}

// ─── ErrPolicyNameNotFound path ────────────────────────────

func TestResolveEntryAttestationPolicy_NameNotOnSchema(t *testing.T) {
	missing := "unknown-policy"
	entry := makeEntryWithPolicyName(t, &missing)
	schema := &types.SchemaParameters{
		AttestationPolicies: []types.AttestationPolicy{
			{Name: "concurring-1", MinAttestors: 1, Required: true},
			{Name: "en-banc-3", MinAttestors: 3, Required: true},
		},
	}
	_, err := ResolveEntryAttestationPolicy(entry, schema)
	if !errors.Is(err, ErrPolicyNameNotFound) {
		t.Errorf("err = %v, want errors.Is(ErrPolicyNameNotFound)", err)
	}
}

// ─── Happy path ────────────────────────────────────────────────

func TestResolveEntryAttestationPolicy_HappyPath(t *testing.T) {
	name := "en-banc-3"
	entry := makeEntryWithPolicyName(t, &name)
	want := types.AttestationPolicy{
		Name:         "en-banc-3",
		MinAttestors: 3,
		Window:       168 * time.Hour,
		Required:     true,
	}
	schema := &types.SchemaParameters{
		AttestationPolicies: []types.AttestationPolicy{
			{Name: "concurring-1", MinAttestors: 1, Required: true},
			want,
			{Name: "advisory-2", MinAttestors: 2, Required: false},
		},
	}
	got, err := ResolveEntryAttestationPolicy(entry, schema)
	if err != nil {
		t.Fatalf("ResolveEntryAttestationPolicy: %v", err)
	}
	if got == nil {
		t.Fatal("got nil policy on happy path")
	}
	if got.Name != want.Name || got.MinAttestors != want.MinAttestors || got.Required != want.Required {
		t.Errorf("got %+v, want %+v", *got, want)
	}
}

// ─── VerifyEntryAttestationPolicyFromSchema short-circuit ──────

func TestVerifyEntryAttestationPolicyFromSchema_NotAdopted_NoErr(t *testing.T) {
	// Build a primary entry without an AttestationPolicyName,
	// serialize it, and pass through the end-to-end seam. The
	// resolver short-circuits to (nil, nil) before invoking the
	// SDK composite, so a nil schema or nil verifier do NOT
	// cause errors here.
	entry := makeEntryWithPolicyName(t, nil)
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sigBytes, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	signed, err := envelope.NewEntry(entry.Header, entry.DomainPayload, []envelope.Signature{
		{SignerDID: entry.Header.SignerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sigBytes},
	})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	raw, err := envelope.Serialize(signed)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	report, err := VerifyEntryAttestationPolicyFromSchema(
		context.Background(),
		types.EntryWithMetadata{
			CanonicalBytes: raw,
			Position:       types.LogPosition{LogDID: "did:web:l", Sequence: 1},
			LogTime:        time.Unix(1, 0),
		},
		&types.SchemaParameters{}, // empty AttestationPolicies; ignored
		nil,                       // no candidates
		nil,                       // no verifier — the short-circuit avoids needing one
		nil,                       // no delegation resolver
	)
	if err != nil {
		t.Fatalf("VerifyEntryAttestationPolicyFromSchema returned err on not-adopted entry: %v", err)
	}
	if report != nil {
		t.Errorf("not-adopted entry MUST return (nil, nil); got report=%+v", report)
	}
}
