/*
FILE PATH: verification/attestation_binding_test.go

DESCRIPTION:

	Tests for the JN attestation-binding adapter. Pins each
	rejection path the binding check produces against its typed
	sentinel.
*/
package verification

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
)

// makeAttestationEntry builds an entry with Header.CosignatureOf
// set to the supplied position. SchemaRef is nil — sufficient
// for binding-only tests; signature math is exercised separately.
func makeAttestationEntry(t *testing.T, signerDID string, target types.LogPosition) *envelope.Entry {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	cos := target
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     signerDID,
		Destination:   "did:web:dst",
		AuthorityPath: &auth,
		CosignatureOf: &cos,
	}, []byte(`{"k":"v"}`))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return entry
}

func makeNonAttestationEntry(t *testing.T, signerDID string) *envelope.Entry {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     signerDID,
		Destination:   "did:web:dst",
		AuthorityPath: &auth,
	}, []byte(`{"k":"v"}`))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return entry
}

// ─── CheckAttestationBinding ──────────────────────────────

func TestCheckAttestationBinding_HappyPath(t *testing.T) {
	target := types.LogPosition{LogDID: "did:web:log1", Sequence: 42}
	entry := makeAttestationEntry(t, "did:key:zAttester", target)
	if err := CheckAttestationBinding(entry, target); err != nil {
		t.Fatalf("CheckAttestationBinding: %v", err)
	}
}

func TestCheckAttestationBinding_NilEntry(t *testing.T) {
	target := types.LogPosition{LogDID: "did:web:log1", Sequence: 1}
	err := CheckAttestationBinding(nil, target)
	if !errors.Is(err, ErrAttestationNilEntry) {
		t.Errorf("err = %v, want errors.Is(ErrAttestationNilEntry)", err)
	}
	if !errors.Is(err, ErrAttestationBinding) {
		t.Errorf("err = %v, want errors.Is(ErrAttestationBinding)", err)
	}
}

func TestCheckAttestationBinding_NoCosignatureOf(t *testing.T) {
	target := types.LogPosition{LogDID: "did:web:log1", Sequence: 1}
	entry := makeNonAttestationEntry(t, "did:key:zAttester")
	err := CheckAttestationBinding(entry, target)
	if !errors.Is(err, ErrAttestationMissingCosignatureOf) {
		t.Errorf("err = %v, want errors.Is(ErrAttestationMissingCosignatureOf)", err)
	}
}

func TestCheckAttestationBinding_LogDIDMismatch(t *testing.T) {
	entry := makeAttestationEntry(t, "did:key:zAttester",
		types.LogPosition{LogDID: "did:web:logA", Sequence: 5})
	err := CheckAttestationBinding(entry, types.LogPosition{LogDID: "did:web:logB", Sequence: 5})
	if !errors.Is(err, ErrAttestationLogDIDMismatch) {
		t.Errorf("err = %v, want errors.Is(ErrAttestationLogDIDMismatch)", err)
	}
}

func TestCheckAttestationBinding_SequenceMismatch(t *testing.T) {
	entry := makeAttestationEntry(t, "did:key:zAttester",
		types.LogPosition{LogDID: "did:web:logA", Sequence: 5})
	err := CheckAttestationBinding(entry, types.LogPosition{LogDID: "did:web:logA", Sequence: 99})
	if !errors.Is(err, ErrAttestationSequenceMismatch) {
		t.Errorf("err = %v, want errors.Is(ErrAttestationSequenceMismatch)", err)
	}
}

// ─── FilterAttestationsOf ───────────────────────────────

func TestFilterAttestationsOf_NilSlice(t *testing.T) {
	got := FilterAttestationsOf(nil, types.LogPosition{LogDID: "x", Sequence: 1})
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestFilterAttestationsOf_FiltersToTarget(t *testing.T) {
	target := types.LogPosition{LogDID: "did:web:log1", Sequence: 42}
	other := types.LogPosition{LogDID: "did:web:log1", Sequence: 100}
	a := makeAttestationEntry(t, "did:key:zA", target) // matches
	b := makeAttestationEntry(t, "did:key:zB", other)  // does NOT match
	c := makeAttestationEntry(t, "did:key:zC", target) // matches
	d := makeNonAttestationEntry(t, "did:key:zD")      // no CosignatureOf

	got := FilterAttestationsOf([]*envelope.Entry{a, b, c, d}, target)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0] != a || got[1] != c {
		t.Errorf("order or selection wrong: got [%p %p], want [%p %p]", got[0], got[1], a, c)
	}
}

func TestFilterAttestationsOf_AllRejected_NilReturn(t *testing.T) {
	target := types.LogPosition{LogDID: "did:web:logA", Sequence: 1}
	mismatch := makeAttestationEntry(t, "did:key:zA",
		types.LogPosition{LogDID: "did:web:logB", Sequence: 1})
	got := FilterAttestationsOf([]*envelope.Entry{mismatch}, target)
	if got != nil {
		t.Errorf("got %v, want nil (all-rejected case)", got)
	}
}
